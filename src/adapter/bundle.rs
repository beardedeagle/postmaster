//! `postmaster_bundle` adapter for structured, encrypted JSON inputs.
//!
//! The bundle format is a JSON file with:
//! - `format`: must be `"postmaster.bundle"` (fail closed on unknown)
//! - `version`: integer, must be `1`
//! - `profile`: optional public metadata, not used for key selection
//! - `suite`: mandatory crypto suite identifier (must match the ECIES path)
//! - `recipients`: array of `{ id, public_key }` — public routing metadata
//! - `entries`: map of key name → `{ encoding, ciphertext }`
//!
//! All fields are public metadata except `ciphertext`, which is
//! encrypted and authenticated. Each entry's ciphertext is additionally
//! bound to its key name as AES-GCM additional authenticated data (AAD):
//! a ciphertext cut from one entry and pasted under another name fails
//! decryption. Entries use the same identifier
//! rule as `.env`-derived keys: `[A-Za-z_][A-Za-z0-9_]*`.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::keys::{KeyRing, is_ident, is_private_key_var_name};

/// The top-level bundle container.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    /// Must be `"postmaster.bundle"`.
    pub format: String,
    /// Must be `1`.
    pub version: u32,
    /// Optional public metadata, not used to select keys or entries.
    #[serde(default)]
    pub profile: Option<String>,
    /// Mandatory crypto suite identifier.
    pub suite: String,
    /// Public routing metadata: one entry per recipient.
    #[serde(default)]
    pub recipients: Vec<Recipient>,
    /// Key name → encrypted entry.
    pub entries: std::collections::BTreeMap<String, BundleEntry>,
}

/// Public recipient metadata, parsed but not used for key selection.
/// Resolution uses the fixed `POSTMASTER_KEY` variable.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    /// Public identifier for this recipient (e.g., `"host:api-01"`).
    pub id: String,
    /// Public-key metadata, conventionally compressed secp256k1 hex.
    /// Parsed as a string; not used for decryption.
    pub public_key: String,
}

/// An encrypted entry in the bundle.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct BundleEntry {
    /// Either `"utf8"` or `"bytes"`. UTF-8 is validated during resolution.
    /// Env projection rejects NUL bytes; files preserve byte-exact values.
    pub encoding: Encoding,
    /// Base64-encoded ECIES ciphertext.
    pub ciphertext: String,
}

/// Value encoding type.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    /// UTF-8 string value, validated during resolution in every mode.
    Utf8,
    /// Raw byte value; files preserve it and env projection rejects NUL.
    Bytes,
}

/// The only supported crypto suite: ECIES (secp256k1, HKDF-SHA256,
/// AES-256-GCM) with the entry name bound as AES-GCM additional
/// authenticated data. Ciphertexts that do not authenticate with that entry
/// name are rejected during decryption.
const SUITE: &str = "ecies-secp256k1-hkdf-sha256-aes-256-gcm-entry-aad";

/// Parse a bundle JSON file, rejecting invalid metadata and reserved key names.
pub fn parse_bundle(raw: &[u8], path: &Path) -> Result<Bundle, String> {
    let bundle: Bundle =
        serde_json::from_slice(raw).map_err(|e| format!("{}: {e}", path.display()))?;
    if bundle.format != "postmaster.bundle" {
        return Err(format!(
            "{}: unknown format {:?} (expected \"postmaster.bundle\")",
            path.display(),
            bundle.format
        ));
    }
    if bundle.version != 1 {
        return Err(format!(
            "{}: unknown version {} (expected 1)",
            path.display(),
            bundle.version
        ));
    }
    if bundle.suite != SUITE {
        return Err(format!(
            "{}: unsupported suite {:?} (expected {SUITE})",
            path.display(),
            bundle.suite
        ));
    }
    for name in bundle.entries.keys() {
        if !is_ident(name) {
            return Err(format!(
                "{}: refusing non-identifier key {name:?}",
                path.display()
            ));
        }
        if is_private_key_var_name(name) {
            return Err(format!(
                "{}: key {name:?} is reserved for private-key provisioning",
                path.display()
            ));
        }
    }
    Ok(bundle)
}

/// Resolved bundle entry: (key name, plaintext bytes, encoding).
pub type ResolvedBundleVars = Vec<(String, Zeroizing<Vec<u8>>, Encoding)>;

/// Resolve all entries in a bundle file against the key ring.
///
/// Each entry's ciphertext is base64-decoded and decrypted with ECIES
/// using the key ring's `POSTMASTER_KEY` candidates (rotation-aware).
/// Returns resolved (name, plaintext, encoding) triples in the order
/// entries appear in the bundle (sorted by key name via BTreeMap).
pub fn resolve_bundle(
    bundle: &Bundle,
    ring: &KeyRing,
    bundle_path: &Path,
) -> Result<ResolvedBundleVars, String> {
    let var = crate::adapter::KeyNaming::Bundle.key_prefix();
    let candidates = ring
        .candidates(var)
        .ok_or_else(|| format!("key ring has no {var} entry"))?;
    let mut out = Vec::new();
    for (name, entry) in &bundle.entries {
        let ciphertext: Zeroizing<Vec<u8>> = Zeroizing::new(
            BASE64
                .decode(&entry.ciphertext)
                .map_err(|_| format!("{}: {name} is not valid base64", bundle_path.display()))?,
        );
        // AAD = the entry name: a ciphertext pasted under a different entry fails
        // authentication here.
        let mut decrypted: Option<Zeroizing<Vec<u8>>> = None;
        for sk in candidates {
            if let Some(pt) = crate::aad::decrypt(&sk[..], &ciphertext, name.as_bytes()) {
                decrypted = Some(pt);
                break;
            }
        }
        match decrypted {
            Some(pt) => {
                // `utf8` is a promise the bundle makes to env-mode
                // consumers: validate it at the trust boundary and fail
                // closed — invalid bytes must never flow into an
                // environment value. `bytes` entries stay byte-exact.
                if entry.encoding == Encoding::Utf8 && std::str::from_utf8(&pt).is_err() {
                    return Err(format!(
                        "{}: {name} declares utf8 but is not valid UTF-8",
                        bundle_path.display()
                    ));
                }
                out.push((name.clone(), pt, entry.encoding));
            }
            None => {
                let _ = ciphertext; // zeroize on drop
                // No candidate count in the error text.
                return Err(format!(
                    "{}: no key under {var} decrypts {name}",
                    bundle_path.display()
                ));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, unused_qualifications)]
mod tests {
    use super::*;
    use crate::test_util::aad_fixture::encrypt;
    use std::collections::BTreeMap;

    fn test_pk_hex() -> String {
        let sk_bytes = hex::decode(crate::keys::tests::TEST_SK_HEX).unwrap();
        let sk = ecies::SecretKey::parse_slice(&sk_bytes).unwrap();
        let pk = ecies::PublicKey::from_secret_key(&sk);
        hex::encode(pk.serialize_compressed())
    }

    fn make_bundle(entries: Vec<(&str, &str, Encoding)>) -> Bundle {
        let mut map = BTreeMap::new();
        for (name, ct, enc) in entries {
            map.insert(
                name.to_string(),
                BundleEntry {
                    encoding: enc,
                    ciphertext: ct.to_string(),
                },
            );
        }
        Bundle {
            format: "postmaster.bundle".into(),
            version: 1,
            profile: Some("test".into()),
            suite: SUITE.into(),
            recipients: vec![Recipient {
                id: "test".into(),
                public_key: test_pk_hex(),
            }],
            entries: map,
        }
    }

    fn enc(name: &str, value: &str) -> String {
        let pk = hex::decode(test_pk_hex()).unwrap();
        let ct = encrypt(&pk, value.as_bytes(), name.as_bytes());
        BASE64.encode(ct)
    }

    #[test]
    fn parse_bundle_validates_format() {
        let raw = serde_json::json!({
            "format": "wrong",
            "version": 1,
            "suite": "ecies-secp256k1-hkdf-sha256-aes-256-gcm-entry-aad",
            "recipients": [],
            "entries": {}
        });
        let err = parse_bundle(
            serde_json::to_vec(&raw).unwrap().as_slice(),
            Path::new("/test"),
        )
        .unwrap_err();
        assert!(err.contains("unknown format"), "{err}");
    }

    #[test]
    fn parse_bundle_validates_version() {
        let raw = serde_json::json!({
            "format": "postmaster.bundle",
            "version": 99,
            "suite": "ecies-secp256k1-hkdf-sha256-aes-256-gcm-entry-aad",
            "recipients": [],
            "entries": {}
        });
        let err = parse_bundle(
            serde_json::to_vec(&raw).unwrap().as_slice(),
            Path::new("/test"),
        )
        .unwrap_err();
        assert!(err.contains("unknown version"), "{err}");
    }

    #[test]
    fn parse_bundle_validates_suite() {
        let raw = serde_json::json!({
            "format": "postmaster.bundle",
            "version": 1,
            "suite": "wrong-suite",
            "recipients": [],
            "entries": {}
        });
        let err = parse_bundle(
            serde_json::to_vec(&raw).unwrap().as_slice(),
            Path::new("/test"),
        )
        .unwrap_err();
        assert!(err.contains("unsupported suite"), "{err}");
    }

    #[test]
    fn parse_bundle_rejects_non_identifier_key() {
        let raw = serde_json::json!({
            "format": "postmaster.bundle",
            "version": 1,
            "suite": "ecies-secp256k1-hkdf-sha256-aes-256-gcm-entry-aad",
            "recipients": [],
            "entries": {
                "BAD.KEY": { "encoding": "utf8", "ciphertext": "dGVzdA==" }
            }
        });
        let err = parse_bundle(
            serde_json::to_vec(&raw).unwrap().as_slice(),
            Path::new("/test"),
        )
        .unwrap_err();
        assert!(err.contains("non-identifier"), "{err}");
    }

    #[test]
    fn parse_bundle_rejects_unknown_fields() {
        let raw = serde_json::json!({
            "format": "postmaster.bundle",
            "version": 1,
            "suite": "ecies-secp256k1-hkdf-sha256-aes-256-gcm-entry-aad",
            "recipients": [],
            "entries": {},
            "unknown_field": "should fail"
        });
        assert!(
            parse_bundle(
                serde_json::to_vec(&raw).unwrap().as_slice(),
                Path::new("/test"),
            )
            .is_err()
        );
    }

    #[test]
    fn resolve_bundle_decrypts_entries() {
        let ct = enc("SECRET", "hello-bundle");
        let bundle = make_bundle(vec![("SECRET", &ct, Encoding::Utf8)]);
        let ring = crate::keys::tests::make_test_ring();
        let resolved = resolve_bundle(&bundle, &ring, Path::new("/test")).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, "SECRET");
        assert_eq!(&resolved[0].1[..], b"hello-bundle");
        assert_eq!(resolved[0].2, Encoding::Utf8);
    }

    #[test]
    fn resolve_bundle_rejects_relocated_ciphertext() {
        // A ciphertext encrypted under one entry name must not decrypt under another.
        let ct = enc("REAL", "top-secret");
        let bundle = make_bundle(vec![("FAKE", &ct, Encoding::Utf8)]);
        let ring = crate::keys::tests::make_test_ring();
        let err = resolve_bundle(&bundle, &ring, Path::new("/test")).unwrap_err();
        assert!(err.contains("no key under"), "{err}");
    }

    #[test]
    fn resolve_bundle_fails_on_wrong_key() {
        let other_sk = "22".repeat(32);
        let other_sk_bytes = hex::decode(&other_sk).unwrap();
        let other_sk = ecies::SecretKey::parse_slice(&other_sk_bytes).unwrap();
        let other_pk = ecies::PublicKey::from_secret_key(&other_sk);
        let ct = BASE64.encode(encrypt(
            &other_pk.serialize_compressed(),
            b"unreachable",
            b"SECRET",
        ));
        let bundle = make_bundle(vec![("SECRET", &ct, Encoding::Utf8)]);
        let ring = crate::keys::tests::make_test_ring();
        let err = resolve_bundle(&bundle, &ring, Path::new("/test")).unwrap_err();
        assert!(err.contains("no key under"), "{err}");
    }

    #[test]
    fn resolve_bundle_handles_bytes_encoding() {
        let binary_val = b"\x00\x01\x02\xff";
        let pk = hex::decode(test_pk_hex()).unwrap();
        let ct = BASE64.encode(encrypt(&pk, binary_val, b"TLS_KEY"));
        let bundle = make_bundle(vec![("TLS_KEY", &ct, Encoding::Bytes)]);
        let ring = crate::keys::tests::make_test_ring();
        let resolved = resolve_bundle(&bundle, &ring, Path::new("/test")).unwrap();
        assert_eq!(&resolved[0].1[..], binary_val);
        assert_eq!(resolved[0].2, Encoding::Bytes);
    }

    #[test]
    fn resolve_bundle_rejects_invalid_utf8_when_declared_utf8() {
        // An entry declaring `encoding: "utf8"` whose plaintext is not
        // valid UTF-8 must fail closed; the same plaintext under
        // `encoding: "bytes"` stays byte-exact.
        let invalid = b"\xff\xfe";
        let pk = hex::decode(test_pk_hex()).unwrap();
        let ct = BASE64.encode(encrypt(&pk, invalid, b"GREETING"));
        let ring = crate::keys::tests::make_test_ring();

        let bundle = make_bundle(vec![("GREETING", &ct, Encoding::Utf8)]);
        let err = resolve_bundle(&bundle, &ring, Path::new("/test")).unwrap_err();
        assert!(
            err.contains("GREETING declares utf8 but is not valid UTF-8"),
            "{err}"
        );

        let bundle = make_bundle(vec![("GREETING", &ct, Encoding::Bytes)]);
        let resolved = resolve_bundle(&bundle, &ring, Path::new("/test")).unwrap();
        assert_eq!(&resolved[0].1[..], &invalid[..]);
    }

    #[test]
    fn resolve_bundle_multiple_entries() {
        let ct1 = enc("KEY_A", "value1");
        let ct2 = enc("KEY_B", "value2");
        let bundle = make_bundle(vec![
            ("KEY_A", &ct1, Encoding::Utf8),
            ("KEY_B", &ct2, Encoding::Utf8),
        ]);
        let ring = crate::keys::tests::make_test_ring();
        let resolved = resolve_bundle(&bundle, &ring, Path::new("/test")).unwrap();
        assert_eq!(resolved.len(), 2);
        // BTreeMap sorts by key name
        assert_eq!(resolved[0].0, "KEY_A");
        assert_eq!(&resolved[0].1[..], b"value1");
        assert_eq!(resolved[1].0, "KEY_B");
        assert_eq!(&resolved[1].1[..], b"value2");
    }

    #[test]
    fn resolve_bundle_requires_a_postmaster_key_entry() {
        // A ring containing only dotenv keys must report the missing bundle key.
        let ct = enc("SECRET", "unreachable");
        let bundle = make_bundle(vec![("SECRET", &ct, Encoding::Utf8)]);
        let env_only_ring = KeyRing::from_pairs(
            [(
                "DOTENV_PRIVATE_KEY".to_string(),
                zeroize::Zeroizing::new("22".repeat(32)),
            )],
            &[crate::adapter::KeyNaming::Env],
        )
        .unwrap();
        let err = resolve_bundle(&bundle, &env_only_ring, Path::new("/test")).unwrap_err();
        assert!(
            err.contains("key ring has no POSTMASTER_KEY entry"),
            "{err}"
        );
    }

    #[test]
    fn resolve_bundle_rejects_invalid_base64() {
        // Malformed base64 in a ciphertext field is a hard parse error naming the
        // entry, not a decrypt failure.
        let bundle = make_bundle(vec![("SECRET", "!!!not-base64!!!", Encoding::Utf8)]);
        let ring = crate::keys::tests::make_test_ring();
        let err = resolve_bundle(&bundle, &ring, Path::new("/test")).unwrap_err();
        assert!(err.contains("SECRET is not valid base64"), "{err}");
    }
}
