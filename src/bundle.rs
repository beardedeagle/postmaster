//! `postmaster_bundle` adapter: a neutral JSON container for encrypted
//! secrets that doesn't pretend to be an `.env` file.
//!
//! The bundle format is a JSON file with:
//! - `format`: must be `"postmaster.bundle"` (fail closed on unknown)
//! - `version`: integer, must be `1`
//! - `profile`: optional public selection metadata (not a secret)
//! - `suite`: mandatory crypto suite identifier (must match the ECIES path)
//! - `recipients`: array of `{ id, public_key }` — public routing metadata
//! - `entries`: map of key name → `{ encoding, ciphertext }`
//!
//! All fields are public metadata except `ciphertext`, which is
//! encrypted and authenticated. Entries use the same identifier rule
//! as `.env`-derived keys: `[A-Za-z_][A-Za-z0-9_]*`.

#![allow(missing_docs, missing_debug_implementations)]

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::keys::{KeyRing, is_ident};

/// The top-level bundle container.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    /// Must be `"postmaster.bundle"`.
    pub format: String,
    /// Must be `1`.
    pub version: u32,
    /// Optional public selection metadata (not a secret).
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

/// A recipient in the bundle: public routing metadata used to select
/// local private key material.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    /// Public identifier for this recipient (e.g., `"host:api-01"`).
    pub id: String,
    /// Compressed secp256k1 public key (hex-encoded).
    pub public_key: String,
}

/// An encrypted entry in the bundle.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct BundleEntry {
    /// Either `"utf8"` or `"bytes"`. `env` projection rejects bytes that
    /// cannot become a POSIX environment value; `files` and `credentials`
    /// preserve byte-exact values.
    pub encoding: Encoding,
    /// Base64-encoded ECIES ciphertext.
    pub ciphertext: String,
}

/// Value encoding type.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Utf8,
    Bytes,
}

/// Parse a bundle JSON file from raw bytes.
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
    if bundle.suite != "ecies-secp256k1-hkdf-sha256-aes-256-gcm" {
        return Err(format!(
            "{}: unsupported suite {:?} (expected ecies-secp256k1-hkdf-sha256-aes-256-gcm)",
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
        let mut decrypted: Option<Zeroizing<Vec<u8>>> = None;
        for sk in candidates {
            if let Ok(pt) = ecies::decrypt(&sk[..], &ciphertext) {
                decrypted = Some(Zeroizing::new(pt));
                break;
            }
        }
        match decrypted {
            Some(pt) => out.push((name.clone(), pt, entry.encoding)),
            None => {
                let _ = ciphertext; // zeroize on drop
                return Err(format!(
                    "{}: no key under {var} decrypts {name} ({} candidate(s) tried)",
                    bundle_path.display(),
                    candidates.len()
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
            suite: "ecies-secp256k1-hkdf-sha256-aes-256-gcm".into(),
            recipients: vec![Recipient {
                id: "test".into(),
                public_key: test_pk_hex(),
            }],
            entries: map,
        }
    }

    fn enc(value: &str) -> String {
        let pk = hex::decode(test_pk_hex()).unwrap();
        let ct = ecies::encrypt(&pk, value.as_bytes()).unwrap();
        BASE64.encode(ct)
    }

    #[test]
    fn parse_bundle_validates_format() {
        let raw = serde_json::json!({
            "format": "wrong",
            "version": 1,
            "suite": "ecies-secp256k1-hkdf-sha256-aes-256-gcm",
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
            "suite": "ecies-secp256k1-hkdf-sha256-aes-256-gcm",
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
            "suite": "ecies-secp256k1-hkdf-sha256-aes-256-gcm",
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
            "suite": "ecies-secp256k1-hkdf-sha256-aes-256-gcm",
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
        let ct = enc("hello-bundle");
        let bundle = make_bundle(vec![("SECRET", &ct, Encoding::Utf8)]);
        let ring = crate::keys::tests::make_test_ring();
        let resolved = resolve_bundle(&bundle, &ring, Path::new("/test")).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, "SECRET");
        assert_eq!(&resolved[0].1[..], b"hello-bundle");
        assert_eq!(resolved[0].2, Encoding::Utf8);
    }

    #[test]
    fn resolve_bundle_fails_on_wrong_key() {
        let other_sk = "22".repeat(32);
        let other_sk_bytes = hex::decode(&other_sk).unwrap();
        let other_sk = ecies::SecretKey::parse_slice(&other_sk_bytes).unwrap();
        let other_pk = ecies::PublicKey::from_secret_key(&other_sk);
        let ct = BASE64
            .encode(ecies::encrypt(&other_pk.serialize_compressed(), b"unreachable").unwrap());
        let bundle = make_bundle(vec![("SECRET", &ct, Encoding::Utf8)]);
        let ring = crate::keys::tests::make_test_ring();
        let err = resolve_bundle(&bundle, &ring, Path::new("/test")).unwrap_err();
        assert!(err.contains("no key under"), "{err}");
    }

    #[test]
    fn resolve_bundle_handles_bytes_encoding() {
        let binary_val = b"\x00\x01\x02\xff";
        let pk = hex::decode(test_pk_hex()).unwrap();
        let ct = BASE64.encode(ecies::encrypt(&pk, binary_val).unwrap());
        let bundle = make_bundle(vec![("TLS_KEY", &ct, Encoding::Bytes)]);
        let ring = crate::keys::tests::make_test_ring();
        let resolved = resolve_bundle(&bundle, &ring, Path::new("/test")).unwrap();
        assert_eq!(&resolved[0].1[..], binary_val);
        assert_eq!(resolved[0].2, Encoding::Bytes);
    }

    #[test]
    fn resolve_bundle_multiple_entries() {
        let ct1 = enc("value1");
        let ct2 = enc("value2");
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
}
