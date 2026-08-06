//! Key loading, variable name resolution, and ciphertext decryption.
//!
//! All secret material is Zeroized. Decryption is tried with rotation candidates.
//! Plaintext values (from `dotenvx set --plain`) are passed through.
//!
//! Key-naming conventions are abstracted via the `KeyNaming` trait
//! (see `adapter/mod.rs`), so the core logic is adapter-neutral. The `.env`
//! adapter's `KeyNaming::Env` is the first implementation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::{Zeroize, Zeroizing};

use crate::adapter::KeyNaming;
use crate::config::Entry;

mod env;
#[cfg(target_os = "macos")]
mod keychain;
mod load;
pub mod provisioning;
pub mod source;
mod verify;

/// Re-exported so `crate::keys::verify_external_binary` keeps resolving.
pub use verify::verify_external_binary;

/// The exact predicate `KeyRing::from_env` admits, re-exported so setup
/// verification accepts precisely the variables resolution would load
/// (audit 2026-08-02 A16).
pub(crate) use env::is_key_var_name;

/// Full variable name (adapter-specific, e.g. DOTENV_PRIVATE_KEY[_<ENV>])
/// → candidate secret keys. Multiple candidates per name come from
/// comma-separated rotation convention; decryption tries each in order.
#[derive(Debug)]
pub struct KeyRing(HashMap<String, Vec<Zeroizing<[u8; 32]>>>);

impl KeyRing {
    /// Look up candidate keys for a given key variable name.
    /// Returns `None` if the variable has no candidates in the ring.
    pub fn candidates(&self, var: &str) -> Option<&[Zeroizing<[u8; 32]>]> {
        self.0.get(var).map(|v| v.as_slice())
    }

    /// Load a `.env.keys` file from `path` and build a key ring.
    ///
    /// Security invariants enforced on the opened file (all checked on the
    /// file descriptor, never the path, to eliminate TOCTOU windows):
    ///   - `O_NOFOLLOW`: reject a symlink at `path` (defense-in-depth; also
    ///     closes the credential-source symlink leg of audit finding #2).
    ///   - `mode & 0o077 == 0`: no group or world read/write/exec. A keys
    ///     file accidentally `chmod 0644` would expose private keys to every
    ///     process on the host; fail closed instead.
    ///   - `st_uid == euid`: the file must be owned by the service user.
    ///
    /// `namings` is the required adapter set; entries under other
    /// prefixes are dropped (and zeroized) at parse time.
    pub fn load(path: &Path, namings: &[KeyNaming]) -> Result<Self, String> {
        load::load(path, namings)
    }

    /// Core parser shared by every key source: keep keys matching any of
    /// the required adapters' key prefixes, split comma-separated rotation
    /// candidates, hex-decode to 32-byte zeroized keys. Empty result is an
    /// error (fail closed). Takes `Zeroizing<String>` values so callers
    /// never hand key material as a plain heap String that drops without
    /// zeroization. `namings` is the set the config's artifacts require
    /// (see `ExecConfig::required_namings`) — the ring admits exactly
    /// those prefixes, no more (least privilege on key material).
    pub fn from_pairs(
        pairs: impl IntoIterator<Item = (String, Zeroizing<String>)>,
        namings: &[KeyNaming],
    ) -> Result<Self, String> {
        let mut map: HashMap<String, Vec<Zeroizing<[u8; 32]>>> = HashMap::new();
        for (name, mut value) in pairs {
            if !namings.iter().any(|n| name.starts_with(n.key_prefix())) {
                value.zeroize();
                continue;
            }
            let mut keys = Vec::new();
            for part in value.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let mut raw =
                    hex::decode(part).map_err(|_| format!("{name}: entry is not valid hex"))?;
                if raw.len() != 32 {
                    raw.zeroize();
                    return Err(format!("{name}: expected a 32-byte key"));
                }
                let mut arr = [0_u8; 32];
                arr.copy_from_slice(&raw);
                raw.zeroize();
                keys.push(Zeroizing::new(arr));
            }
            value.zeroize();
            if keys.is_empty() {
                return Err(format!("{name}: no usable keys"));
            }
            map.insert(name, keys);
        }
        if map.is_empty() {
            return Err(empty_error(namings));
        }
        Ok(KeyRing(map))
    }

    /// Private key variables from the process environment (external
    /// provisioning; `key.file = null` in the module). Reads all
    /// variables matching any required adapter's key prefix.
    pub fn from_env(namings: &[KeyNaming]) -> Result<Self, String> {
        env::from_env(namings)
    }

    /// macOS System keychain: one generic-password item per variable,
    /// service = `service`, account = the adapter's key variable name.
    /// Only the vars actually needed (derived from artifact names) are
    /// fetched.
    #[cfg(target_os = "macos")]
    pub fn from_keychain(
        service: &str,
        vars: &[String],
        namings: &[KeyNaming],
    ) -> Result<Self, String> {
        keychain::from_keychain(service, vars, namings)
    }
}

/// Human-readable empty-ring error for a naming set: a single naming
/// keeps its adapter-specific message; multiple namings join them.
fn empty_error(namings: &[KeyNaming]) -> String {
    match namings {
        [] => "no key material admitted (empty naming set)".to_string(),
        [single] => single.empty_error(),
        many => format!(
            "no {}",
            many.iter()
                .map(|n| n.empty_error().trim_start_matches("no ").to_string())
                .collect::<Vec<_>>()
                .join(" or ")
        ),
    }
}

/// Shell-identifier check shared with the Nix module's eval-time isIdent.
pub fn is_ident(k: &str) -> bool {
    let mut cs = k.chars();
    matches!(cs.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && cs.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Decrypt one raw value: `encrypted:<b64>` via the ring (rotation-aware),
/// anything else passed through as opaque bytes (plaintext passthrough).
/// Base64 payload may contain ASCII whitespace (spaces, newlines, tabs, CR),
/// matching the lenient decoding for line-wrapped values.
pub fn decrypt_value(
    env_file: &Path,
    key: &str,
    raw: &str,
    ring: &KeyRing,
    naming: KeyNaming,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let Some(b64) = raw.strip_prefix("encrypted:") else {
        return Ok(Zeroizing::new(raw.as_bytes().to_vec()));
    };
    let ciphertext: Zeroizing<Vec<u8>> = {
        if b64.chars().any(|c| c.is_ascii_whitespace()) {
            // Zeroizing: b64_clean holds derived ciphertext material (base64
            // of the encrypted blob). Zeroize on drop for defense-in-depth,
            // matching the crate's hygiene posture on key and plaintext buffers.
            let b64_clean = Zeroizing::new(
                b64.chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect::<String>(),
            );
            Zeroizing::new(
                BASE64
                    .decode(&*b64_clean)
                    .map_err(|_| format!("{}: {key} is not valid base64", env_file.display()))?,
            )
        } else {
            Zeroizing::new(
                BASE64
                    .decode(b64)
                    .map_err(|_| format!("{}: {key} is not valid base64", env_file.display()))?,
            )
        }
    };
    let var = naming.key_var_for(env_file)?;
    let candidates = ring
        .0
        .get(&var)
        .ok_or_else(|| format!("key ring has no {var} entry"))?;
    for sk in candidates {
        if let Ok(pt) = ecies::decrypt(&sk[..], &ciphertext) {
            return Ok(Zeroizing::new(pt));
        }
    }
    // No candidate count in the error text — the rotation-set size is
    // not something errors should leak (audit 2026-08-02 A15).
    Err(format!(
        "{}: no key under {var} decrypts {key}",
        env_file.display()
    ))
}

/// Resolve a single entry using the key ring.
/// Supports both encrypted values and plaintext passthrough.
pub fn resolve(
    entry: &Entry,
    ring: &KeyRing,
    naming: KeyNaming,
) -> Result<Zeroizing<Vec<u8>>, String> {
    // O_NOFOLLOW on the ciphertext open (audit 2026-08-02 A13): refuse
    // to read through a planted symlink.
    let fd = rustix::fs::open(
        &entry.env_file,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| {
        format!(
            "{}: {e} (refusing to follow a symlink)",
            entry.env_file.display()
        )
    })?;
    let iter = dotenvy::from_read_iter(std::fs::File::from(fd));
    // Last assignment wins, matching dotenv semantics within one file.
    let mut found: Option<Zeroizing<String>> = None;
    for item in iter {
        let (k, v) = item.map_err(|e| format!("{}: {e}", entry.env_file.display()))?;
        let v = Zeroizing::new(v);
        if k == entry.key {
            found = Some(v);
        }
    }
    let raw =
        found.ok_or_else(|| format!("{}: no key named {}", entry.env_file.display(), entry.key))?;

    decrypt_value(&entry.env_file, &entry.key, &raw, ring, naming)
}

/// Resolved (name, secret-bytes) pairs, in injection order.
pub type ResolvedVars = Vec<(String, Zeroizing<Vec<u8>>)>;

/// Outcome of a [`resolve_all`] pass.
#[derive(Debug)]
pub struct Resolution {
    /// Resolved (name, plaintext) pairs in injection order.
    pub resolved: ResolvedVars,
    /// `(name, error)` for each encrypted value that could not be
    /// decrypted and was skipped under `strict: false`. Recorded so
    /// `--verify-keys` can fail closed on a partial key rotation
    /// (audit 2026-08-02 A3). Always empty under `strict: true`, where
    /// the first failure aborts the whole pass instead.
    pub failed: Vec<(String, String)>,
}

/// Resolve every key across `files` per the precedence contract
/// (see docs/src/launcher-contract.md): within one file the LAST assignment
/// wins (dotenv semantics); across files the FIRST file defining a key wins
/// unless `overload`; keys already present in the process environment are
/// skipped unless `overload`. Adapter metadata keys are dropped;
/// non-identifier keys are a hard error (they become env names/filenames).
/// Undecryptable values abort under `strict`; otherwise they are skipped
/// and recorded in [`Resolution::failed`].
pub fn resolve_all(
    files: &[PathBuf],
    ring: &KeyRing,
    overload: bool,
    strict: bool,
    env_has: &dyn Fn(&str) -> bool,
    naming: KeyNaming,
) -> Result<Resolution, String> {
    let metadata_prefix = naming.metadata_prefix();
    let mut order: Vec<String> = Vec::new();
    let mut merged: HashMap<String, (PathBuf, Zeroizing<String>)> = HashMap::new();
    for f in files {
        // O_NOFOLLOW on the ciphertext open (audit 2026-08-02 A13):
        // refuse to read through a planted symlink.
        let fd = rustix::fs::open(
            f,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| format!("{}: {e} (refusing to follow a symlink)", f.display()))?;
        let iter = dotenvy::from_read_iter(std::fs::File::from(fd));
        let mut file_vals: HashMap<String, Zeroizing<String>> = HashMap::new();
        let mut file_order: Vec<String> = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(|e| format!("{}: {e}", f.display()))?;
            let v = Zeroizing::new(v);
            if let Some(prefix) = metadata_prefix
                && k.starts_with(prefix)
            {
                continue;
            }
            if !is_ident(&k) {
                return Err(format!(
                    "{}: refusing non-identifier key {k:?}",
                    f.display()
                ));
            }
            if !file_vals.contains_key(&k) {
                file_order.push(k.clone());
            }
            file_vals.insert(k, v); // last assignment within a file wins
        }
        for k in file_order {
            // Unreachable invariant (file_order mirrors file_vals), but a
            // clear error beats an abort under panic=abort (audit
            // 2026-08-02 A22).
            let Some(v) = file_vals.remove(&k) else {
                return Err(format!("internal: {k} in file_order but not file_vals"));
            };
            if let Some(slot) = merged.get_mut(&k) {
                if overload {
                    *slot = (f.clone(), v); // later file wins under overload
                }
            } else {
                order.push(k.clone());
                merged.insert(k, (f.clone(), v));
            }
        }
    }
    let mut out = Vec::new();
    let mut failed = Vec::new();
    for k in order {
        if !overload && env_has(&k) {
            continue; // process environment wins
        }
        // Unreachable invariant (order mirrors merged), but a clear error
        // beats an abort under panic=abort (audit 2026-08-02 A22).
        let Some((file, raw)) = merged.remove(&k) else {
            return Err(format!("internal: {k} in order but not merged"));
        };
        match decrypt_value(&file, &k, &raw, ring, naming) {
            Ok(v) => out.push((k, v)),
            Err(e) if strict => return Err(e),
            Err(e) => {
                crate::server::log(&format!("non-strict: skipping {k}: {e}"));
                failed.push((k, e));
            }
        }
    }
    Ok(Resolution {
        resolved: out,
        failed,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, unused_qualifications)]
/// Inline unit tests for key loading, resolution, and decryption.
pub mod tests {
    use super::*;
    use crate::adapter::KeyNaming;

    /// Test secret key hex — never use outside tests.
    pub const TEST_SK_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    /// Build a test key ring with the test secret key under
    /// `POSTMASTER_KEY` (for bundle adapter tests).
    pub fn make_test_ring() -> KeyRing {
        let pairs = vec![(
            "POSTMASTER_KEY".to_string(),
            Zeroizing::new(TEST_SK_HEX.to_string()),
        )];
        KeyRing::from_pairs(pairs, &[KeyNaming::Bundle]).unwrap()
    }
    use std::io::Write;
    use std::path::Path;

    /// Shared with the `load` submodule's tests.
    pub fn with_temp_keys(content: &str, f: impl FnOnce(&Path)) {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "postmaster-test-keys-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "{}", content).unwrap();
        }
        // KeyRing::load now enforces 0600-or-stricter permissions (audit
        // finding #1). The temp file must pass that check.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        f(&path);
        let _ = std::fs::remove_file(&path);
    }

    /// Shared with the `load` submodule's tests.
    pub fn tdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("pm-keys-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn key_var_for_basic() {
        assert_eq!(
            KeyNaming::Env
                .key_var_for(std::path::Path::new(".env"))
                .unwrap(),
            "DOTENV_PRIVATE_KEY"
        );
        assert_eq!(
            KeyNaming::Env
                .key_var_for(std::path::Path::new(".env.production"))
                .unwrap(),
            "DOTENV_PRIVATE_KEY_PRODUCTION"
        );
        assert_eq!(
            KeyNaming::Env
                .key_var_for(std::path::Path::new(".env.staging_v2"))
                .unwrap(),
            "DOTENV_PRIVATE_KEY_STAGING_V2"
        );
    }

    #[test]
    fn load_rotated_keys_and_plaintext_env() {
        // Create a real .env file with a plaintext value (simulating --plain)
        let env_dir = std::env::temp_dir();
        let env_path = env_dir.join(format!(
            "postmaster-test-env-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        {
            let mut f = std::fs::File::create(&env_path).unwrap();
            writeln!(f, "PLAIN=hello-world").unwrap();
        }

        let entry = Entry {
            env_file: env_path.clone(),
            key: "PLAIN".to_string(),
            peer_user: None,
        };
        // Ring can be empty for plaintext path
        let ring = KeyRing(HashMap::new());
        let result = resolve(&entry, &ring, KeyNaming::Env).unwrap();
        assert_eq!(&*result, b"hello-world");

        let _ = std::fs::remove_file(&env_path);
    }

    #[test]
    fn from_pairs_filters_and_rotates() {
        let ring = KeyRing::from_pairs(
            [
                ("UNRELATED".to_string(), Zeroizing::new("x".to_string())),
                (
                    "DOTENV_PRIVATE_KEY_PRODUCTION".to_string(),
                    Zeroizing::new(format!("{},{}", "22".repeat(32), "33".repeat(32))),
                ),
            ],
            &[KeyNaming::Env],
        )
        .unwrap();
        assert_eq!(ring.0.len(), 1);
        assert_eq!(ring.0["DOTENV_PRIVATE_KEY_PRODUCTION"].len(), 2);
    }

    #[test]
    fn from_pairs_admits_exactly_the_required_namings() {
        // The bundle-ring gap fix: a config requiring both adapters must
        // get both prefix families in the ring, and nothing else.
        let pairs = || {
            [
                (
                    "DOTENV_PRIVATE_KEY".to_string(),
                    Zeroizing::new("22".repeat(32)),
                ),
                (
                    "POSTMASTER_KEY".to_string(),
                    Zeroizing::new("33".repeat(32)),
                ),
                ("UNRELATED".to_string(), Zeroizing::new("44".repeat(32))),
            ]
        };

        let both = KeyRing::from_pairs(pairs(), &[KeyNaming::Env, KeyNaming::Bundle]).unwrap();
        assert!(both.candidates("DOTENV_PRIVATE_KEY").is_some());
        assert!(both.candidates("POSTMASTER_KEY").is_some());
        assert_eq!(both.0.len(), 2, "UNRELATED must be dropped");

        // Least privilege: a naming the config does not require is NOT
        // admitted, even when the source provides it.
        let env_only = KeyRing::from_pairs(pairs(), &[KeyNaming::Env]).unwrap();
        assert!(env_only.candidates("DOTENV_PRIVATE_KEY").is_some());
        assert!(env_only.candidates("POSTMASTER_KEY").is_none());

        // A bundle-only requirement with only Env material present fails
        // closed with the adapter's own empty message.
        let err = KeyRing::from_pairs(
            [(
                "DOTENV_PRIVATE_KEY".to_string(),
                Zeroizing::new("22".repeat(32)),
            )],
            &[KeyNaming::Bundle],
        )
        .unwrap_err();
        assert_eq!(err, KeyNaming::Bundle.empty_error());
    }

    #[test]
    fn from_pairs_empty_is_error() {
        assert!(
            KeyRing::from_pairs(
                [("A".to_string(), Zeroizing::new("b".to_string()))],
                &[KeyNaming::Env]
            )
            .is_err()
        );
    }

    #[test]
    fn is_ident_rules() {
        assert!(is_ident("DATABASE_URL") && is_ident("_x9"));
        assert!(!is_ident("9x") && !is_ident("a-b") && !is_ident("") && !is_ident("a b"));
    }

    #[test]
    fn resolve_all_precedence() {
        let d = tdir("prec");
        std::fs::write(
            d.join(".env"),
            "A=first\nB=one\nB=two\nDOTENV_PUBLIC_KEY=zz\n",
        )
        .unwrap();
        std::fs::write(d.join(".env.local"), "A=second\nC=three\n").unwrap();
        let files = [d.join(".env"), d.join(".env.local")];
        let ring = KeyRing(HashMap::new());

        // default: first file wins; within a file last assignment wins;
        // process-env presence suppresses; DOTENV_* filtered.
        let out = resolve_all(&files, &ring, false, true, &|k| k == "C", KeyNaming::Env).unwrap();
        let got: Vec<(&str, &[u8])> = out
            .resolved
            .iter()
            .map(|(k, v)| (k.as_str(), &v[..]))
            .collect();
        assert_eq!(
            got,
            vec![("A", b"first".as_slice()), ("B", b"two".as_slice())]
        );

        // overload: later file wins, env presence ignored.
        let out = resolve_all(&files, &ring, true, true, &|k| k == "C", KeyNaming::Env).unwrap();
        let got: Vec<(&str, &[u8])> = out
            .resolved
            .iter()
            .map(|(k, v)| (k.as_str(), &v[..]))
            .collect();
        assert_eq!(
            got,
            vec![
                ("A", b"second".as_slice()),
                ("B", b"two".as_slice()),
                ("C", b"three".as_slice())
            ]
        );
    }

    #[test]
    fn resolve_all_rejects_non_identifier() {
        // dotenvy rejects keys starting with `-` or digit during parsing, but accepts `.`
        // in subsequent characters (e.g., BAD.KEY=x parses fine). Our is_ident check rejects
        // `.` in all positions, so a dotted key exercises the rejection branch in resolve_all.
        let d = tdir("ident");
        std::fs::write(d.join(".env"), "BAD.KEY=x\n").unwrap();
        let ring = KeyRing(HashMap::new());
        let e = resolve_all(
            &[d.join(".env")],
            &ring,
            false,
            true,
            &|_| false,
            KeyNaming::Env,
        )
        .unwrap_err();
        assert!(e.contains("non-identifier"), "{e}");
    }

    #[test]
    fn resolve_all_strict_fails_on_undecryptable() {
        let d = tdir("strict");
        std::fs::write(d.join(".env"), "A=encrypted:!!!notbase64\n").unwrap();
        let ring = KeyRing(HashMap::new());
        assert!(
            resolve_all(
                &[d.join(".env")],
                &ring,
                false,
                true,
                &|_| false,
                KeyNaming::Env
            )
            .is_err()
        );
        // non-strict: skipped, not served wrong — and the skip is
        // recorded so --verify-keys can fail closed on it (audit
        // 2026-08-02 A3).
        let out = resolve_all(
            &[d.join(".env")],
            &ring,
            false,
            false,
            &|_| false,
            KeyNaming::Env,
        )
        .unwrap();
        assert!(out.resolved.is_empty());
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].0, "A");
    }
}
