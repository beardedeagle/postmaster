//! Key loading, variable name resolution, and ciphertext decryption.
//!
//! All secret material is Zeroized. Decryption is tried with rotation candidates.
//! Plaintext values (from `dotenvx set --plain`) are passed through.
//!
//! Key-naming conventions are abstracted via the `KeyNaming` trait
//! (see `adapter.rs`), so the core logic is adapter-neutral. The `.env`
//! adapter's `KeyNaming::Env` is the first implementation.

#![allow(missing_docs, missing_debug_implementations)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::{Zeroize, Zeroizing};

use crate::adapter::KeyNaming;
use crate::config::Entry;

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
    pub fn load(path: &Path, naming: KeyNaming) -> Result<Self, String> {
        let oflags =
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
        let fd = rustix::fs::open(path, oflags, rustix::fs::Mode::empty()).map_err(|e| {
            format!(
                "keys file {}: {e} (refusing to follow a symlink)",
                path.display()
            )
        })?;
        let stat = rustix::fs::fstat(&fd)
            .map_err(|e| format!("keys file {}: fstat: {e}", path.display()))?;
        let mode = rustix::fs::Mode::from_bits_truncate(stat.st_mode);
        // Reject group or world accessibility. 0o077 masks both RWXG and RWXO.
        if mode.intersects(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO) {
            return Err(format!(
                "keys file {}: permissions {:#o} are group/world accessible; expected 0400 or 0600 (fail closed)",
                path.display(),
                stat.st_mode
            ));
        }
        let euid = rustix::process::geteuid().as_raw();
        if stat.st_uid != euid {
            return Err(format!(
                "keys file {}: owned by uid {} but postmaster euid is {euid} (fail closed)",
                path.display(),
                stat.st_uid
            ));
        }
        let file = std::fs::File::from(fd);
        let iter = dotenvy::from_read_iter(file);
        let mut pairs = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(|e| format!("keys file {}: {e}", path.display()))?;
            pairs.push((k, Zeroizing::new(v)));
        }
        Self::from_pairs(pairs, naming).map_err(|e| format!("keys file {}: {e}", path.display()))
    }

    /// Core parser shared by every key source: keep keys matching the
    /// adapter's key prefix, split comma-separated rotation candidates,
    /// hex-decode to 32-byte zeroized keys. Empty result is an error
    /// (fail closed). Takes `Zeroizing<String>` values so callers never
    /// hand key material as a plain heap String that drops without
    /// zeroization.
    pub fn from_pairs(
        pairs: impl IntoIterator<Item = (String, Zeroizing<String>)>,
        naming: KeyNaming,
    ) -> Result<Self, String> {
        let prefix = naming.key_prefix();
        let mut map: HashMap<String, Vec<Zeroizing<[u8; 32]>>> = HashMap::new();
        for (name, mut value) in pairs {
            if !name.starts_with(prefix) {
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
            return Err(naming.empty_error());
        }
        Ok(KeyRing(map))
    }

    /// Private key variables from the process environment (external
    /// provisioning; `key.file = null` in the module). Reads all
    /// variables matching the adapter's key prefix.
    pub fn from_env(naming: KeyNaming) -> Result<Self, String> {
        let prefix = naming.key_prefix();
        Self::from_pairs(
            std::env::vars()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k, Zeroizing::new(v))),
            naming,
        )
        .map_err(|e| format!("environment: {e}"))
    }

    /// macOS System keychain: one generic-password item per variable,
    /// service = `service`, account = the adapter's key variable name.
    /// Only the vars actually needed (derived from artifact names) are
    /// fetched.
    #[cfg(target_os = "macos")]
    pub fn from_keychain(
        service: &str,
        vars: &[String],
        naming: KeyNaming,
    ) -> Result<Self, String> {
        // Audit finding #3: verify the integrity of /usr/bin/security
        // before invoking it. On macOS the binary is SIP-protected, but
        // verify the code signature at runtime as defense-in-depth rather
        // than trusting the path implicitly.
        verify_external_binary(Path::new("/usr/bin/security"))?;
        let mut pairs = Vec::new();
        for var in vars {
            let out = std::process::Command::new("/usr/bin/security")
                .args(["find-generic-password", "-s", service, "-a", var, "-w"])
                .output()
                .map_err(|e| format!("security: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "keychain {service}: no item for account {var} (fail closed)"
                ));
            }
            let mut val = Zeroizing::new(
                String::from_utf8(out.stdout)
                    .map_err(|_| format!("keychain {service}/{var}: not UTF-8"))?,
            );
            // Zeroizing the trimmed copy: the value is wrapped in Zeroizing
            // before being passed to from_pairs, so key material is zeroized
            // on drop at every stage. No plain-String window remains.
            let trimmed = Zeroizing::new(val.trim().to_string());
            pairs.push((var.clone(), trimmed));
            val.zeroize();
        }
        Self::from_pairs(pairs, naming).map_err(|e| format!("keychain {service}: {e}"))
    }
}

/// Verify the integrity of an external binary before invoking it as part
/// of a secret-handling path. This is a defense-in-depth trust boundary
/// check (audit finding #3): the binary path is a trust root, and we
/// verify it has not been tampered with before exec.
///
/// On macOS: `codesign -v <path>` verifies the code signature. The binary
/// is additionally SIP-protected, so this catches a hypothetical SIP
/// bypass or a misconfigured environment.
///
/// On Linux: verify the file is a regular file, owned by root (uid 0),
/// and not world-writable. There is no universal code-signing mechanism
/// on Linux, so ownership and permission checks are the practical
/// defense-in-depth boundary.
pub fn verify_external_binary(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/bin/codesign")
            .args(["-v", path.to_str().unwrap_or("")])
            .output()
            .map_err(|e| format!("{}: codesign verification failed: {e}", path.display()))?;
        if !out.status.success() {
            return Err(format!(
                "{}: code signature verification failed (audit finding #3 trust boundary)",
                path.display()
            ));
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::symlink_metadata(path)
            .map_err(|e| format!("{}: cannot stat external binary: {e}", path.display()))?;
        if md.file_type().is_symlink() {
            return Err(format!(
                "{}: external binary is a symlink; refusing to trust a symlinked binary",
                path.display()
            ));
        }
        if !md.is_file() {
            return Err(format!(
                "{}: external binary is not a regular file",
                path.display()
            ));
        }
        if md.uid() != 0 {
            return Err(format!(
                "{}: external binary owned by uid {} (expected root/0); refusing to trust",
                path.display(),
                md.uid()
            ));
        }
        if md.mode() & 0o002 != 0 {
            return Err(format!(
                "{}: external binary is world-writable; refusing to trust",
                path.display()
            ));
        }
    }
    Ok(())
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
    Err(format!(
        "{}: no key under {var} decrypts {key} ({} candidate(s) tried)",
        env_file.display(),
        candidates.len()
    ))
}

/// Resolve a single entry using the key ring.
/// Supports both encrypted values and plaintext passthrough.
pub fn resolve(
    entry: &Entry,
    ring: &KeyRing,
    naming: KeyNaming,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let iter = dotenvy::from_path_iter(&entry.env_file)
        .map_err(|e| format!("{}: {e}", entry.env_file.display()))?;
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

/// Resolve every key across `files` per the precedence contract
/// (see docs/src/launcher-contract.md): within one file the LAST assignment
/// wins (dotenv semantics); across files the FIRST file defining a key wins
/// unless `overload`; keys already present in the process environment are
/// skipped unless `overload`. Adapter metadata keys are dropped;
/// non-identifier keys are a hard error (they become env names/filenames).
pub fn resolve_all(
    files: &[PathBuf],
    ring: &KeyRing,
    overload: bool,
    strict: bool,
    env_has: &dyn Fn(&str) -> bool,
    naming: KeyNaming,
) -> Result<ResolvedVars, String> {
    let metadata_prefix = naming.metadata_prefix();
    let mut order: Vec<String> = Vec::new();
    let mut merged: HashMap<String, (PathBuf, Zeroizing<String>)> = HashMap::new();
    for f in files {
        let iter = dotenvy::from_path_iter(f).map_err(|e| format!("{}: {e}", f.display()))?;
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
            let v = file_vals.remove(&k).expect("key recorded in file_order");
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
    for k in order {
        if !overload && env_has(&k) {
            continue; // process environment wins
        }
        let (file, raw) = merged.remove(&k).expect("key recorded in order");
        match decrypt_value(&file, &k, &raw, ring, naming) {
            Ok(v) => out.push((k, v)),
            Err(e) if strict => return Err(e),
            Err(e) => crate::server::log(&format!("non-strict: skipping {k}: {e}")),
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, unused_qualifications)]
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
        KeyRing::from_pairs(pairs, KeyNaming::Bundle).unwrap()
    }
    use std::io::Write;
    use std::path::Path;

    fn with_temp_keys(content: &str, f: impl FnOnce(&Path)) {
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

    fn tdir(tag: &str) -> std::path::PathBuf {
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
            KeyNaming::Env,
        )
        .unwrap();
        assert_eq!(ring.0.len(), 1);
        assert_eq!(ring.0["DOTENV_PRIVATE_KEY_PRODUCTION"].len(), 2);
    }

    #[test]
    fn from_pairs_empty_is_error() {
        assert!(
            KeyRing::from_pairs(
                [("A".to_string(), Zeroizing::new("b".to_string()))],
                KeyNaming::Env
            )
            .is_err()
        );
    }

    #[test]
    fn load_rejects_bad_hex() {
        let content = "DOTENV_PRIVATE_KEY=not-hex\n";
        with_temp_keys(content, |p| match KeyRing::load(p, KeyNaming::Env) {
            Err(e) if e.contains("not valid hex") => {}
            other => panic!("expected bad hex error, got {other:?}"),
        });
    }

    #[test]
    fn load_rejects_world_readable_keys_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "postmaster-test-keys-worldread-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "DOTENV_PRIVATE_KEY={}", "11".repeat(32)).unwrap();
        }
        // 0644: world-readable — must be rejected.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        match KeyRing::load(&path, KeyNaming::Env) {
            Err(e) if e.contains("group/world accessible") => {}
            other => panic!("expected group/world permission error, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_group_readable_keys_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "postmaster-test-keys-groupread-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "DOTENV_PRIVATE_KEY={}", "11".repeat(32)).unwrap();
        }
        // 0640: group-readable — must be rejected.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        match KeyRing::load(&path, KeyNaming::Env) {
            Err(e) if e.contains("group/world accessible") => {}
            other => panic!("expected group permission error, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_symlink_keys_file() {
        let dir = tdir("symlink-keys");
        let real = dir.join("real-keys");
        std::fs::write(&real, format!("DOTENV_PRIVATE_KEY={}\n", "11".repeat(32))).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join(".env.keys");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        match KeyRing::load(&link, KeyNaming::Env) {
            Err(e) if e.contains("symlink") => {}
            other => panic!("expected symlink rejection error, got {other:?}"),
        }
    }

    #[test]
    fn load_accepts_0600_keys_file() {
        // Sanity: a properly locked-down keys file (0600, owned by euid)
        // loads normally. This guards against false positives from the
        // permission and ownership checks.
        let content = format!("DOTENV_PRIVATE_KEY={}\n", "11".repeat(32));
        with_temp_keys(&content, |p| {
            KeyRing::load(p, KeyNaming::Env).expect("0600 keys file owned by euid should load");
        });
    }

    #[test]
    fn load_accepts_0400_keys_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "postmaster-test-keys-0400-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "DOTENV_PRIVATE_KEY={}", "11".repeat(32)).unwrap();
        }
        // 0400: read-only by owner — stricter than 0600, must pass.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        KeyRing::load(&path, KeyNaming::Env).expect("0400 keys file owned by euid should load");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn verify_external_binary_accepts_codesigned_binary() {
        // /usr/bin/security is Apple-signed and SIP-protected; the codesign
        // verification must pass. This guards against a hypothetical SIP
        // bypass or a misconfigured environment where the binary has been
        // replaced.
        verify_external_binary(std::path::Path::new("/usr/bin/security"))
            .expect("codesigned system binary should pass verification");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn verify_external_binary_rejects_unsigned_file() {
        // A temp file with no code signature must be rejected by codesign -v.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "postmaster-test-unsigned-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, b"not a signed binary").unwrap();
        let result = verify_external_binary(&path);
        let _ = std::fs::remove_file(&path);
        assert!(
            result.is_err(),
            "unsigned file should fail code signature verification"
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn verify_external_binary_rejects_non_root_owned() {
        // On Linux, a non-root-owned binary in /tmp must be rejected.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "postmaster-test-binary-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, b"fake binary").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let result = verify_external_binary(&path);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err(), "non-root-owned binary should be rejected");
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
        let got: Vec<(&str, &[u8])> = out.iter().map(|(k, v)| (k.as_str(), &v[..])).collect();
        assert_eq!(
            got,
            vec![("A", b"first".as_slice()), ("B", b"two".as_slice())]
        );

        // overload: later file wins, env presence ignored.
        let out = resolve_all(&files, &ring, true, true, &|k| k == "C", KeyNaming::Env).unwrap();
        let got: Vec<(&str, &[u8])> = out.iter().map(|(k, v)| (k.as_str(), &v[..])).collect();
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
        // non-strict: skipped, not served wrong.
        let out = resolve_all(
            &[d.join(".env")],
            &ring,
            false,
            false,
            &|_| false,
            KeyNaming::Env,
        )
        .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn from_env_loads_and_fails_closed() {
        // from_env reads ALL DOTENV_PRIVATE_KEY* vars from the process
        // environment and delegates to from_pairs. This is a single test
        // (not two) because env mutation is global and tests run in
        // parallel — two tests mutating DOTENV_PRIVATE_KEY* simultaneously
        // would race. Using a unique suffix to avoid collision with any
        // ambient vars in the test runner.
        let var_name = "DOTENV_PRIVATE_KEY_TESTFROMENV";
        let key_hex = "aa".repeat(32);

        // Positive path: set a valid key, from_env succeeds.
        // SAFETY: set_var/remove_var are unsafe on edition 2024 (not
        // thread-safe). This test does not spawn threads and the var name
        // is unique, so no concurrent test mutates the same var.
        unsafe {
            std::env::set_var(var_name, &key_hex);
        }
        let ring = KeyRing::from_env(KeyNaming::Env);
        unsafe {
            std::env::remove_var(var_name);
        }
        let ring = ring.expect("from_env should succeed with a valid key set");
        let candidates = ring
            .0
            .get(var_name)
            .expect("ring should contain the key we set");
        assert_eq!(candidates.len(), 1, "exactly one candidate expected");
        assert_eq!(&candidates[0][..], &[0xaa; 32]);

        // Negative path: set an invalid hex value, from_env fails closed
        // with an "environment:" prefixed error.
        unsafe {
            std::env::set_var(var_name, "not-valid-hex-at-all");
        }
        let err = KeyRing::from_env(KeyNaming::Env);
        unsafe {
            std::env::remove_var(var_name);
        }
        let err = err.expect_err("from_env should fail on invalid hex");
        assert!(
            err.starts_with("environment:"),
            "expected 'environment:' prefix, got: {err}"
        );

        // Also verify the from_pairs empty-error path directly: no
        // DOTENV_PRIVATE_KEY* entries at all should be an error.
        assert!(
            KeyRing::from_pairs(
                [(
                    "NOT_A_DOTENV_KEY".to_string(),
                    Zeroizing::new("x".to_string())
                )],
                KeyNaming::Env,
            )
            .is_err()
        );
    }
}
