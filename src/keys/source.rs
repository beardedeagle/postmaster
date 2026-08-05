//! Key source selection — loads the private key ring from the first
//! available source per the exec config's ordered `keys` list.
//!
//! `credential` is skippable (absent `$CREDENTIALS_DIRECTORY` or file ⇒
//! try the next source); every other source is terminal: once selected,
//! its failure fails the launcher.

use std::fs;
use std::path::Path;

use crate::adapter::KeyNaming;
use crate::exec_config::KeySourceSpec;
use crate::keys::KeyRing;

/// Ordered key-source selection. `credential` is skippable (no
/// $CREDENTIALS_DIRECTORY or file absent ⇒ try next source); every other
/// source is terminal: once selected, its failure fails the launcher.
// `wanted_vars` is only consumed by the macOS keychain source; on other
// targets the parameter is unused, so silence that leg's clippy warning
// without touching the signature or source-selection semantics.
#[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
pub fn load_ring(specs: &[KeySourceSpec], wanted_vars: &[String]) -> Result<KeyRing, String> {
    for spec in specs {
        match spec {
            KeySourceSpec::Credential(name) => {
                if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
                    let p = Path::new(&dir).join(name);
                    // Use symlink_metadata instead of p.exists(): exists()
                    // follows symlinks, so a planted symlink at
                    // $CREDENTIALS_DIRECTORY/<name> pointing to a
                    // world-readable file would be silently followed.
                    // Reject symlinks outright (audit finding #2); the
                    // subsequent KeyRing::load also opens with O_NOFOLLOW
                    // as defense-in-depth.
                    match fs::symlink_metadata(&p) {
                        Ok(md) if md.file_type().is_symlink() => {
                            return Err(format!(
                                "{}: credential source is a symlink; refusing to follow (remove the symlink)",
                                p.display()
                            ));
                        }
                        Ok(md) if md.is_file() => return KeyRing::load(&p, KeyNaming::Env),
                        Ok(_) => {
                            return Err(format!(
                                "{}: credential source is not a regular file",
                                p.display()
                            ));
                        }
                        Err(_) => { /* absent: fall through to next source */ }
                    }
                }
                // absent credential: fall through to the next source
            }
            KeySourceSpec::File(p) => {
                if p.starts_with("/nix/store") {
                    return Err(format!(
                        "{}: refusing plaintext private keys from the world-readable Nix store",
                        p.display()
                    ));
                }
                return KeyRing::load(p, KeyNaming::Env);
            }
            KeySourceSpec::Keychain(service) => {
                #[cfg(target_os = "macos")]
                return KeyRing::from_keychain(service, wanted_vars, KeyNaming::Env);
                #[cfg(not(target_os = "macos"))]
                return Err(format!(
                    "key source keychain({service}) is only available on macOS"
                ));
            }
            KeySourceSpec::Environment => return KeyRing::from_env(KeyNaming::Env),
        }
    }
    Err("no usable key source (configure keys=[…] or set DOTENV_PRIVATE_KEY*)".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, unused_qualifications)]
mod tests {
    use super::*;
    use crate::exec_config::KeySourceSpec;

    /// Serializes tests that mutate the process-global
    /// `CREDENTIALS_DIRECTORY`. The test harness runs tests in parallel
    /// threads of one process, so unsynchronized set_var/remove_var on
    /// the same variable races (observed as a flaky failure of
    /// `load_ring_credential_rejects_non_file`, 2026-08-04).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn load_ring_credential_is_skippable() {
        // credential source with no CREDENTIALS_DIRECTORY set should fall
        // through to the next source. Here the next source is "environment",
        // which is terminal and will fail closed (no DOTENV_PRIVATE_KEY*
        // vars in the test runner). The error must be from the environment
        // source, not from the credential source.
        //
        // SAFETY: set_var/remove_var are unsafe on edition 2024 (not
        // thread-safe). Serialized via ENV_LOCK against the other
        // CREDENTIALS_DIRECTORY-mutating tests in this module.
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("CREDENTIALS_DIRECTORY");
        }
        let specs = vec![
            KeySourceSpec::Credential("nonexistent".to_string()),
            KeySourceSpec::Environment,
        ];
        let err = load_ring(&specs, &[]).unwrap_err();
        // The error should come from the environment source (terminal),
        // proving credential fell through rather than erroring.
        assert!(
            err.contains("environment:") || err.contains("no usable key source"),
            "credential should be skippable; got: {err}"
        );
    }

    #[test]
    fn load_ring_credential_rejects_symlink() {
        // Audit finding #2: a symlink planted at
        // $CREDENTIALS_DIRECTORY/<name> must be rejected, not followed.
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("pm-keysource-symlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let real = d.join("real-keys");
        fs::write(&real, format!("DOTENV_PRIVATE_KEY={}\n", "11".repeat(32))).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        let cred_dir = d.join("creds");
        fs::create_dir_all(&cred_dir).unwrap();
        let link = cred_dir.join("dotenv-private-key");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // SAFETY: set_var/remove_var are unsafe on edition 2024 (not
        // thread-safe). Serialized via ENV_LOCK against the other
        // CREDENTIALS_DIRECTORY-mutating tests in this module.
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("CREDENTIALS_DIRECTORY", &cred_dir);
        }
        let specs = vec![KeySourceSpec::Credential("dotenv-private-key".to_string())];
        let err = load_ring(&specs, &[]).unwrap_err();
        unsafe {
            std::env::remove_var("CREDENTIALS_DIRECTORY");
        }
        assert!(
            err.contains("symlink"),
            "credential symlink should be rejected; got: {err}"
        );
    }

    #[test]
    fn load_ring_credential_rejects_non_file() {
        // A directory as a credential source name should be rejected,
        // not silently skipped or treated as a file.
        let d = std::env::temp_dir().join(format!("pm-keysource-dir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let cred_dir = d.join("creds");
        fs::create_dir_all(&cred_dir).unwrap();
        let sub = cred_dir.join("subdir");
        fs::create_dir_all(&sub).unwrap();

        // SAFETY: set_var/remove_var are unsafe on edition 2024 (not
        // thread-safe). Serialized via ENV_LOCK against the other
        // CREDENTIALS_DIRECTORY-mutating tests in this module.
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("CREDENTIALS_DIRECTORY", &cred_dir);
        }
        let specs = vec![KeySourceSpec::Credential("subdir".to_string())];
        let err = load_ring(&specs, &[]).unwrap_err();
        unsafe {
            std::env::remove_var("CREDENTIALS_DIRECTORY");
        }
        assert!(
            err.contains("not a regular file"),
            "credential directory should be rejected; got: {err}"
        );
    }

    #[test]
    fn load_ring_file_is_terminal() {
        // file source with a nonexistent path should return an error
        // immediately, NOT fall through to the next source. We verify this
        // by putting a valid "environment" source after the bad file source:
        // if file were skippable, load_ring would try environment and fail
        // with "environment:" — instead it must fail with the file path.
        let ghost_path = std::env::temp_dir()
            .join(format!("pm-keysource-terminal-{}", std::process::id()))
            .join("ghost.keys");
        let specs = vec![
            KeySourceSpec::File(ghost_path.clone()),
            KeySourceSpec::Environment,
        ];
        let err = load_ring(&specs, &[]).unwrap_err();
        assert!(
            err.contains("ghost.keys"),
            "file source should be terminal and error with the path; got: {err}"
        );
    }

    #[test]
    fn load_ring_file_rejects_nix_store() {
        // file source under /nix/store must return immediately with an
        // error, not fall through to a subsequent source.
        let specs = vec![
            KeySourceSpec::File(std::path::PathBuf::from("/nix/store/abc/.env.keys")),
            KeySourceSpec::Environment,
        ];
        let err = load_ring(&specs, &[]).unwrap_err();
        assert!(
            err.contains("Nix store"),
            "file source under /nix/store should be terminal and reject; got: {err}"
        );
    }

    #[test]
    fn load_ring_environment_is_terminal() {
        // environment source with no DOTENV_PRIVATE_KEY* vars should return
        // an error immediately, not fall through. Since it's the last source,
        // we verify the error is from from_env, not from the "no usable key
        // source" fallback message.
        //
        // SAFETY: set_var/remove_var are unsafe on edition 2024 (not
        // thread-safe). Serialized via ENV_LOCK against the other
        // CREDENTIALS_DIRECTORY-mutating tests in this module.
        let _guard = ENV_LOCK.lock().unwrap();
        let var_name = "DOTENV_PRIVATE_KEY_TESTTERMINAL";
        unsafe {
            std::env::remove_var(var_name);
        }
        let specs = vec![
            KeySourceSpec::Credential("skipped".to_string()),
            KeySourceSpec::Environment,
        ];
        // Remove CREDENTIALS_DIRECTORY so credential is skippable.
        unsafe {
            std::env::remove_var("CREDENTIALS_DIRECTORY");
        }
        let err = load_ring(&specs, &[]).unwrap_err();
        // The error must be from environment (terminal), not "no usable key
        // source" (which would mean environment also fell through).
        assert!(
            !err.contains("no usable key source"),
            "environment should be terminal, not fall through; got: {err}"
        );
    }
}
