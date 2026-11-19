//! `postmaster setup` command path.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use super::ensure_keychain_items;
use super::{default_keys_dir, ensure_keys_dir, ensure_keys_file, verify_key_sources};
use crate::adapter::KeyNaming;
use crate::exec_config::{ExecConfig, ExecMode, KeySourceSpec};
use crate::server::log;

/// Resolve distinct setup key variables in first-seen input order.
fn wanted_keys(cfg: &ExecConfig) -> Result<Vec<String>, String> {
    let mut wanted = Vec::new();
    for f in &cfg.env_files {
        wanted.push(KeyNaming::Env.key_var_for(f)?);
    }
    for f in &cfg.bundle_files {
        wanted.push(KeyNaming::Bundle.key_var_for(f)?);
    }
    let mut seen = HashSet::new();
    wanted.retain(|key| seen.insert(key.clone()));
    Ok(wanted)
}

/// `postmaster setup`: verify platform prerequisites, create keys
/// directory with correct permissions, optionally seed keychain items,
/// and validate the environment. Idempotent — skips steps that are
/// already correct.
///
/// `--recheck`: re-run verification checks only, without creating or
/// modifying anything.
///
/// `--unattended`: non-interactive mode for automation. Uses defaults
/// or env vars instead of prompting. Fail closed on any missing
/// prerequisite.
///
/// `--force`: re-seed or re-create even if the target state is already
/// present.
///
/// `--keys-dir <path>`: override the keys directory path.
pub fn setup(
    config_path: &Path,
    recheck: bool,
    unattended: bool,
    force: bool,
    keys_dir_override: Option<PathBuf>,
) -> Result<(), String> {
    if recheck && force {
        return Err("setup: --recheck conflicts with --force".into());
    }
    let cfg = crate::launcher::parse_exec_config(config_path)?;
    cfg.validate_shape()?;

    if cfg.mode == ExecMode::Credentials {
        log("setup: credentials mode requires no private key sources");
        return Ok(());
    }

    let wanted = wanted_keys(&cfg)?;

    if recheck {
        // --recheck: verification only, no creation or modification
        return verify_key_sources(&cfg, &wanted);
    }

    // Step 1: Create or verify keys directory
    let keys_dir = keys_dir_override.unwrap_or_else(default_keys_dir);
    ensure_keys_dir(&keys_dir, force)?;

    // Step 2: Verify or create key files for file-source keys
    for spec in &cfg.keys {
        if let KeySourceSpec::File(path) = spec {
            ensure_keys_file(path, force, unattended)?;
        }
    }

    // Step 3: Verify or seed keychain items (macOS only)
    #[cfg(target_os = "macos")]
    for spec in &cfg.keys {
        if let KeySourceSpec::Keychain(service) = spec {
            ensure_keychain_items(service, &wanted, force, unattended)?;
        }
    }

    // Step 4: Verify the full environment (same as --recheck)
    verify_key_sources(&cfg, &wanted)?;

    log(&format!(
        "setup: complete — keys dir {}, selected key source verified",
        keys_dir.display(),
    ));
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn credentials_setup_does_not_create_or_require_key_sources() {
        let dir = crate::test_util::temp_dir::TestDir::new("credentials-setup");
        let config = dir.join("exec.json");
        let keys_dir = dir.join("unused");
        std::fs::write(
            &config,
            r#"{"mode":"credentials","credential_keys":["DB"]}"#,
        )
        .unwrap();
        for recheck in [false, true] {
            setup(&config, recheck, true, false, Some(keys_dir.clone())).unwrap();
            assert!(!keys_dir.exists());
        }
        assert!(setup(&config, true, true, true, None).is_err());
    }

    #[test]
    fn setup_keys_are_unique_and_keep_first_seen_order() {
        let mut cfg: ExecConfig = serde_json::from_value(serde_json::json!({
            "mode": "env", "keys": [{"keychain": "postmaster"}],
            "bundle_files": ["/x/first.json", "/x/second.json"]
        }))
        .unwrap();
        assert_eq!(wanted_keys(&cfg).unwrap(), ["POSTMASTER_KEY"]);
        cfg.env_files = [
            "/x/.env.production",
            "/x/.env",
            "/y/.env.production",
            "/x/.env.development",
        ]
        .map(PathBuf::from)
        .into();
        assert_eq!(
            wanted_keys(&cfg).unwrap(),
            [
                "DOTENV_PRIVATE_KEY_PRODUCTION",
                "DOTENV_PRIVATE_KEY",
                "DOTENV_PRIVATE_KEY_DEVELOPMENT",
                "POSTMASTER_KEY"
            ]
        );
        cfg.env_files.push("/x/.env.bad-name".into());
        assert!(wanted_keys(&cfg).is_err());
    }
}
