//! `postmaster setup` command path.

use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use super::ensure_keychain_items;
use super::{default_keys_dir, ensure_keys_dir, ensure_keys_file, verify_key_sources};
use crate::adapter::KeyNaming;
use crate::exec_config::KeySourceSpec;
use crate::server::log;

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
    let cfg = crate::launcher::parse_exec_config(config_path)?;
    cfg.validate_shape()?;

    // Build the wanted key variable list from both env and bundle files
    let mut wanted: Vec<String> = Vec::new();
    for f in &cfg.env_files {
        wanted.push(KeyNaming::Env.key_var_for(f)?);
    }
    for f in &cfg.bundle_files {
        wanted.push(KeyNaming::Bundle.key_var_for(f)?);
    }

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
        "setup: complete — keys dir {}, {} key source(s) verified",
        keys_dir.display(),
        cfg.keys.len()
    ));
    Ok(())
}
