//! Key provisioning — setup and verification of key sources, key
//! directory creation, keychain seeding, and runtime key source checks.
//!
//! This module implements the `postmaster setup` and `postmaster cleanup`
//! commands, plus the key-provisioning helpers they depend on.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::adapter::KeyNaming;
use crate::exec_config::{ExecConfig, KeySourceSpec};
use crate::server::log;

/// Default keys directory path: `/var/lib/postmaster` on Linux,
/// `~/Library/Application Support/postmaster` on macOS.
fn default_keys_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("postmaster");
        }
    }
    PathBuf::from("/var/lib/postmaster")
}

/// Create the keys directory with 0700 permissions if it doesn't exist.
/// If it exists, verify permissions and ownership are correct. Idempotent
/// — skips if already correct unless `force` is true.
#[allow(clippy::print_stderr)]
fn ensure_keys_dir(keys_dir: &Path, _force: bool) -> Result<(), String> {
    if keys_dir.exists() {
        // Open the directory itself and work on the fd throughout:
        // O_DIRECTORY|O_NOFOLLOW rejects symlinks and non-directories at
        // open, and fchmod on the fd eliminates the TOCTOU between a
        // path-based check and a path-based chmod (audit 2026-08-02 A5).
        let dir_fd = rustix::fs::open(
            keys_dir,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| {
            format!(
                "{}: cannot open keys directory: {e} (refusing a symlink or non-directory)",
                keys_dir.display()
            )
        })?;
        let stat = rustix::fs::fstat(&dir_fd)
            .map_err(|e| format!("{}: fstat: {e}", keys_dir.display()))?;
        let mode = rustix::fs::Mode::from_bits_truncate(stat.st_mode);
        if mode.intersects(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO) {
            // Fix permissions if we can
            rustix::fs::fchmod(&dir_fd, rustix::fs::Mode::RWXU)
                .map_err(|e| format!("{}: cannot fix permissions: {e}", keys_dir.display()))?;
            log(&format!(
                "{}: permissions corrected to 0700",
                keys_dir.display()
            ));
        }
        log(&format!("{}: keys directory verified", keys_dir.display()));
        return Ok(());
    }

    // Create the directory with 0700. create_dir_all follows intermediate
    // symlinks, so first reject any existing symlink component in the
    // prefix (audit 2026-08-02 O5). Residual TOCTOU: a component could be
    // swapped between this check and the create, but an attacker with
    // that write access could plant the symlink outright — and the open
    // below is still NOFOLLOW on the final component.
    let mut prefix = PathBuf::new();
    for comp in keys_dir.components() {
        prefix.push(comp);
        if let Ok(md) = fs::symlink_metadata(&prefix)
            && md.file_type().is_symlink()
        {
            return Err(format!(
                "{}: refusing to create keys directory through a symlinked component",
                prefix.display()
            ));
        }
    }
    fs::create_dir_all(keys_dir)
        .map_err(|e| format!("{}: cannot create keys directory: {e}", keys_dir.display()))?;
    let dir_fd = rustix::fs::open(
        keys_dir,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| format!("{}: cannot open keys directory: {e}", keys_dir.display()))?;
    rustix::fs::fchmod(&dir_fd, rustix::fs::Mode::RWXU)
        .map_err(|e| format!("{}: cannot set permissions: {e}", keys_dir.display()))?;
    log(&format!(
        "{}: keys directory created with 0700",
        keys_dir.display()
    ));
    Ok(())
}

/// Verify a keys file exists with correct permissions (0600, owned by
/// euid). If the file doesn't exist, in interactive mode, prompt the
/// operator to create it. In unattended mode, fail closed. If the file
/// exists but has wrong permissions, fix them.
#[allow(clippy::print_stderr)]
fn ensure_keys_file(path: &Path, _force: bool, unattended: bool) -> Result<(), String> {
    if path.exists() {
        // Verify permissions and ownership (same checks as setup_recheck)
        let oflags =
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
        let fd = rustix::fs::open(path, oflags, rustix::fs::Mode::empty())
            .map_err(|e| format!("{}: {e} (refusing to follow a symlink)", path.display()))?;
        let stat = rustix::fs::fstat(&fd).map_err(|e| format!("{}: fstat: {e}", path.display()))?;
        let mode = rustix::fs::Mode::from_bits_truncate(stat.st_mode);
        if mode.intersects(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO) {
            // Fix permissions
            rustix::fs::fchmod(&fd, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
                .map_err(|e| format!("{}: cannot fix permissions: {e}", path.display()))?;
            log(&format!(
                "{}: permissions corrected to 0600",
                path.display()
            ));
        }
        let euid = rustix::process::geteuid().as_raw();
        if stat.st_uid != euid {
            return Err(format!(
                "{}: owned by uid {} but postmaster euid is {euid} (cannot fix ownership automatically)",
                path.display(),
                stat.st_uid
            ));
        }
        log(&format!("{}: keys file verified", path.display()));
        return Ok(());
    }

    // File doesn't exist
    if unattended {
        return Err(format!(
            "{}: keys file not found (unattended mode — cannot prompt; create the file manually before running setup)",
            path.display()
        ));
    }

    // Interactive: prompt the operator
    eprintln!("{}: keys file not found.", path.display());
    eprintln!(
        "Create it now? You will need to paste the key contents (DOTENV_PRIVATE_KEY=<64-hex>...). [y/N] "
    );
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return Err(format!("{}: cannot read input", path.display()));
    }
    if !input.trim().eq_ignore_ascii_case("y") {
        return Err(format!(
            "{}: operator declined to create keys file",
            path.display()
        ));
    }

    eprintln!("Paste the keys file contents (Ctrl+D to finish):");
    // Zeroizing: operator-pasted key material must not linger in freed
    // heap pages (audit 2026-08-02 O4).
    let mut contents = zeroize::Zeroizing::new(String::new());
    if std::io::stdin().read_to_string(&mut contents).is_err() {
        return Err(format!("{}: cannot read key contents", path.display()));
    }

    // Write the file with 0600. O_EXCL | O_NOFOLLOW makes creation
    // fail-closed: it refuses to overwrite anything already at the path
    // and refuses to follow a planted symlink.
    let oflags = rustix::fs::OFlags::WRONLY
        | rustix::fs::OFlags::CREATE
        | rustix::fs::OFlags::EXCL
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    let fd = rustix::fs::open(path, oflags, rustix::fs::Mode::from_bits_truncate(0o600)).map_err(
        |e| {
            format!(
                "{}: cannot create: {e} (refusing to overwrite or follow a symlink)",
                path.display()
            )
        },
    )?;
    let mut file = fs::File::from(fd);
    use std::io::Write;
    file.write_all(contents.as_bytes())
        .map_err(|e| format!("{}: cannot write: {e}", path.display()))?;
    log(&format!("{}: keys file created with 0600", path.display()));
    Ok(())
}

/// Verify keychain items exist for the wanted key variables. If they
/// don't exist and we're in interactive mode, offer to seed them.
/// On macOS only.
#[cfg(target_os = "macos")]
#[allow(clippy::print_stderr)]
fn ensure_keychain_items(
    service: &str,
    wanted: &[String],
    force: bool,
    unattended: bool,
) -> Result<(), String> {
    let mut missing: Vec<&str> = Vec::new();
    for var in wanted {
        // Existence check via the Security.framework API (F1) — no
        // subprocess; retrieved bytes zeroized on drop (A17).
        match security_framework::passwords::get_generic_password(service, var) {
            Ok(bytes) => {
                let _ = zeroize::Zeroizing::new(bytes); // zeroize on drop
            }
            Err(_) => missing.push(var),
        }
    }

    if missing.is_empty() && !force {
        log(&format!(
            "keychain {service}: all {wanted_len} item(s) verified",
            wanted_len = wanted.len()
        ));
        return Ok(());
    }

    if unattended && !missing.is_empty() {
        return Err(format!(
            "keychain {service}: {missing_len} item(s) missing (unattended mode — cannot prompt)",
            missing_len = missing.len()
        ));
    }

    // Interactive: offer to seed missing items
    if !missing.is_empty() {
        eprintln!(
            "keychain {service}: missing items for: {}",
            missing.join(", ")
        );
        eprintln!("Seed them now? You will need to paste each key value. [y/N] ");
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            return Err("cannot read input".into());
        }
        if !input.trim().eq_ignore_ascii_case("y") {
            return Err(format!(
                "keychain {service}: operator declined to seed missing items"
            ));
        }

        for var in &missing {
            eprint!("Paste value for {var}: ");
            // Zeroizing: pasted key material must not linger in freed
            // heap pages (audit 2026-08-02 O4). `trim()` borrows, no copy.
            let mut value = zeroize::Zeroizing::new(String::new());
            if std::io::stdin().read_line(&mut value).is_err() {
                return Err(format!("cannot read value for {var}"));
            }
            let value = value.trim();
            if value.is_empty() {
                return Err(format!("{var}: empty value, refusing to seed"));
            }
            // Seed via the Security.framework API, not the security CLI:
            // `add-generic-password -w <value>` exposes key material in
            // the subprocess argv, readable by any local process via ps /
            // proc_pidinfo (audit 2026-08-02 O3; F1 crate direction).
            security_framework::passwords::set_generic_password(service, var, value.as_bytes())
                .map_err(|e| format!("keychain {service}: failed to seed {var}: {e}"))?;
            log(&format!("keychain {service}: seeded {var}"));
        }
    }

    Ok(())
}

/// Verify that all configured key sources are accessible. This is the
/// `--recheck` path — same as the old `setup_recheck` function.
fn verify_key_sources(cfg: &ExecConfig, wanted: &[String]) -> Result<(), String> {
    // `wanted` is only consulted by the macOS keychain check below.
    #[cfg(not(target_os = "macos"))]
    let _ = wanted;
    let mut checked = 0_u32;
    let mut found = 0_u32;

    for spec in &cfg.keys {
        match spec {
            KeySourceSpec::Credential(name) => {
                checked += 1;
                let dir = std::env::var_os("CREDENTIALS_DIRECTORY")
                    .ok_or("$CREDENTIALS_DIRECTORY is not set")?;
                let p = Path::new(&dir).join(name);
                if !p.exists() {
                    return Err(format!(
                        "{}: credential source not found under $CREDENTIALS_DIRECTORY",
                        p.display()
                    ));
                }
                found += 1;
            }
            KeySourceSpec::File(path) => {
                checked += 1;
                if path.starts_with("/nix/store") {
                    return Err(format!(
                        "{}: refusing plaintext private keys from the world-readable Nix store",
                        path.display()
                    ));
                }
                let oflags = rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC;
                let fd =
                    rustix::fs::open(path, oflags, rustix::fs::Mode::empty()).map_err(|e| {
                        format!("{}: {e} (refusing to follow a symlink)", path.display())
                    })?;
                let stat = rustix::fs::fstat(&fd)
                    .map_err(|e| format!("{}: fstat: {e}", path.display()))?;
                let mode = rustix::fs::Mode::from_bits_truncate(stat.st_mode);
                if mode.intersects(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO) {
                    return Err(format!(
                        "{}: permissions {:#o} are group/world accessible; expected 0400 or 0600",
                        path.display(),
                        stat.st_mode
                    ));
                }
                let euid = rustix::process::geteuid().as_raw();
                if stat.st_uid != euid {
                    return Err(format!(
                        "{}: owned by uid {} but postmaster euid is {euid}",
                        path.display(),
                        stat.st_uid
                    ));
                }
                found += 1;
            }
            KeySourceSpec::Keychain(service) => {
                #[cfg(target_os = "macos")]
                {
                    checked += 1;
                    for var in wanted {
                        // Security.framework API (F1) — no subprocess;
                        // retrieved bytes zeroized on drop (A17).
                        match security_framework::passwords::get_generic_password(service, var) {
                            Ok(bytes) => {
                                let _ = zeroize::Zeroizing::new(bytes); // zeroize on drop
                            }
                            Err(_) => {
                                return Err(format!(
                                    "keychain {service}: no item for account {var} (fail closed)"
                                ));
                            }
                        }
                    }
                    found += 1;
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = service;
                    return Err("keychain source is only available on macOS".into());
                }
            }
            KeySourceSpec::Environment => {
                checked += 1;
                let env_prefix = KeyNaming::Env.key_prefix();
                let bundle_prefix = KeyNaming::Bundle.key_prefix();
                let has_key = std::env::vars()
                    .any(|(k, _)| k.starts_with(env_prefix) || k.starts_with(bundle_prefix));
                if !has_key {
                    return Err(format!(
                        "environment: no {env_prefix}* or {bundle_prefix}* variables set"
                    ));
                }
                found += 1;
            }
        }
    }

    if checked == 0 {
        return Err("no key sources configured (configure keys=[…])".into());
    }

    log(&format!(
        "setup: {found}/{checked} key source(s) verified — environment ready"
    ));
    Ok(())
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

/// `postmaster cleanup`: remove all secret files from the secrets_dir
/// configured in the exec config. Intended for `ExecStopPost` in systemd
/// or equivalent lifecycle hooks. Does not decrypt — only removes files
/// that postmaster would have written. Bulk removal is guarded by the
/// `.postmaster-managed` sentinel: a non-empty directory lacking it is
/// refused (postmaster only bulk-deletes directories it manages). Safe
/// to run even if the directory is empty or does not exist.
pub fn cleanup(config_path: &Path) -> Result<(), String> {
    let cfg = crate::launcher::parse_exec_config(config_path)?;
    let dir = cfg
        .secrets_dir
        .as_deref()
        .ok_or("cleanup: config has no secrets_dir — nothing to clean up")?;
    // Refuse to bulk-delete in a directory that isn't clearly
    // postmaster-managed (audit 2026-08-02 A19): in a symlinked or
    // group/world-accessible dir these deletes could hit foreign files.
    let md = match fs::symlink_metadata(dir) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log(&format!(
                "cleanup: {} does not exist; nothing to clean up",
                dir.display()
            ));
            return Ok(());
        }
        Err(e) => return Err(format!("{}: cleanup: {e}", dir.display())),
    };
    if md.file_type().is_symlink() || !md.is_dir() {
        return Err(format!(
            "{}: cleanup: refusing a symlinked or non-directory secrets dir",
            dir.display()
        ));
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log(&format!(
                "cleanup: {} does not exist; nothing to clean up",
                dir.display()
            ));
            return Ok(());
        }
        Err(e) => return Err(format!("{}: cleanup: {e}", dir.display())),
    };
    let entries: Vec<std::io::Result<fs::DirEntry>> = entries.collect();
    if entries.is_empty() {
        log(&format!(
            "cleanup: {} is empty; nothing to clean up",
            dir.display()
        ));
        return Ok(());
    }
    // Managed-dir guard (audit 2026-08-02 A19): non-empty and no
    // sentinel means postmaster never wrote here — bulk deletes could
    // hit foreign files. Refuse.
    match fs::symlink_metadata(dir.join(crate::secret_files::MANAGED_SENTINEL)) {
        Ok(smd) if smd.is_file() => {}
        _ => {
            return Err(format!(
                "{}: cleanup: no {} sentinel; refusing to bulk-delete in a directory postmaster did not write to",
                dir.display(),
                crate::secret_files::MANAGED_SENTINEL
            ));
        }
    }
    let mut removed = 0_usize;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                log(&format!(
                    "{}: cleanup: skip unreadable entry: {e}",
                    dir.display()
                ));
                continue;
            }
        };
        let path = entry.path();
        // The sentinel is infrastructure, not a secret — skipped here
        // and removed last, so an interrupted cleanup can be re-run.
        if entry.file_name().to_str() == Some(crate::secret_files::MANAGED_SENTINEL) {
            continue;
        }
        match fs::symlink_metadata(&path) {
            Ok(md) if md.is_file() => {
                if let Err(e) = fs::remove_file(&path) {
                    log(&format!("{}: cleanup: {e}", path.display()));
                } else {
                    removed += 1;
                }
            }
            Ok(md) => {
                log(&format!(
                    "{}: cleanup: skipping non-file (type {:?})",
                    path.display(),
                    md.file_type()
                ));
            }
            Err(e) => {
                log(&format!("{}: cleanup: stat: {e}", path.display()));
            }
        }
    }
    // Remove the sentinel last (see above).
    let sentinel = dir.join(crate::secret_files::MANAGED_SENTINEL);
    if let Err(e) = fs::remove_file(&sentinel)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        log(&format!("{}: cleanup: {e}", sentinel.display()));
    }
    log(&format!(
        "cleanup: removed {removed} file(s) from {}",
        dir.display()
    ));
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_removes_all_files_from_secrets_dir() {
        let dir = std::env::temp_dir().join(format!("pm-keyprov-cleanup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // cleanup requires a postmaster-managed (owner-only) dir
        // (audit 2026-08-02 A19); match real deployments.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.join("KEY_A"), b"secret-a").unwrap();
        fs::write(dir.join("KEY_B"), b"secret-b").unwrap();
        fs::create_dir(dir.join("subdir")).unwrap();
        fs::write(dir.join(crate::secret_files::MANAGED_SENTINEL), b"").unwrap();

        let cfg_path = dir.join("exec.json");
        fs::write(
            &cfg_path,
            format!(
                r#"{{"mode":"files","keys":["environment"],"env_files":["/nonexistent"],"secrets_dir":"{}"}}"#,
                dir.display()
            ),
        )
        .unwrap();

        cleanup(&cfg_path).unwrap();

        assert!(!dir.join("KEY_A").exists(), "KEY_A should be removed");
        assert!(!dir.join("KEY_B").exists(), "KEY_B should be removed");
        assert!(dir.join("subdir").exists(), "subdir should be preserved");
        assert!(
            !dir.join(crate::secret_files::MANAGED_SENTINEL).exists(),
            "sentinel is removed last"
        );
    }

    #[test]
    fn cleanup_refuses_unmanaged_dir() {
        // audit 2026-08-02 A19: a non-empty dir without the sentinel was
        // never written by postmaster; cleanup must refuse to bulk-delete
        // there (foreign files could be present).
        let dir = std::env::temp_dir().join(format!("pm-keyprov-unmanaged-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("FOREIGN"), b"not-ours").unwrap();
        let cfg_path = dir.join("exec.json");
        fs::write(
            &cfg_path,
            format!(
                r#"{{"mode":"files","keys":["environment"],"env_files":["/nonexistent"],"secrets_dir":"{}"}}"#,
                dir.display()
            ),
        )
        .unwrap();

        let err = cleanup(&cfg_path).unwrap_err();

        assert!(err.contains("sentinel"), "{err}");
        assert!(dir.join("FOREIGN").exists(), "nothing may be deleted");
    }

    #[test]
    fn cleanup_nonexistent_dir_is_ok() {
        let dir = std::env::temp_dir().join(format!("pm-keyprov-missing-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("exec.json");
        fs::write(
            &cfg_path,
            format!(
                r#"{{"mode":"files","keys":["environment"],"env_files":["/nonexistent"],"secrets_dir":"{}/no-such-dir"}}"#,
                dir.display()
            ),
        )
        .unwrap();

        assert!(cleanup(&cfg_path).is_ok());
    }
}
