//! Key provisioning — setup and verification of key sources, key
//! directory creation, keychain seeding, and runtime key source checks.
//!
//! This module implements the `postmaster setup` and `postmaster cleanup`
//! commands, plus the key-provisioning helpers they depend on.

use std::fs;
use std::path::{Path, PathBuf};

use crate::exec_config::{ExecConfig, KeySourceSpec};
use crate::server::log;

mod cleanup;
mod input;
mod setup;

/// The `postmaster cleanup` command, re-exported at the crate root for
/// `main()` via lib.rs.
pub use cleanup::cleanup;
/// The `postmaster setup` command, re-exported at the crate root for
/// `main()` via lib.rs.
pub use setup::setup;

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

/// Create a 0700 keys directory, or check the existing directory's ownership
/// and remove group or other access. `force` affects key files and Keychain
/// items, not the directory.
#[allow(clippy::print_stderr)]
fn ensure_keys_dir(keys_dir: &Path, _force: bool) -> Result<(), String> {
    if keys_dir.exists() {
        // Open the directory itself and work on the fd throughout:
        // O_DIRECTORY|O_NOFOLLOW rejects symlinks and non-directories at open, and
        // fchmod on the fd eliminates the TOCTOU between a path-based check and a
        // path-based chmod.
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
        if stat.st_uid != rustix::process::geteuid().as_raw() {
            return Err(format!(
                "{}: keys directory is owned by another user",
                keys_dir.display()
            ));
        }
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

    // Create the directory with 0700. create_dir_all follows intermediate symlinks, so
    // first reject any existing symlink component in the prefix. Residual TOCTOU: a
    // component could be swapped between this check and the create, but an attacker
    // with that write access could plant the symlink outright — and the open below is
    // still NOFOLLOW on the final component.
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
    let stat =
        rustix::fs::fstat(&dir_fd).map_err(|e| format!("{}: stat: {e}", keys_dir.display()))?;
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(format!(
            "{}: keys directory is owned by another user",
            keys_dir.display()
        ));
    }
    rustix::fs::fchmod(&dir_fd, rustix::fs::Mode::RWXU)
        .map_err(|e| format!("{}: cannot set permissions: {e}", keys_dir.display()))?;
    log(&format!(
        "{}: keys directory created with 0700",
        keys_dir.display()
    ));
    Ok(())
}

/// Check an owned, regular key file and remove group or other access.
/// Prompt for missing contents in interactive mode; fail closed if unattended.
/// New files and forced replacements use fresh 0600 inodes.
///
/// `--force` re-prompts for the contents even when the file is already
/// correct (manual key rotation). Force requires
/// interactive mode: unattended has no operator to paste contents.
#[allow(clippy::print_stderr)]
fn ensure_keys_file(path: &Path, force: bool, unattended: bool) -> Result<(), String> {
    use crate::secret_files::{
        open_secrets_dir, replace_file, validate_directory_path, validate_projection,
    };
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, openat, statat};
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = validate_directory_path(parent)?;
    let dir_fd =
        open_secrets_dir(&parent).map_err(|e| format!("{}: parent: {e}", path.display()))?;
    validate_projection(&dir_fd, &parent)?;
    let name = path.file_name().ok_or("keys path requires a filename")?;
    let original = match openat(
        &dir_fd,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let st = fstat(&fd).map_err(|e| format!("{}: stat: {e}", path.display()))?;
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
                || st.st_uid != rustix::process::geteuid().as_raw()
                || st.st_nlink != 1
            {
                return Err(format!(
                    "{}: refusing foreign, linked or non-regular keys file",
                    path.display()
                ));
            }
            if st.st_mode & 0o077 != 0 {
                rustix::fs::fchmod(&fd, Mode::RUSR | Mode::WUSR)
                    .map_err(|e| format!("{}: chmod: {e}", path.display()))?;
                log(&format!(
                    "{}: permissions corrected to 0600",
                    path.display()
                ));
            }
            crate::secret_files::clear_file_acl(&fd)?;
            if !force {
                log(&format!("{}: keys file verified", path.display()));
                return Ok(());
            }
            Some((fd, st))
        }
        Err(rustix::io::Errno::NOENT) => None,
        Err(e) => {
            return Err(format!(
                "{}: {e} (refusing to follow a symlink)",
                path.display()
            ));
        }
    };
    if unattended {
        return Err(format!(
            "{}: {} (unattended mode cannot prompt)",
            path.display(),
            if original.is_some() {
                "--force re-prompts for key contents"
            } else {
                "keys file not found"
            }
        ));
    }
    if original.is_some() {
        eprintln!("{}: keys file exists and is valid.", path.display());
        eprintln!("--force given: replace its contents now? [y/N] ");
    } else {
        eprintln!("{}: keys file not found.", path.display());
        eprintln!(
            "Create it now? You will need to paste the key contents (DOTENV_PRIVATE_KEY=<64-hex>...). [y/N] "
        );
    }
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|_| format!("{}: cannot read input", path.display()))?;
    if !input.trim().eq_ignore_ascii_case("y") {
        if original.is_some() {
            log(&format!(
                "{}: --force declined; existing keys file kept",
                path.display()
            ));
            return Ok(());
        }
        return Err(format!(
            "{}: operator declined to create keys file",
            path.display()
        ));
    }
    let contents = input::read_secret("Paste the keys file contents (Ctrl+D to finish):", false)?;
    if let Some((_fd, original)) = original {
        let current = statat(&dir_fd, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| format!("{}: stat: {e}", path.display()))?;
        if current.st_dev != original.st_dev || current.st_ino != original.st_ino {
            return Err(format!(
                "{}: keys file changed while awaiting input",
                path.display()
            ));
        }
        replace_file(&dir_fd, name, contents.as_bytes())
            .map_err(|e| format!("{}: {e}", path.display()))?;
        log(&format!(
            "{}: keys file contents replaced (--force)",
            path.display()
        ));
    } else {
        let fd = openat(
            &dir_fd,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| {
            format!(
                "{}: cannot create: {e} (refusing to overwrite or follow a symlink)",
                path.display()
            )
        })?;
        crate::secret_files::clear_file_acl(&fd)?;
        rustix::fs::fchmod(&fd, Mode::RUSR | Mode::WUSR)
            .map_err(|e| format!("{}: chmod: {e}", path.display()))?;
        let mut file = fs::File::from(fd);
        use std::io::Write as _;
        if let Err(e) = file.write_all(contents.as_bytes()) {
            let _ = rustix::fs::unlinkat(&dir_fd, name, AtFlags::empty());
            return Err(format!("{}: cannot write: {e}", path.display()));
        }
        log(&format!("{}: keys file created with 0600", path.display()));
    }
    Ok(())
}

/// Verify keychain items exist for the wanted key variables. If they
/// don't exist and we're in interactive mode, offer to seed them.
/// `--force` re-seeds every wanted item, including existing ones. macOS only.
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
        // Existence check via the Security.framework API — no subprocess; retrieved
        // bytes zeroized on drop.
        match security_framework::passwords::get_generic_password(service, var) {
            Ok(bytes) => {
                let _ = zeroize::Zeroizing::new(bytes); // zeroize on drop
            }
            Err(_) => missing.push(var),
        }
    }

    // --force re-seeds every wanted item, present or not; without it only the missing
    // ones are offered.
    let to_seed: Vec<&str> = if force {
        wanted.iter().map(String::as_str).collect()
    } else {
        missing
    };

    if to_seed.is_empty() {
        log(&format!(
            "keychain {service}: all {wanted_len} item(s) verified",
            wanted_len = wanted.len()
        ));
        return Ok(());
    }

    if unattended {
        return Err(format!(
            "keychain {service}: {seed_len} item(s) to seed (unattended mode — cannot prompt)",
            seed_len = to_seed.len()
        ));
    }

    // Interactive: offer to seed
    eprintln!("keychain {service}: items to seed: {}", to_seed.join(", "));
    eprintln!("Seed them now? You will need to paste each key value. [y/N] ");
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return Err("cannot read input".into());
    }
    if !input.trim().eq_ignore_ascii_case("y") {
        return Err(format!(
            "keychain {service}: operator declined to seed items"
        ));
    }

    for var in &to_seed {
        let value = input::read_secret(&format!("Paste value for {var}:"), true)?;
        let value = value.trim();
        if value.is_empty() {
            return Err(format!("{var}: empty value, refusing to seed"));
        }
        // Seed via the Security.framework API, not the security CLI:
        // `add-generic-password -w <value>` exposes key material in the subprocess
        // argv, readable by any local process via ps / proc_pidinfo.
        security_framework::passwords::set_generic_password(service, var, value.as_bytes())
            .map_err(|e| format!("keychain {service}: failed to seed {var}: {e}"))?;
        log(&format!("keychain {service}: seeded {var}"));
    }

    Ok(())
}

/// Check configured key-source prerequisites without decrypting values.
/// File sources get descriptor-based access checks; credentials get presence
/// and type checks. Keychain and environment sources check required names.
fn verify_key_sources(cfg: &ExecConfig, wanted: &[String]) -> Result<(), String> {
    // `wanted` is only consulted by the macOS keychain check below.
    #[cfg(not(target_os = "macos"))]
    let _ = wanted;
    let mut checked = 0_u32;

    for spec in &cfg.keys {
        match spec {
            KeySourceSpec::Credential(name) => {
                checked += 1;
                let dir = std::env::var_os("CREDENTIALS_DIRECTORY")
                    .ok_or("$CREDENTIALS_DIRECTORY is not set")?;
                let p = Path::new(&dir).join(name);
                // Mirror load_ring's discipline: verification must not pass what
                // resolution rejects — exists() follows symlinks, but the loader
                // refuses a symlinked credential outright.
                match fs::symlink_metadata(&p) {
                    Ok(md) if md.file_type().is_symlink() => {
                        return Err(format!(
                            "{}: credential source is a symlink; refusing to follow",
                            p.display()
                        ));
                    }
                    Ok(md) if md.is_file() => {}
                    Ok(_) => {
                        return Err(format!(
                            "{}: credential source is not a regular file",
                            p.display()
                        ));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Err(format!(
                            "{}: credential source not found under $CREDENTIALS_DIRECTORY",
                            p.display()
                        ));
                    }
                    Err(e) => {
                        return Err(format!(
                            "{}: cannot stat credential source: {e}",
                            p.display()
                        ));
                    }
                }
            }
            KeySourceSpec::File(path) => {
                checked += 1;
                if path.starts_with("/nix/store") {
                    return Err(format!(
                        "{}: refusing plaintext private keys from the world-readable Nix store",
                        path.display()
                    ));
                }
                // NONBLOCK is inert on regular files and prevents a FIFO from hanging
                // verification at open; the file-type check then rejects anything that
                // isn't a regular file.
                let oflags = rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NONBLOCK;
                let fd =
                    rustix::fs::open(path, oflags, rustix::fs::Mode::empty()).map_err(|e| {
                        format!("{}: {e} (refusing to follow a symlink)", path.display())
                    })?;
                let stat = rustix::fs::fstat(&fd)
                    .map_err(|e| format!("{}: fstat: {e}", path.display()))?;
                if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() {
                    return Err(format!(
                        "{}: not a regular file (fail closed)",
                        path.display()
                    ));
                }
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
                crate::secret_files::validate_private_file_acl(&fd)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
            }
            KeySourceSpec::Keychain(service) => {
                #[cfg(target_os = "macos")]
                {
                    checked += 1;
                    for var in wanted {
                        // Security.framework API — no subprocess; retrieved bytes
                        // zeroized on drop.
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
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = service;
                    return Err("keychain source is only available on macOS".into());
                }
            }
            KeySourceSpec::Environment => {
                checked += 1;
                // Require each adapter namespace with the same exact-prefix predicate
                // as KeyRing::from_env; unrelated keys must not satisfy setup checks.
                for naming in cfg.required_namings() {
                    let prefix = naming.key_prefix();
                    // vars_os: std::env::vars() panics during iteration on non-Unicode
                    // entries — an abort under panic=abort, not a clean verification
                    // failure.
                    if !std::env::vars_os().any(|(k, _)| {
                        k.to_str()
                            .is_some_and(|k| crate::keys::is_key_var_name(prefix, k))
                    }) {
                        return Err(format!("environment: no {prefix}* variables set"));
                    }
                }
            }
        }
    }

    if checked == 0 {
        return Err("no key sources configured (configure keys=[…])".into());
    }

    // Every per-source failure above early-returns, so reaching the log means checked
    // == verified — report the count, not a fraction that is always N/N.
    log(&format!(
        "setup: {checked} key source(s) verified — environment ready"
    ));
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::adapter::KeyNaming;
    use crate::test_util::ENV_LOCK;

    fn env_only_cfg() -> ExecConfig {
        serde_json::from_str(r#"{"mode":"env","keys":["environment"],"env_files":["/x/.env"]}"#)
            .unwrap()
    }

    #[test]
    fn verify_key_sources_uses_from_env_predicate() {
        // Verification must admit exactly what KeyRing::from_env admits. A
        // prefix-substring collision like DOTENV_PRIVATE_KEYFOO is NOT a key var, so
        // with only such a var set, verification must fail.
        let _guard = ENV_LOCK.lock().unwrap();
        let cfg = env_only_cfg();
        let bogus = "DOTENV_PRIVATE_KEYFOO_PMVERIFY";
        let valid = "DOTENV_PRIVATE_KEY_PMVERIFY";

        // Positive leg: an exact `PREFIX_<suffix>` var passes. Robust
        // against any valid key vars ambient in the test runner's own
        // environment.
        // SAFETY: set_var/remove_var are unsafe on edition 2024 (not
        // thread-safe). Serialized via the process-wide ENV_LOCK
        // (crate::test_util) shared by every env-mutating test.
        unsafe {
            std::env::set_var(valid, "aa".repeat(32));
        }
        assert!(
            verify_key_sources(&cfg, &[]).is_ok(),
            "an exact PREFIX_<suffix> variable must pass verification"
        );

        // Negative leg: only a prefix-substring collision remains.
        unsafe {
            std::env::remove_var(valid);
            std::env::set_var(bogus, "aa".repeat(32));
        }
        let res = verify_key_sources(&cfg, &[]);
        unsafe {
            std::env::remove_var(bogus);
        }
        // Guard against an ambient valid key var in the test runner's
        // own environment (e.g. DOTENV_PRIVATE_KEY exported in CI): if
        // one is present, the negative leg is not observable — skip
        // rather than flake. A concurrent test cannot be the source:
        // every env-mutating test holds the shared ENV_LOCK. Only the
        // Env prefix counts here: this config requires Env naming alone.
        let any_valid = std::env::vars()
            .any(|(k, _)| crate::keys::is_key_var_name(KeyNaming::Env.key_prefix(), &k));
        if !any_valid {
            let err = res.expect_err("a prefix-substring variable must fail verification");
            assert!(err.contains("environment:"), "{err}");
        }
    }

    #[test]
    fn verify_key_sources_credential_rejects_symlink() {
        // Rechecks must reject symlinks just as runtime loading does.
        use std::os::unix::fs::PermissionsExt;
        let d = crate::test_util::temp_dir::TestDir::new("mod");
        let cred_dir = d.join("creds");
        fs::create_dir_all(&cred_dir).unwrap();
        let real = d.join("real-keys");
        fs::write(&real, format!("DOTENV_PRIVATE_KEY={}\n", "11".repeat(32))).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&real, cred_dir.join("link-keys")).unwrap();

        let cfg: ExecConfig = serde_json::from_str(
            r#"{"mode":"env","keys":[{"credential":"link-keys"}],"env_files":["/x/.env"]}"#,
        )
        .unwrap();

        // SAFETY: set_var/remove_var are unsafe on edition 2024 (not
        // thread-safe). Serialized via the process-wide ENV_LOCK
        // (crate::test_util) shared by every env-mutating test.
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("CREDENTIALS_DIRECTORY", &cred_dir);
        }
        let res = verify_key_sources(&cfg, &[]);
        unsafe {
            std::env::remove_var("CREDENTIALS_DIRECTORY");
        }
        let _ = fs::remove_dir_all(&d);
        let err = res.expect_err("a symlinked credential must fail verification");
        assert!(err.contains("symlink"), "{err}");
    }

    #[test]
    fn ensure_keys_file_force_unattended_fails_closed() {
        // --force re-prompts for contents, which unattended mode cannot do — fail
        // closed rather than silently skipping the re-create the operator asked for.
        use std::os::unix::fs::PermissionsExt;
        let d = crate::test_util::temp_dir::TestDir::new("mod");
        let keys = d.join(".env.keys");
        fs::write(&keys, format!("DOTENV_PRIVATE_KEY={}\n", "11".repeat(32))).unwrap();
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o600)).unwrap();

        let err =
            ensure_keys_file(&keys, true, true).expect_err("force + unattended must fail closed");
        assert!(err.contains("unattended"), "{err}");

        // Non-force unattended with a valid file verifies fine.
        ensure_keys_file(&keys, false, true).expect("valid file must verify without force");
        let _ = fs::remove_dir_all(&d);
    }

    fn bundle_only_cfg() -> ExecConfig {
        serde_json::from_str(
            r#"{"mode":"env","keys":["environment"],"bundle_files":["/x/s.json"]}"#,
        )
        .unwrap()
    }

    fn mixed_cfg() -> ExecConfig {
        serde_json::from_str(
            r#"{"mode":"env","keys":["environment"],"env_files":["/x/.env"],"bundle_files":["/x/s.json"]}"#,
        )
        .unwrap()
    }

    /// True when a valid key var for `prefix` exists that this test did
    /// NOT set itself (i.e. ambient in the runner's own environment).
    fn ambient_key_var(prefix: &str, mine: &[&str]) -> bool {
        std::env::vars()
            .any(|(k, _)| !mine.contains(&k.as_str()) && crate::keys::is_key_var_name(prefix, &k))
    }

    #[test]
    fn verify_key_sources_requires_each_required_naming() {
        // The compounding half of the bundle-ring gap: verification used
        // to accept EITHER prefix for the environment source, so an
        // env-files-only config passed with only POSTMASTER_KEY present
        // (then failed at exec), and a bundle-only config failed despite
        // its POSTMASTER_KEY being right there. Every required naming
        // must now be present.
        //
        // SAFETY: set_var/remove_var are unsafe on edition 2024 (not
        // thread-safe). Serialized via the process-wide ENV_LOCK
        // (crate::test_util) shared by every env-mutating test.
        let _guard = ENV_LOCK.lock().unwrap();
        let dotenv = "DOTENV_PRIVATE_KEY_PMREQUIRED";
        let bundle = "POSTMASTER_KEY_PMREQUIRED";
        let key_hex = "aa".repeat(32);
        unsafe {
            std::env::remove_var(dotenv);
            std::env::remove_var(bundle);
        }

        // bundle-only config + its POSTMASTER_KEY present → passes.
        unsafe {
            std::env::set_var(bundle, &key_hex);
        }
        assert!(
            verify_key_sources(&bundle_only_cfg(), &[]).is_ok(),
            "a bundle config's own POSTMASTER_KEY must satisfy verification"
        );

        // env-only config + only bundle material → fails (the old lie).
        let res = verify_key_sources(&env_only_cfg(), &[]);
        if !ambient_key_var(KeyNaming::Env.key_prefix(), &[dotenv, bundle]) {
            let err = res.expect_err("POSTMASTER_KEY must not satisfy an env-only config");
            assert!(err.contains("DOTENV_PRIVATE_KEY"), "{err}");
        }

        // mixed config with only ONE of the two required namings → fails.
        unsafe {
            std::env::remove_var(bundle);
            std::env::set_var(dotenv, &key_hex);
        }
        let res = verify_key_sources(&mixed_cfg(), &[]);
        if !ambient_key_var(KeyNaming::Bundle.key_prefix(), &[dotenv, bundle]) {
            let err = res.expect_err("a mixed config requires POSTMASTER_KEY too");
            assert!(err.contains("POSTMASTER_KEY"), "{err}");
        }

        // mixed config with both required namings present → passes.
        unsafe {
            std::env::set_var(bundle, &key_hex);
        }
        assert!(
            verify_key_sources(&mixed_cfg(), &[]).is_ok(),
            "both required namings present must pass"
        );

        unsafe {
            std::env::remove_var(dotenv);
            std::env::remove_var(bundle);
        }
    }

    #[test]
    fn ensure_keys_dir_creates_0700_and_corrects_wide_modes() {
        // Creation and repair must both leave the directory at 0700.
        use std::os::unix::fs::PermissionsExt;
        // Canonicalize the temp base: on macOS it sits under /var →
        // /private/var, and the directory-prefix walk would refuse
        // the symlinked /var component for reasons unrelated to this test.
        let d = crate::test_util::temp_dir::TestDir::new("mod");

        let created = d.join("new-keys");
        ensure_keys_dir(&created, false).expect("create should succeed");
        let mode = fs::metadata(&created).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "fresh keys dir must be 0700, got {mode:o}");

        let wide = d.join("wide-keys");
        fs::create_dir_all(&wide).unwrap();
        fs::set_permissions(&wide, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_keys_dir(&wide, false).expect("verify/correct should succeed");
        let mode = fs::metadata(&wide).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "a 0755 keys dir must be corrected to 0700");

        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn ensure_keys_dir_refuses_a_symlinked_prefix() {
        // create_dir_all follows intermediate symlinks, so the prefix walk must refuse
        // them before anything is created. Canonicalize the temp base (macOS /var →
        // /private/var) so the walk reaches OUR planted symlink instead of refusing the
        // OS-provided /var component first.
        let d = crate::test_util::temp_dir::TestDir::new("mod");
        let real = d.join("real");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, d.join("link")).unwrap();

        let err = ensure_keys_dir(&d.join("link").join("keys"), false)
            .expect_err("a symlinked path component must be refused");
        assert!(err.contains("symlink"), "{err}");
        assert!(
            !real.join("keys").exists(),
            "nothing may be created through the symlink"
        );

        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn ensure_keys_file_corrects_mode_and_missing_unattended_fails() {
        // A 0644 keys file is corrected to 0600; a missing file in unattended mode
        // fails closed (no prompt).
        use std::os::unix::fs::PermissionsExt;
        let d = crate::test_util::temp_dir::TestDir::new("mod");
        let keys = d.join(".env.keys");
        fs::write(&keys, format!("DOTENV_PRIVATE_KEY={}\n", "11".repeat(32))).unwrap();
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o644)).unwrap();

        ensure_keys_file(&keys, false, true).expect("verify/correct should succeed");
        let mode = fs::metadata(&keys).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a 0644 keys file must be corrected to 0600");

        let missing = d.join("absent.keys");
        let err = ensure_keys_file(&missing, false, true)
            .expect_err("missing file + unattended must fail closed");
        assert!(err.contains("unattended mode"), "{err}");

        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn keys_files_reject_linked_special_and_foreign_inodes_before_mutation() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = crate::test_util::temp_dir::TestDir::new("key-custody");
        let path = dir.join("keys");
        fs::write(&path, b"unchanged").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::hard_link(&path, dir.join("link")).unwrap();
        assert!(ensure_keys_file(&path, false, true).is_err());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        fs::remove_file(&path).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert!(ensure_keys_file(&path, false, true).is_err());
        if rustix::process::geteuid().is_root() {
            fs::remove_file(&path).unwrap();
            fs::write(&path, b"foreign").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            rustix::fs::chown(&path, Some(rustix::fs::Uid::from_raw(65534)), None).unwrap();
            assert!(ensure_keys_file(&path, false, true).is_err());
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o644
            );
            let foreign = dir.join("directory");
            fs::create_dir(&foreign).unwrap();
            fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755)).unwrap();
            rustix::fs::chown(&foreign, Some(rustix::fs::Uid::from_raw(65534)), None).unwrap();
            assert!(ensure_keys_dir(&foreign, false).is_err());
            assert_eq!(
                fs::metadata(&foreign).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
    }
}
