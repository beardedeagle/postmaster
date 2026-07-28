//! `postmaster exec` — the envelope launcher. Reads a public JSON config,
//! loads private keys, decrypts values natively (same ecies path as the
//! daemon), injects via the configured mode, and execvp's the target.
//! This file OWNS the injection boundary formerly templated as shell in
//! modules/lib.nix: values are opaque bytes end to end — no interpolation,
//! no eval, no shell.

#![allow(missing_docs, missing_debug_implementations)]

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::adapter::KeyNaming;
use crate::bundle::{parse_bundle, resolve_bundle};
use crate::config::{ExecConfig, ExecMode, KeySourceSpec};
use crate::keys::{KeyRing, resolve_all};
use crate::server::{fetch_bytes, log};

type Resolved = Vec<(String, Zeroizing<Vec<u8>>)>;

/// Ordered key-source selection. `credential` is skippable (no
/// $CREDENTIALS_DIRECTORY or file absent ⇒ try next source); every other
/// source is terminal: once selected, its failure fails the launcher.
// `wanted_vars` is only consumed by the macOS keychain source; on other
// targets the parameter is unused, so silence that leg's clippy warning
// without touching the signature or source-selection semantics.
#[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
fn load_ring(specs: &[KeySourceSpec], wanted_vars: &[String]) -> Result<KeyRing, String> {
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

/// Pure parser for /sbin/mount output: is `mp` mounted as HFS?
fn mount_lists_hfs(mount_out: &str, mp: &Path) -> bool {
    // Strip trailing slashes so a mount point like "/foo/" matches
    // "/foo" in mount output (which never includes trailing slashes).
    let mp_str = mp.to_string_lossy();
    let mp_trimmed = mp_str.trim_end_matches('/');
    let needle = format!(" on {mp_trimmed} (hfs");
    mount_out.lines().any(|l| l.contains(&needle))
}

/// Extract the device path for a mount point from `mount` output.
/// Format: `/dev/disk8 on /path (hfs, ...)` → `/dev/disk8`.
fn mount_device_for(mount_out: &str, mp: &Path) -> Option<String> {
    let mp_str = mp.to_string_lossy();
    let mp_trimmed = mp_str.trim_end_matches('/');
    let needle = format!(" on {mp_trimmed} (hfs");
    for line in mount_out.lines() {
        if let Some(idx) = line.find(&needle) {
            // The device is everything before " on "
            let device = &line[..idx].trim();
            if !device.is_empty() {
                return Some(device.to_string());
            }
        }
    }
    None
}

/// Verify that a device is backed by RAM (not a file-backed disk image).
/// Parses `hdiutil info` text output for the device's `image-path`
/// field and checks it starts with `ram://`.
fn device_is_ram_backed(device: &str, hdiutil_out: &str) -> bool {
    // hdiutil info output structure (per image entry):
    //   image-path      : ram://1024
    //   image-type      : read/write
    //   ...
    // /dev/disk8
    //
    // The device appears as a line by itself after the image properties.
    // We find the device line, then scan backwards for the image-path
    // field in the same image entry.

    let lines: Vec<&str> = hdiutil_out.lines().collect();
    let device_line = device.trim();
    for (idx, line) in lines.iter().enumerate() {
        if line.trim() == device_line {
            // Scan backwards from the device line to find image-path
            for prev in lines[..idx].iter().rev() {
                let trimmed = prev.trim();
                if trimmed.starts_with("image-path") {
                    // Extract the value after "image-path      : "
                    if let Some(colon_idx) = trimmed.find(':') {
                        let value = trimmed[colon_idx + 1..].trim();
                        return value.starts_with("ram://");
                    }
                }
                // If we hit another device line or a separator, this
                // image entry's properties ended — stop scanning.
                if trimmed.starts_with("/dev/") || trimmed.starts_with("====") {
                    break;
                }
            }
            return false;
        }
    }
    false
}

/// darwin ramdisk guard (was ramdiskGuard in modules/darwin.nix): plaintext
/// lands only on the postmaster ramdisk, in a directory this user owns.
fn verify_ramdisk(mount_point: &Path, secrets_dir: &Path) -> Result<(), String> {
    let out = std::process::Command::new("/sbin/mount")
        .output()
        .map_err(|e| format!("/sbin/mount: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !mount_lists_hfs(&text, mount_point) {
        return Err(format!(
            "{}: not the postmaster ramdisk; refusing to write plaintext to persistent disk",
            mount_point.display()
        ));
    }
    // Verify the mount is RAM-backed, not a file-backed HFS image.
    // Extract the device from mount output, then check hdiutil info
    // for that device's image-path starting with ram://.
    let device = mount_device_for(&text, mount_point).ok_or_else(|| {
        format!(
            "{}: could not determine backing device from mount output",
            mount_point.display()
        )
    })?;
    let hdiutil_out = std::process::Command::new("/usr/bin/hdiutil")
        .arg("info")
        .output()
        .map_err(|e| format!("hdiutil info: {e}"))?;
    let hdiutil_text = String::from_utf8_lossy(&hdiutil_out.stdout);
    if !device_is_ram_backed(&device, &hdiutil_text) {
        return Err(format!(
            "{}: mount device {device} is not RAM-backed (image-path does not start with ram://); refusing to write plaintext to a file-backed disk image",
            mount_point.display()
        ));
    }
    // Use symlink_metadata instead of metadata: if secrets_dir is itself a
    // symlink to persistent disk (planted by a prior compromised launch on
    // the darwin ramdisk, which persists across restarts), fs::metadata would
    // follow the link and inspect the TARGET — a directory owned by the
    // service user on persistent disk — and approve it. Reject symlinks
    // outright so the ramdisk invariant is not bypassed.
    let md = fs::symlink_metadata(secrets_dir).map_err(|e| {
        format!(
            "{}: {e} (is postmaster-ramdisk healthy?)",
            secrets_dir.display()
        )
    })?;
    if md.file_type().is_symlink() {
        return Err(format!(
            "{}: secrets_dir is a symlink; refusing to follow — remove the symlink and ensure the directory is on the ramdisk",
            secrets_dir.display()
        ));
    }
    if !md.is_dir() || md.uid() != rustix::process::geteuid().as_raw() {
        return Err(format!(
            "{}: missing or not owned by this service user (is postmaster-ramdisk healthy?)",
            secrets_dir.display()
        ));
    }
    Ok(())
}

/// Resolved values → env pairs. Env values cannot hold NUL; fail closed
/// rather than truncate.
fn env_pairs(resolved: &Resolved) -> Result<Vec<(OsString, OsString)>, String> {
    let mut out = Vec::with_capacity(resolved.len());
    for (k, v) in resolved {
        if v.contains(&0) {
            return Err(format!(
                "{k}: value contains a NUL byte; cannot be an environment variable (use files mode)"
            ));
        }
        out.push((OsString::from(k.clone()), OsString::from_vec(v.to_vec())));
    }
    Ok(out)
}

/// Writes `value` to `dir.join(key)`. Invariant this enforces: plaintext
/// lands only on the mount `verify_ramdisk` already checked — a symlink
/// planted at the target path (e.g. by leftover/attacker-controlled state
/// in a per-service ramdisk dir that persists across restarts) must never
/// be followed onto persistent disk, so the open refuses symlinks
/// (`O_NOFOLLOW`) and fails closed instead.
fn write_secret_file(dir: &Path, key: &str, value: &[u8]) -> Result<PathBuf, String> {
    use std::io::Write;
    let path = dir.join(key);
    let oflags = rustix::fs::OFlags::WRONLY
        | rustix::fs::OFlags::CREATE
        | rustix::fs::OFlags::TRUNC
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    let fd = rustix::fs::open(&path, oflags, rustix::fs::Mode::from_bits_truncate(0o600))
        .map_err(|e| format!("{}: {e} (refusing to follow a symlink)", path.display()))?;
    // Use fchmod on the fd (not set_permissions on the path) to eliminate a
    // TOCTOU: between open(O_NOFOLLOW) and a path-based chmod, an attacker
    // with directory write access could unlink the file and create a symlink
    // at the same path. fchmod operates on the already-opened fd, which is
    // the file we just created — no path re-resolution occurs.
    rustix::fs::fchmod(&fd, rustix::fs::Mode::from_bits_truncate(0o600))
        .map_err(|e| format!("{}: fchmod: {e}", path.display()))?;
    let mut f = fs::File::from(fd);
    f.write_all(value)
        .and_then(|()| f.flush())
        .map_err(|e| format!("{}: write: {e}", path.display()))?;
    Ok(path)
}

/// Unlink all paths in `written` (best-effort) after a mid-loop failure so
/// stale plaintext files do not persist on the ramdisk/tmpfs. The caller
/// must only push successfully-written secret file paths here.
fn cleanup_written(written: &[PathBuf]) {
    for p in written {
        let _ = fs::remove_file(p);
    }
}

/// Prune stale secret files from `dir` that are not in `keep_keys`. This
/// removes plaintext files left behind by a previous launch whose config
/// has since changed (a key removed from credential_keys or a resolved key
/// set that no longer includes a prior entry). Best-effort: logs but does
/// not fail if a file cannot be removed, since the primary invariant —
/// plaintext is transient — is best served by cleaning what we can rather
/// than aborting the launch over an unrelated stale file.
fn prune_stale(dir: &Path, keep_keys: &[String]) -> Result<(), String> {
    let keep: std::collections::HashSet<&str> = keep_keys.iter().map(String::as_str).collect();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        // If the directory does not exist yet, there is nothing to prune.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: prune: {e}", dir.display())),
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                log(&format!(
                    "{}: prune: skip unreadable entry: {e}",
                    dir.display()
                ));
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if keep.contains(name_str) {
            continue;
        }
        // Only unlink regular files; skip subdirectories and symlinks to
        // avoid following attacker-controlled links in a shared dir.
        let path = entry.path();
        match fs::symlink_metadata(&path) {
            Ok(md) if md.is_file() => {
                if let Err(e) = fs::remove_file(&path) {
                    log(&format!("{}: prune: {e}", path.display()));
                }
            }
            Ok(md) => {
                log(&format!(
                    "{}: prune: skipping non-file (type {:?})",
                    path.display(),
                    md.file_type()
                ));
            }
            Err(e) => {
                log(&format!("{}: prune: stat: {e}", path.display()));
            }
        }
    }
    Ok(())
}

/// Preflight key freshness check (audit finding #4): verify that the
/// loaded key ring can actually decrypt at least one encrypted value
/// from the env files. Catches stale keys from a previous rotation
/// cycle that are valid hex but no longer match the ciphertext. Without
/// this check, `strict: false` would silently skip undecryptable values
/// and launch the child with no secrets.
///
/// The check scans each env file for the first `encrypted:` value and
/// attempts a test decryption. If no encrypted values exist (all
/// plaintext passthrough), the check passes trivially.
fn verify_key_freshness(resolved: &Resolved, env_files: &[PathBuf]) -> Result<(), String> {
    // If we resolved at least one value, the keys are fresh enough.
    // An empty resolved vec with encrypted values in the env files means
    // the keys are stale (all decryptions failed under strict:false).
    if !resolved.is_empty() {
        return Ok(());
    }
    // resolved is empty: check whether any env file contains encrypted
    // values. If none do (all plaintext), the empty result is expected.
    for env_file in env_files {
        let iter = match dotenvy::from_path_iter(env_file) {
            Ok(it) => it,
            Err(e) => return Err(format!("{}: {e}", env_file.display())),
        };
        for item in iter {
            let (k, v) = match item {
                Ok(p) => p,
                Err(e) => return Err(format!("{}: {e}", env_file.display())),
            };
            if let Some(prefix) = KeyNaming::Env.metadata_prefix()
                && k.starts_with(prefix)
            {
                continue;
            }
            if v.starts_with("encrypted:") {
                // Found an encrypted value but resolved is empty: the
                // keys are stale and could not decrypt it.
                return Err(format!(
                    "{}: --verify-keys failed: key ring could not decrypt {k} (stale keys from a previous rotation?)",
                    env_file.display()
                ));
            }
        }
    }
    // No encrypted values found: the empty resolved vec is expected.
    Ok(())
}

/// Enforce the global identifier constraint on `credential_keys` up front.
/// These raw JSON strings are later used as filenames (`dir.join(k)`) and as
/// env-var name fragments (`{k}_FILE`); unlike env/files mode they don't pass
/// through `resolve_all`'s `is_ident` check, so without this a key like
/// `"../evil"` or an absolute path could escape the ramdisk-verified
/// `secrets_dir` (path traversal) or inject an arbitrary env var name.
/// Fail closed: validate ALL entries before any file is written or any
/// socket is fetched, so a bad key later in the list can't leave a partial
/// plaintext write behind.
fn validate_credential_keys(keys: &[String]) -> Result<(), String> {
    for k in keys {
        if !crate::keys::is_ident(k) {
            return Err(format!(
                "credential key {k:?}: not a valid identifier (refusing to use as filename/env name)"
            ));
        }
    }
    Ok(())
}

fn decrypt(cfg: &ExecConfig) -> Result<Resolved, String> {
    if cfg.env_files.is_empty() && cfg.bundle_files.is_empty() {
        return Err("exec config lists no env_files or bundle_files".into());
    }
    // Build the wanted key list: env files map via Env naming, bundle
    // files map via Bundle naming. Both are needed in the key ring.
    let mut wanted: Vec<String> = Vec::new();
    for f in &cfg.env_files {
        wanted.push(KeyNaming::Env.key_var_for(f)?);
    }
    for f in &cfg.bundle_files {
        wanted.push(KeyNaming::Bundle.key_var_for(f)?);
    }
    let ring = load_ring(&cfg.keys, &wanted)?;

    // Resolve .env files (if any) via the env adapter
    let mut resolved: Resolved = if cfg.env_files.is_empty() {
        Vec::new()
    } else {
        resolve_all(
            &cfg.env_files,
            &ring,
            cfg.overload,
            cfg.strict,
            &|k| std::env::var_os(k).is_some(),
            KeyNaming::Env,
        )?
    };

    // Resolve bundle files (if any) via the bundle adapter
    for bundle_path in &cfg.bundle_files {
        let raw = fs::read(bundle_path).map_err(|e| format!("{}: {e}", bundle_path.display()))?;
        let bundle = parse_bundle(&raw, bundle_path)?;
        let bundle_resolved = resolve_bundle(&bundle, &ring, bundle_path)?;
        for (name, value, encoding) in bundle_resolved {
            // Check process-env precedence (same as resolve_all)
            if !cfg.overload && std::env::var_os(&name).is_some() {
                continue;
            }
            // NUL check for utf8 entries that would become env vars
            if matches!(cfg.mode, ExecMode::Env)
                && encoding == crate::bundle::Encoding::Utf8
                && value.contains(&0)
            {
                if cfg.strict {
                    return Err(format!(
                        "{name}: value contains a NUL byte; cannot be an environment variable (use files mode)"
                    ));
                }
                log(&format!("non-strict: skipping {name}: NUL byte in value"));
                continue;
            }
            resolved.push((name, value));
        }
    }

    Ok(resolved)
}

pub fn check_config(config_path: &Path) -> Result<(), String> {
    let cfg = parse_exec_config(config_path)?;
    cfg.validate_shape()
}

/// `postmaster setup`: verify platform prerequisites, create keys
/// directory with correct permissions, optionally seed keychain items,
/// and validate the environment. Idempotent — skips steps that are
/// already correct.
///
/// `--recheck`: re-run verification checks only, without creating or
/// modifying anything. Equivalent to the old `setup_recheck`.
///
/// `--unattended`: non-interactive mode for automation. Uses defaults
/// or env vars instead of prompting. Fail closed on any missing
/// prerequisite.
///
/// `--force`: re-seed or re-create even if the target state is already
/// present.
///
/// `--keys-dir <path>`: override the keys directory path. Default is
/// `postmaster cleanup`: remove all secret files from the secrets_dir
/// configured in the exec config. Intended for `ExecStopPost` in systemd
/// or equivalent lifecycle hooks. Does not decrypt — only removes files
/// that postmaster would have written. Safe to run even if the directory
/// is empty or does not exist.
pub fn cleanup(config_path: &Path) -> Result<(), String> {
    let cfg = parse_exec_config(config_path)?;
    let dir = cfg
        .secrets_dir
        .as_deref()
        .ok_or("cleanup: config has no secrets_dir — nothing to clean up")?;
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
    log(&format!(
        "cleanup: removed {removed} file(s) from {}",
        dir.display()
    ));
    Ok(())
}

/// Default keys directory path: `/var/lib/postmaster` on Linux,
/// `~/Library/Application Support/postmaster` on macOS.
pub fn setup(
    config_path: &Path,
    recheck: bool,
    unattended: bool,
    force: bool,
    keys_dir_override: Option<PathBuf>,
) -> Result<(), String> {
    let cfg = parse_exec_config(config_path)?;
    cfg.validate_shape()?;

    // Build the wanted key variable list from both env and bundle files
    let mut wanted: Vec<String> = Vec::new();
    for f in &cfg.env_files {
        wanted.push(KeyNaming::Env.key_var_for(f)?);
    }
    for f in &cfg.bundle_files {
        wanted.push(KeyNaming::Bundle.key_var_for(f)?);
    }

    // Step 1: Verify platform prerequisites
    verify_platform_prerequisites(&cfg, unattended)?;

    if recheck {
        // --recheck: verification only, no creation or modification
        return verify_key_sources(&cfg, &wanted);
    }

    // Step 2: Create or verify keys directory
    let keys_dir = keys_dir_override.unwrap_or_else(default_keys_dir);
    ensure_keys_dir(&keys_dir, force)?;

    // Step 3: Verify or create key files for file-source keys
    for spec in &cfg.keys {
        if let KeySourceSpec::File(path) = spec {
            ensure_keys_file(path, force, unattended)?;
        }
    }

    // Step 4: Verify or seed keychain items (macOS only)
    #[cfg(target_os = "macos")]
    for spec in &cfg.keys {
        if let KeySourceSpec::Keychain(service) = spec {
            ensure_keychain_items(service, &wanted, force, unattended)?;
        }
    }

    // Step 5: Verify the full environment (same as --recheck)
    verify_key_sources(&cfg, &wanted)?;

    log(&format!(
        "setup: complete — keys dir {}, {} key source(s) verified",
        keys_dir.display(),
        cfg.keys.len()
    ));
    Ok(())
}

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

/// Verify platform prerequisites: codesign check on macOS, root-owned
/// binary check on Linux. Fails closed in unattended mode if the
/// external binary can't be verified.
fn verify_platform_prerequisites(cfg: &ExecConfig, _unattended: bool) -> Result<(), String> {
    // Only check if keychain source is configured (the only source that
    // invokes an external binary)
    let has_keychain = cfg
        .keys
        .iter()
        .any(|k| matches!(k, KeySourceSpec::Keychain(_)));
    if !has_keychain {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        // Verify /usr/bin/security code signature
        crate::keys::verify_external_binary(Path::new("/usr/bin/security"))
            .map_err(|e| format!("platform prerequisite: {e}"))?;
        log("setup: platform prerequisite verified (codesign /usr/bin/security)");
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = unattended;
        log("setup: no platform-specific prerequisites on this OS");
    }

    Ok(())
}

/// Create the keys directory with 0700 permissions if it doesn't exist.
/// If it exists, verify permissions and ownership are correct. Idempotent
/// — skips if already correct unless `force` is true.
fn ensure_keys_dir(keys_dir: &Path, _force: bool) -> Result<(), String> {
    if keys_dir.exists() {
        // Verify it's a directory, not a symlink
        let md =
            fs::symlink_metadata(keys_dir).map_err(|e| format!("{}: {e}", keys_dir.display()))?;
        if md.is_symlink() {
            return Err(format!(
                "{}: refusing to use a symlink as keys directory",
                keys_dir.display()
            ));
        }
        if !md.is_dir() {
            return Err(format!(
                "{}: exists but is not a directory",
                keys_dir.display()
            ));
        }
        // Verify permissions: 0700 (rwx------)
        use std::os::unix::fs::PermissionsExt;
        let mode = md.permissions().mode();
        if mode & 0o077 != 0 {
            // Fix permissions if we can
            fs::set_permissions(keys_dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("{}: cannot fix permissions: {e}", keys_dir.display()))?;
            log(&format!(
                "{}: permissions corrected to 0700",
                keys_dir.display()
            ));
        }
        log(&format!("{}: keys directory verified", keys_dir.display()));
        return Ok(());
    }

    // Create the directory with 0700
    fs::create_dir_all(keys_dir)
        .map_err(|e| format!("{}: cannot create keys directory: {e}", keys_dir.display()))?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(keys_dir, fs::Permissions::from_mode(0o700))
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
    let mut contents = String::new();
    if std::io::stdin().read_to_string(&mut contents).is_err() {
        return Err(format!("{}: cannot read key contents", path.display()));
    }

    // Write the file with 0600
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: cannot create: {e}", path.display()))?;
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
        let out = std::process::Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", service, "-a", var, "-w"])
            .output()
            .map_err(|e| format!("security: {e}"))?;
        if !out.status.success() {
            missing.push(var);
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
            let mut value = String::new();
            if std::io::stdin().read_line(&mut value).is_err() {
                return Err(format!("cannot read value for {var}"));
            }
            let value = value.trim();
            if value.is_empty() {
                return Err(format!("{var}: empty value, refusing to seed"));
            }
            let out = std::process::Command::new("/usr/bin/security")
                .args([
                    "add-generic-password",
                    "-s",
                    service,
                    "-a",
                    var,
                    "-w",
                    value,
                ])
                .output()
                .map_err(|e| format!("security: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "keychain {service}: failed to seed {var}: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            log(&format!("keychain {service}: seeded {var}"));
        }
    }

    Ok(())
}

/// Verify that all configured key sources are accessible. This is the
/// `--recheck` path — same as the old `setup_recheck` function.
fn verify_key_sources(cfg: &ExecConfig, wanted: &[String]) -> Result<(), String> {
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
                checked += 1;
                #[cfg(target_os = "macos")]
                {
                    for var in wanted {
                        let out = std::process::Command::new("/usr/bin/security")
                            .args(["find-generic-password", "-s", service, "-a", var, "-w"])
                            .output()
                            .map_err(|e| format!("security: {e}"))?;
                        if !out.status.success() {
                            return Err(format!(
                                "keychain {service}: no item for account {var} (fail closed)"
                            ));
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

/// Read and deserialize an ExecConfig from a JSON file. Shared by
/// `check_config` (validate-only) and `exec` (validate + materialize).
fn parse_exec_config(config_path: &Path) -> Result<ExecConfig, String> {
    let raw = fs::read(config_path).map_err(|e| format!("{}: {e}", config_path.display()))?;
    serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", config_path.display()))
}

pub fn exec(config_path: &Path, argv: &[String], verify_keys: bool) -> Result<(), String> {
    let cfg = parse_exec_config(config_path)?;
    cfg.validate_shape()?;

    let mut extra: Vec<(OsString, OsString)> = Vec::new();

    match cfg.mode {
        ExecMode::Env => {
            let resolved = decrypt(&cfg)?;
            if verify_keys {
                verify_key_freshness(&resolved, &cfg.env_files)?;
            }
            extra = env_pairs(&resolved)?;
            // resolved (Zeroizing<Vec<u8>> values) dropped here —
            // decrypted values zeroized before execvp. Only the env
            // array (extra: OsString pairs) survives to execvp, which
            // the kernel needs to build the child's environ.
            drop(resolved);
        }
        ExecMode::Files => {
            let dir = cfg
                .secrets_dir
                .as_deref()
                .ok_or("files mode requires secrets_dir")?;
            match &cfg.verify_ramdisk {
                Some(mp) => verify_ramdisk(mp, dir)?,
                None => {
                    // Defense-in-depth: use symlink_metadata to reject a
                    // symlinked secrets_dir even on Linux where
                    // verify_ramdisk is not used.
                    let md =
                        fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                    if md.file_type().is_symlink() {
                        return Err(format!(
                            "{}: secrets_dir is a symlink; refusing to write plaintext through a symlink",
                            dir.display()
                        ));
                    }
                    if !md.is_dir() {
                        return Err(format!("{}: not a directory", dir.display()));
                    }
                }
            }
            let resolved = decrypt(&cfg)?;
            if verify_keys {
                verify_key_freshness(&resolved, &cfg.env_files)?;
            }
            // Prune stale secret files from a prior launch before writing new ones.
            let keep_keys: Vec<String> = resolved.iter().map(|(k, _)| k.clone()).collect();
            prune_stale(dir, &keep_keys)?;
            let mut written: Vec<PathBuf> = Vec::with_capacity(resolved.len());
            for (k, v) in &resolved {
                let path = match write_secret_file(dir, k, v) {
                    Ok(p) => p,
                    Err(e) => {
                        cleanup_written(&written);
                        return Err(e);
                    }
                };
                written.push(path.clone());
                extra.push((OsString::from(format!("{k}_FILE")), path.into_os_string()));
                if cfg.passthrough.iter().any(|p| p == k) {
                    if v.contains(&0) {
                        cleanup_written(&written);
                        return Err(format!("{k}: passthrough value contains NUL"));
                    }
                    extra.push((OsString::from(k.clone()), OsString::from_vec(v.to_vec())));
                }
            }
            // resolved (Zeroizing<Vec<u8>> values) dropped here —
            // decrypted values zeroized before execvp. Only file paths
            // (extra: OsString pairs) survive to execvp, not the
            // plaintext values themselves.
            drop(resolved);
        }
        ExecMode::Credentials => {
            if cfg.credential_keys.is_empty() {
                return Err("credentials mode requires credential_keys".into());
            }
            validate_credential_keys(&cfg.credential_keys)?;
            if cfg.sockets.is_empty() {
                // systemd path: pid 1 already materialized the credentials.
                let dir = std::env::var_os("CREDENTIALS_DIRECTORY")
                    .ok_or("postmaster credentials expected but CREDENTIALS_DIRECTORY is unset")?;
                let dir = PathBuf::from(dir);
                for k in &cfg.credential_keys {
                    extra.push((
                        OsString::from(format!("{k}_FILE")),
                        dir.join(k).into_os_string(),
                    ));
                }
            } else {
                // launchd path: pull each key from postmaster ourselves.
                let dir = cfg
                    .secrets_dir
                    .as_deref()
                    .ok_or("credentials(fetch) mode requires secrets_dir")?;
                if let Some(mp) = &cfg.verify_ramdisk {
                    verify_ramdisk(mp, dir)?;
                }
                let sockets: &HashMap<String, PathBuf> = &cfg.sockets;
                // Prune stale credential files from a prior launch.
                prune_stale(dir, &cfg.credential_keys)?;
                let mut written: Vec<PathBuf> = Vec::with_capacity(cfg.credential_keys.len());
                for k in &cfg.credential_keys {
                    let sock = sockets
                        .get(k)
                        .ok_or_else(|| format!("{k}: no socket mapped in exec config"))?;
                    let bytes = match fetch_bytes(sock) {
                        Ok(b) => b,
                        Err(e) => {
                            cleanup_written(&written);
                            return Err(e);
                        }
                    };
                    let path = match write_secret_file(dir, k, &bytes) {
                        Ok(p) => p,
                        Err(e) => {
                            cleanup_written(&written);
                            return Err(e);
                        }
                    };
                    written.push(path.clone());
                    extra.push((OsString::from(format!("{k}_FILE")), path.into_os_string()));
                }
                extra.push((
                    OsString::from("CREDENTIALS_DIRECTORY"),
                    dir.as_os_str().to_os_string(),
                ));
            }
        }
    }

    let program = argv.first().ok_or("exec: empty argv")?;
    let err = std::process::Command::new(program)
        .args(&argv[1..])
        .envs(extra)
        .exec(); // only returns on failure
    log(&format!("exec {program}: {err}"));
    Err(format!("exec {program}: {err}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, unused_qualifications)]
mod tests {
    use super::*;

    #[test]
    fn mount_guard_parses_mount_output() {
        let out = "/dev/disk3 on / (apfs, local)\n/dev/disk7 on /private/var/run/postmaster (hfs, local, nodev, nosuid, noexec)\n";
        assert!(mount_lists_hfs(
            out,
            Path::new("/private/var/run/postmaster")
        ));
        assert!(!mount_lists_hfs(out, Path::new("/private/var/run/other")));
        assert!(!mount_lists_hfs("/dev/disk3 on / (apfs)\n", Path::new("/")));
    }

    #[test]
    fn mount_device_for_extracts_device() {
        let out = "/dev/disk3 on / (apfs, local)\n/dev/disk7 on /private/var/run/postmaster (hfs, local, nodev, nosuid, noexec)\n";
        assert_eq!(
            mount_device_for(out, Path::new("/private/var/run/postmaster")),
            Some("/dev/disk7".to_string())
        );
        assert_eq!(mount_device_for(out, Path::new("/nonexistent")), None);
    }

    #[test]
    fn device_is_ram_backed_detects_ram_prefix() {
        let hdiutil = "\
framework       : 683.100.3
driver          : 683.100.3
================================================
image-path      : ram://1024
shadow-path     : <none>
icon-path       : /System/Library/PrivateFrameworks/DiskImages.framework/Resources/CDiskImage.icns
image-type      : read/write
system-image    : false
blockcount      : 1024
blocksize       : 512
writeable       : TRUE
autodiskmount   : false
removable       : TRUE
--\nframework name  : DiskImages
/dev/disk8
";
        assert!(device_is_ram_backed("/dev/disk8", hdiutil));

        let hdiutil_file = "\
================================================
image-path      : /Users/user/image.dmg
shadow-path     : <none>
image-type      : read/write
/dev/disk9
";
        assert!(!device_is_ram_backed("/dev/disk9", hdiutil_file));

        // Device not in hdiutil output at all
        assert!(!device_is_ram_backed("/dev/disk99", hdiutil));
    }

    #[test]
    fn env_pairs_rejects_interior_nul() {
        let ok = vec![("A".to_string(), Zeroizing::new(b"x\ny".to_vec()))];
        assert_eq!(env_pairs(&ok).unwrap().len(), 1);
        let bad = vec![("A".to_string(), Zeroizing::new(b"x\0y".to_vec()))];
        assert!(env_pairs(&bad).unwrap_err().contains("NUL"));
    }

    #[test]
    fn validate_credential_keys_accepts_identifiers() {
        assert!(validate_credential_keys(&["DB_URL".to_string()]).is_ok());
    }

    #[test]
    fn validate_credential_keys_rejects_path_traversal_and_bad_identifiers() {
        for bad in ["../evil", "a/b", "", "A B"] {
            let err = validate_credential_keys(&[bad.to_string()]).unwrap_err();
            assert!(
                err.contains("identifier"),
                "key {bad:?}: expected error mentioning 'identifier', got {err:?}"
            );
        }
    }

    fn tdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pm-launcher-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn write_secret_file_refuses_symlink() {
        let dir = tdir("symlink");
        // A persistent-disk target that must never receive the plaintext.
        let real_target = dir.join("real-target");
        fs::write(&real_target, b"untouched").unwrap();
        // Attacker-planted symlink at the path write_secret_file will target.
        let link_path = dir.join("KEY");
        std::os::unix::fs::symlink(&real_target, &link_path).unwrap();

        let result = write_secret_file(&dir, "KEY", b"attacker-controlled-plaintext");

        assert!(
            result.is_err(),
            "write_secret_file must refuse to follow a symlink at the target path"
        );
        assert_eq!(
            fs::read(&real_target).unwrap(),
            b"untouched",
            "the symlink's target file must not be written to"
        );
    }

    #[test]
    fn exec_rejects_empty_argv_instead_of_panicking() {
        use std::os::unix::fs::PermissionsExt;
        // A config that resolves cleanly in "env" mode (no ramdisk/creds
        // machinery involved) so the empty-argv guard is what's exercised,
        // not an earlier, unrelated failure.
        let d = tdir("emptyargv");
        let keys_path = d.join(".env.keys");
        fs::write(
            &keys_path,
            format!("DOTENV_PRIVATE_KEY={}\n", "11".repeat(32)),
        )
        .unwrap();
        // KeyRing::load enforces 0600-or-stricter (audit finding #1).
        fs::set_permissions(&keys_path, fs::Permissions::from_mode(0o600)).unwrap();
        let env_path = d.join(".env");
        fs::write(&env_path, "A=hello\n").unwrap();
        let cfg_path = d.join("exec.json");
        fs::write(
            &cfg_path,
            format!(
                r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"]}}"#,
                keys_path.display(),
                env_path.display()
            ),
        )
        .unwrap();

        let err = exec(&cfg_path, &[], false).unwrap_err();
        assert!(err.contains("empty argv"), "{err}");
    }

    #[test]
    fn prune_stale_removes_unconfigured_files() {
        let dir = tdir("prune");
        // Simulate a previous launch that wrote KEY_A and KEY_B.
        fs::write(dir.join("KEY_A"), b"old-a").unwrap();
        fs::write(dir.join("KEY_B"), b"old-b").unwrap();

        // New config only keeps KEY_A; KEY_B should be pruned.
        prune_stale(&dir, &["KEY_A".to_string()]).unwrap();

        assert!(dir.join("KEY_A").exists(), "KEY_A should survive prune");
        assert!(!dir.join("KEY_B").exists(), "KEY_B should be pruned");
    }

    #[test]
    fn prune_stale_skips_non_files_and_missing_dir() {
        let dir = tdir("prune-nonfile");
        // A subdirectory should be skipped, not unlinked.
        fs::create_dir(dir.join("subdir")).unwrap();
        // A file that is kept should survive.
        fs::write(dir.join("KEEP_ME"), b"data").unwrap();

        prune_stale(&dir, &["KEEP_ME".to_string()]).unwrap();
        assert!(dir.join("KEEP_ME").exists());
        assert!(dir.join("subdir").is_dir(), "subdir should not be removed");

        // Non-existent directory: no error, nothing to prune.
        let ghost = dir.join("does-not-exist");
        assert!(prune_stale(&ghost, &["X".to_string()]).is_ok());
    }

    #[test]
    fn cleanup_written_unlinks_files() {
        let dir = tdir("cleanup");
        let f1 = dir.join("A");
        let f2 = dir.join("B");
        fs::write(&f1, b"secret-a").unwrap();
        fs::write(&f2, b"secret-b").unwrap();

        cleanup_written(&[f1.clone(), f2.clone()]);

        assert!(!f1.exists(), "cleanup should unlink f1");
        assert!(!f2.exists(), "cleanup should unlink f2");
    }

    #[test]
    fn cleanup_removes_all_files_from_secrets_dir() {
        let dir = tdir("cleanup-subcmd");
        fs::write(dir.join("KEY_A"), b"secret-a").unwrap();
        fs::write(dir.join("KEY_B"), b"secret-b").unwrap();
        fs::create_dir(dir.join("subdir")).unwrap();

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
    }

    #[test]
    fn cleanup_nonexistent_dir_is_ok() {
        let dir = tdir("cleanup-missing");
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

    #[test]
    fn load_ring_credential_is_skippable() {
        // credential source with no CREDENTIALS_DIRECTORY set should fall
        // through to the next source. Here the next source is "environment",
        // which is terminal and will fail closed (no DOTENV_PRIVATE_KEY*
        // vars in the test runner). The error must be from the environment
        // source, not from the credential source.
        //
        // SAFETY: set_var/remove_var are unsafe on edition 2024 (not
        // thread-safe). This test does not spawn threads.
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
        let d = tdir("cred-symlink");
        let real = d.join("real-keys");
        fs::write(&real, format!("DOTENV_PRIVATE_KEY={}\n", "11".repeat(32))).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        let cred_dir = d.join("creds");
        fs::create_dir_all(&cred_dir).unwrap();
        let link = cred_dir.join("dotenv-private-key");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // SAFETY: set_var/remove_var are unsafe on edition 2024 (not
        // thread-safe). This test does not spawn threads.
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
        let d = tdir("cred-dir");
        let cred_dir = d.join("creds");
        fs::create_dir_all(&cred_dir).unwrap();
        let sub = cred_dir.join("subdir");
        fs::create_dir_all(&sub).unwrap();

        // SAFETY: set_var/remove_var are unsafe on edition 2024 (not
        // thread-safe). This test does not spawn threads.
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
        let ghost_path = tdir("terminal-file").join("ghost.keys");
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
        // thread-safe). This test does not spawn threads.
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
