//! `postmaster exec` — the envelope launcher. Reads a public JSON config,
//! loads private keys, decrypts values natively (same ecies path as the
//! daemon), injects via the configured mode, and execvp's the target.
//! This file OWNS the injection boundary formerly templated as shell in
//! modules/lib.nix: values are opaque bytes end to end — no interpolation,
//! no eval, no shell.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use crate::adapter::KeyNaming;
use crate::bundle::{parse_bundle, resolve_bundle};
use crate::exec_config::{ExecConfig, ExecMode};
use crate::key_source::load_ring;
use crate::keys::resolve_all;
use crate::monitor::{self, STOP_SIGNALS};
use crate::ramdisk::verify_ramdisk;
use crate::secret_files::{
    Resolved, cleanup_written, env_pairs, open_secrets_dir, prune_stale, write_secret_file,
};
use crate::server::{fetch_bytes, log, read_capped};

/// Guard deferring termination signals across the window where plaintext
/// secret files exist on the ramdisk/tmpfs (audit 2026-08-02 A11). A
/// signal landing mid-write would otherwise strand partial plaintext, so
/// the four termination signals (`STOP_SIGNALS`) are *blocked* across the
/// window. The sibling monitor is then forked — it inherits the blocked
/// mask and keeps it for life (see monitor.rs) — and the parent restores
/// the saved mask before execvp so the service starts with a clean
/// signal state.
///
/// The sigaction flag-handler and second pre-exec gate this guard used
/// to implement were retired with the sibling-monitor design
/// (2026-08-05): the monitor owns stop semantics, so no async handler is
/// needed anywhere. What remains is the deterministic write window
/// (`block`) and the pre-exec mask restore (`restore_mask`) — now real
/// on Linux too, because the fork+monitor model runs there as well.
#[cfg(target_os = "macos")]
pub(crate) struct TerminationGuard {
    old: libc::sigset_t,
}

#[cfg(target_os = "macos")]
impl TerminationGuard {
    pub(crate) fn block() -> Self {
        unsafe {
            // SAFETY: zeroed sigset_t is a valid empty set representation;
            // all pointers are valid and outlive the calls.
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for sig in STOP_SIGNALS {
                libc::sigaddset(&mut set, sig.as_raw());
            }
            let mut old: libc::sigset_t = std::mem::zeroed();
            // pthread form: correct in single- and multi-threaded processes.
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
            Self { old }
        }
    }

    /// Restore the saved signal mask. The parent calls this before
    /// execvp — the child must not inherit blocked termination signals.
    pub(crate) fn restore_mask(&self) {
        unsafe {
            // SAFETY: restoring a previously saved valid mask.
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut());
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for TerminationGuard {
    fn drop(&mut self) {
        self.restore_mask();
    }
}

/// Linux leg of the guard (see the macOS docs above): same block/restore
/// contract via rustix's raw `rt_sigprocmask` — no libc FFI.
#[cfg(target_os = "linux")]
pub(crate) struct TerminationGuard {
    /// `None` only if the block call failed (logged); restore then no-ops
    /// rather than clobbering a mask that was never captured.
    old: Option<rustix::runtime::KernelSigSet>,
}

#[cfg(target_os = "linux")]
impl TerminationGuard {
    pub(crate) fn block() -> Self {
        let mut set = rustix::runtime::KernelSigSet::empty();
        for sig in STOP_SIGNALS {
            set.insert(sig);
        }
        // SAFETY: the set holds only the four standard termination
        // signals — none reserved by any libc in the process (glibc
        // reserves 32/33, untouched). The launcher is single-threaded at
        // this point (the exec path spawns no threads; worker threads
        // exist only in serve mode).
        match unsafe {
            rustix::runtime::kernel_sigprocmask(rustix::runtime::How::BLOCK, Some(&set))
        } {
            Ok(old) => Self { old: Some(old) },
            Err(e) => {
                // rt_sigprocmask cannot realistically fail here (EINVAL/
                // EFAULT cover bad arguments, both impossible) — but if it
                // ever does, log it and run unguarded rather than silently
                // pretend the window is protected.
                log(&format!("termination-guard: sigprocmask failed: {e}"));
                Self { old: None }
            }
        }
    }

    /// Restore the saved signal mask (see the macOS docs).
    pub(crate) fn restore_mask(&self) {
        if let Some(old) = &self.old {
            // SAFETY: restoring a mask previously returned by the kernel
            // for this thread.
            let _ = unsafe {
                rustix::runtime::kernel_sigprocmask(rustix::runtime::How::SETMASK, Some(old))
            };
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for TerminationGuard {
    fn drop(&mut self) {
        self.restore_mask();
    }
}

/// Read and deserialize an ExecConfig from a JSON file. Shared by
/// `check_config` (validate-only) and `exec` (validate + materialize).
pub fn parse_exec_config(config_path: &Path) -> Result<ExecConfig, String> {
    let file =
        fs::File::open(config_path).map_err(|e| format!("{}: {e}", config_path.display()))?;
    let raw = read_capped(file, config_path)?;
    serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", config_path.display()))
}

/// Validate the public shape of an exec config without decrypting,
/// reading key material, or touching the host filesystem. This is
/// the `--check` contract for CI and automation tools.
pub fn check_config(config_path: &Path) -> Result<(), String> {
    let cfg = parse_exec_config(config_path)?;
    cfg.validate_shape()
}

/// Preflight key freshness check: fail if any encrypted env value was
/// skipped during resolution because the key ring could not decrypt it
/// (audit 2026-08-02 A3). Under `strict: false` a partial key rotation
/// would otherwise pass silently here — the old check only caught total
/// failure (empty resolved set) — and the child would launch with a
/// partial secret set. The failure list recorded by `resolve_all` makes
/// every skip visible to `--verify-keys`.
///
/// Bundle files need no scan here: `resolve_bundle` is all-or-nothing —
/// the first undecryptable entry aborts `decrypt()` regardless of
/// `strict`, so stale bundle keys already fail closed before this check
/// runs (audit 2026-08-02 A4).
fn verify_key_freshness(failed: &[(String, String)]) -> Result<(), String> {
    if let Some((k, _)) = failed.first() {
        return Err(format!(
            "--verify-keys failed: key ring could not decrypt {k} (stale keys from a previous rotation?)"
        ));
    }
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

/// Decrypt all configured inputs. Returns the resolved (name, plaintext)
/// pairs plus the `(name, error)` list of encrypted env values skipped
/// under `strict: false` (consumed by `verify_key_freshness`).
fn decrypt(cfg: &ExecConfig) -> Result<(Resolved, Vec<(String, String)>), String> {
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
    let ring = load_ring(&cfg.keys, &wanted, &cfg.required_namings())?;

    // Resolve .env files (if any) via the env adapter. Values skipped
    // under strict:false are recorded in `failed` so --verify-keys can
    // fail closed on a partial key rotation (audit 2026-08-02 A3).
    let (mut resolved, failed): (Resolved, Vec<(String, String)>) = if cfg.env_files.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let r = resolve_all(
            &cfg.env_files,
            &ring,
            cfg.overload,
            cfg.strict,
            &|k| std::env::var_os(k).is_some(),
            KeyNaming::Env,
        )?;
        (r.resolved, r.failed)
    };

    // Resolve bundle files (if any) via the bundle adapter
    for bundle_path in &cfg.bundle_files {
        // O_NOFOLLOW on the ciphertext open (audit 2026-08-02 A13):
        // refuse to read through a planted symlink.
        let bundle_fd = rustix::fs::open(
            bundle_path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| {
            format!(
                "{}: {e} (refusing to follow a symlink)",
                bundle_path.display()
            )
        })?;
        let raw = read_capped(fs::File::from(bundle_fd), bundle_path)?;
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

    Ok((resolved, failed))
}

/// Decrypt configured secret inputs, inject them into the child
/// context, and `execvp` the target binary. The process image is
/// replaced — this function never returns on success.
pub fn exec(config_path: &Path, argv: &[String], verify_keys: bool) -> Result<(), String> {
    let cfg = parse_exec_config(config_path)?;
    cfg.validate_shape()?;

    let program = argv.first().ok_or("exec: empty argv")?;
    // Defer termination signals until the fork/exec below, so a signal
    // landing mid-write can't strand plaintext on disk (audit 2026-08-02
    // A11 — see TerminationGuard docs). The fork-child monitor inherits
    // the blocked mask and keeps it for life; the parent restores the
    // saved mask before execvp.
    let sig_guard = TerminationGuard::block();
    let mut extra: Vec<(OsString, OsString)> = Vec::new();
    // Names of plaintext files written beneath the pinned secrets-dir
    // fd, tracked across the match so the failure paths (and the monitor,
    // post-fork) can unlink them fd-relative (audit 2026-08-02 A9).
    let mut written: Vec<String> = Vec::new();
    // The pinned secrets-dir fd (Files / Credentials-fetch modes only).
    // Opened ONCE with O_DIRECTORY|O_NOFOLLOW|O_RDONLY|CLOEXEC and kept
    // until after the exec-failure cleanup, so every write and every
    // cleanup unlink is relative to the same pinned inode (audit
    // 2026-08-02 A12). Across the fork the monitor inherits the fd
    // (CLOEXEC fires only on exec, which the monitor never performs) and
    // holds it for the service's lifetime.
    let mut secrets_dir_fd: Option<std::os::fd::OwnedFd> = None;

    match cfg.mode {
        ExecMode::Env => {
            let (resolved, failed) = decrypt(&cfg)?;
            if verify_keys {
                verify_key_freshness(&failed)?;
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
            let (resolved, failed) = decrypt(&cfg)?;
            if verify_keys {
                verify_key_freshness(&failed)?;
            }
            // Prune stale secret files from a prior launch before writing new ones.
            let keep_keys: Vec<String> = resolved.iter().map(|(k, _)| k.clone()).collect();
            prune_stale(dir, &keep_keys)?;
            // Pin the secrets dir for the whole write window: the writes,
            // the mid-loop cleanups, and the post-match cleanups all act
            // relative to this one pinned fd.
            let dir_fd = open_secrets_dir(dir)
                .map_err(|e| format!("{}: {e} (refusing to follow a symlink)", dir.display()))?;
            written.reserve(resolved.len());
            for (k, v) in &resolved {
                let path = match write_secret_file(&dir_fd, dir, k, v) {
                    Ok(p) => p,
                    Err(e) => {
                        cleanup_written(&dir_fd, &written);
                        return Err(e);
                    }
                };
                written.push(k.clone());
                extra.push((OsString::from(format!("{k}_FILE")), path.into_os_string()));
                if cfg.passthrough.iter().any(|p| p == k) {
                    if v.contains(&0) {
                        cleanup_written(&dir_fd, &written);
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
            secrets_dir_fd = Some(dir_fd);
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
                // Pin the secrets dir for the whole fetch/write window
                // (same single-fd discipline as files mode).
                let dir_fd = open_secrets_dir(dir).map_err(|e| {
                    format!("{}: {e} (refusing to follow a symlink)", dir.display())
                })?;
                written.reserve(cfg.credential_keys.len());
                for k in &cfg.credential_keys {
                    let sock = sockets
                        .get(k)
                        .ok_or_else(|| format!("{k}: no socket mapped in exec config"))?;
                    let bytes = match fetch_bytes(sock) {
                        Ok(b) => b,
                        Err(e) => {
                            cleanup_written(&dir_fd, &written);
                            return Err(e);
                        }
                    };
                    let path = match write_secret_file(&dir_fd, dir, k, &bytes) {
                        Ok(p) => p,
                        Err(e) => {
                            cleanup_written(&dir_fd, &written);
                            return Err(e);
                        }
                    };
                    written.push(k.clone());
                    extra.push((OsString::from(format!("{k}_FILE")), path.into_os_string()));
                }
                extra.push((
                    OsString::from("CREDENTIALS_DIRECTORY"),
                    dir.as_os_str().to_os_string(),
                ));
                secrets_dir_fd = Some(dir_fd);
            }
        }
    }

    // Zeroization is complete at this point (the key ring dropped inside
    // decrypt(); `resolved` dropped at the end of each arm above): fork
    // the sibling monitor BEFORE exec. The fork-child keeps the guard's
    // blocked mask for life and supervises this process — stop-signal
    // forwarding, bounded grace, SIGKILL escalation, and plaintext cleanup
    // on every death path (sibling-monitor design 2026-08-05; see
    // monitor.rs). The parent execs the service exactly as before, so
    // MainPID is unchanged. The monitor runs for ALL exec launches,
    // including env mode (uniform semantics; its cleanup is a no-op
    // there). The pid is captured pre-fork: post-fork the parent IS the
    // service-to-be, so the monitor needs no racy getppid.
    let service_pid = rustix::process::getpid();
    // SAFETY: fork(2) in a single-threaded process (the exec path spawns
    // no threads; the daemon's worker threads exist only in serve mode).
    // The fork-child executes only monitor::run — the async-signal-safe
    // syscall set documented in monitor.rs: no allocation, no stdio
    // locks, no destructors — and exits via _exit/exit_group. rustix
    // deliberately has no fork wrapper; on Linux this is the one libc FFI
    // call on the exec path, flagged in docs/src/unsafe-code/monitor.md.
    match unsafe { libc::fork() } {
        -1 => {
            // No monitor means no stop semantics and no cleanup on
            // abnormal death: fail closed like an exec failure rather
            // than launch unsupervised.
            if let Some(dir_fd) = &secrets_dir_fd {
                cleanup_written(dir_fd, &written);
            }
            let err = std::io::Error::last_os_error();
            log(&format!("exec {program}: fork: {err}"));
            return Err(format!("exec {program}: fork: {err}"));
        }
        0 => {
            // Fork-child = the monitor (never returns). sig_guard is
            // deliberately NOT dropped here: monitor::run diverges
            // (`-> !`) and the _exit path runs no destructors, so the
            // termination mask stays blocked for the monitor's life
            // (run() re-asserts the block regardless). The inherited
            // `extra` env pairs are SCRUBBED first — they hold plaintext
            // values in env mode (and files-mode passthrough), and
            // free() alone would leave the bytes in the monitor's
            // mapped pages for its whole life (threat model: monitor
            // inherited heap).
            for (k, v) in extra {
                drop(monitor::wipe_pair(k, v));
            }
            monitor::run(service_pid, secrets_dir_fd, written);
        }
        _ => {}
    }
    // Parent only from here (the fork-child diverged). Restore the
    // pre-guard signal mask so the service starts with a clean signal
    // state, then exec exactly as before.
    sig_guard.restore_mask();
    let mut cmd = std::process::Command::new(program);
    cmd.args(&argv[1..]).envs(extra);
    let err = cmd.exec(); // only returns on failure
    // execvp failed: the process image was NOT replaced, so any
    // plaintext secret files written above would otherwise persist
    // (the macOS ramdisk survives process death). Remove them before
    // returning the error (audit 2026-08-02 A9). The monitor watching
    // this process fires on the imminent exit and cleans again —
    // unlinkat of already-removed names is a no-op.
    if let Some(dir_fd) = &secrets_dir_fd {
        cleanup_written(dir_fd, &written);
    }
    log(&format!("exec {program}: {err}"));
    Err(format!("exec {program}: {err}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, unused_qualifications)]
mod tests {
    use super::*;

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

    #[test]
    fn exec_rejects_empty_argv_instead_of_panicking() {
        use std::os::unix::fs::PermissionsExt;
        // A config that resolves cleanly in "env" mode (no ramdisk/creds
        // machinery involved) so the empty-argv guard is what's exercised,
        // not an earlier, unrelated failure.
        let d = std::env::temp_dir().join(format!("pm-launcher-emptyargv-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
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
}
