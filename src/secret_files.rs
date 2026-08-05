//! Secret file operations — writing, cleanup, and pruning of plaintext
//! secret files on RAM-backed filesystems.
//!
//! All file operations use `O_NOFOLLOW` and fd-based permissions to
//! eliminate TOCTOU race conditions against symlink attacks.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// Resolved values keyed by name, each zeroized on drop.
pub type Resolved = Vec<(String, Zeroizing<Vec<u8>>)>;

/// Marker file postmaster creates in any secrets_dir it writes to
/// (audit 2026-08-02 A19). `prune_stale` and `cleanup` refuse to
/// bulk-delete in a non-empty directory that lacks it — foreign files
/// could be present. A permission-mode check cannot make that
/// distinction: the Linux files-mode secrets dir is a namespace-private
/// tmpfs systemd mounts 1777, which is dedicated yet world-accessible.
pub const MANAGED_SENTINEL: &str = ".postmaster-managed";

/// Resolved values → env pairs. Env values cannot hold NUL; fail closed
/// rather than truncate.
pub fn env_pairs(resolved: &Resolved) -> Result<Vec<(OsString, OsString)>, String> {
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
/// (`O_NOFOLLOW`) and fails closed instead. The directory itself is
/// pinned by fd (audit 2026-08-02 A12): a symlink swapped in at `dir`
/// after the caller's checks is rejected, and the file open is relative
/// to the pinned directory inode, not a path re-resolution.
pub fn write_secret_file(dir: &Path, key: &str, value: &[u8]) -> Result<PathBuf, String> {
    let dir_fd = rustix::fs::open(
        dir,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| format!("{}: {e} (refusing to follow a symlink)", dir.display()))?;
    let path = dir.join(key);
    // Drop the managed-dir sentinel (audit 2026-08-02 A19): prune_stale
    // and cleanup refuse to bulk-delete in a non-empty dir lacking it.
    let _sentinel_fd = rustix::fs::openat(
        &dir_fd,
        MANAGED_SENTINEL,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .map_err(|e| format!("{}: sentinel: {e}", path.display()))?;
    let oflags = rustix::fs::OFlags::WRONLY
        | rustix::fs::OFlags::CREATE
        | rustix::fs::OFlags::TRUNC
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    // `key` is a validated identifier (no separators), so this opens
    // exactly `dir/key` beneath the pinned directory fd.
    let fd = rustix::fs::openat(
        &dir_fd,
        key,
        oflags,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
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
pub fn cleanup_written(written: &[PathBuf]) {
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
pub fn prune_stale(dir: &Path, keep_keys: &[String]) -> Result<(), String> {
    let keep: std::collections::HashSet<&str> = keep_keys.iter().map(String::as_str).collect();
    // Symlinked or non-directory secrets dir: refuse outright.
    let md = match fs::symlink_metadata(dir) {
        Ok(md) => md,
        // If the directory does not exist yet, there is nothing to prune.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: prune: {e}", dir.display())),
    };
    if md.file_type().is_symlink() || !md.is_dir() {
        return Err(format!(
            "{}: prune: refusing a symlinked or non-directory secrets dir",
            dir.display()
        ));
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        // Raced away between the stat and here: nothing to prune.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: prune: {e}", dir.display())),
    };
    let entries: Vec<std::io::Result<fs::DirEntry>> = entries.collect();
    // An empty directory is trivially safe (first launch).
    if entries.is_empty() {
        return Ok(());
    }
    // Managed-dir guard (audit 2026-08-02 A19): non-empty and no
    // sentinel means postmaster never wrote here — bulk deletes could
    // hit foreign files. Refuse.
    match fs::symlink_metadata(dir.join(MANAGED_SENTINEL)) {
        Ok(smd) if smd.is_file() => {}
        _ => {
            return Err(format!(
                "{}: prune: no {MANAGED_SENTINEL} sentinel; refusing to bulk-delete in a directory postmaster did not write to",
                dir.display()
            ));
        }
    }
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                crate::server::log(&format!(
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
        // The sentinel is infrastructure, not a secret — never prune it.
        if name_str == MANAGED_SENTINEL || keep.contains(name_str) {
            continue;
        }
        // Only unlink regular files; skip subdirectories and symlinks to
        // avoid following attacker-controlled links in a shared dir.
        let path = entry.path();
        match fs::symlink_metadata(&path) {
            Ok(md) if md.is_file() => {
                if let Err(e) = fs::remove_file(&path) {
                    crate::server::log(&format!("{}: prune: {e}", path.display()));
                }
            }
            Ok(md) => {
                crate::server::log(&format!(
                    "{}: prune: skipping non-file (type {:?})",
                    path.display(),
                    md.file_type()
                ));
            }
            Err(e) => {
                crate::server::log(&format!("{}: prune: stat: {e}", path.display()));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn tdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pm-secretfiles-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        // prune_stale requires a postmaster-managed (owner-only) dir
        // (audit 2026-08-02 A19); match real deployments.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    #[test]
    fn env_pairs_rejects_interior_nul() {
        let ok = vec![("A".to_string(), Zeroizing::new(b"x\ny".to_vec()))];
        assert_eq!(env_pairs(&ok).unwrap().len(), 1);
        let bad = vec![("A".to_string(), Zeroizing::new(b"x\0y".to_vec()))];
        assert!(env_pairs(&bad).unwrap_err().contains("NUL"));
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
    fn prune_stale_removes_unconfigured_files() {
        let dir = tdir("prune");
        // Simulate a previous launch that wrote KEY_A and KEY_B (the
        // sentinel marks the dir as postmaster-managed — A19).
        fs::write(dir.join("KEY_A"), b"old-a").unwrap();
        fs::write(dir.join("KEY_B"), b"old-b").unwrap();
        fs::write(dir.join(MANAGED_SENTINEL), b"").unwrap();

        // New config only keeps KEY_A; KEY_B should be pruned.
        prune_stale(&dir, &["KEY_A".to_string()]).unwrap();

        assert!(dir.join("KEY_A").exists(), "KEY_A should survive prune");
        assert!(!dir.join("KEY_B").exists(), "KEY_B should be pruned");
        assert!(
            dir.join(MANAGED_SENTINEL).exists(),
            "sentinel is never pruned"
        );
    }

    #[test]
    fn prune_stale_refuses_unmanaged_dir() {
        // audit 2026-08-02 A19: a non-empty dir without the sentinel was
        // never written by postmaster; bulk deletes could hit foreign
        // files.
        let dir = tdir("prune-unmanaged");
        fs::write(dir.join("FOREIGN"), b"not-ours").unwrap();

        let err = prune_stale(&dir, &[]).unwrap_err();

        assert!(err.contains("sentinel"), "{err}");
        assert!(dir.join("FOREIGN").exists(), "nothing may be deleted");
    }

    #[test]
    fn prune_stale_empty_dir_needs_no_sentinel() {
        // First launch: the secrets dir exists but is empty — nothing to
        // prune, no sentinel required.
        let dir = tdir("prune-empty");
        prune_stale(&dir, &[]).unwrap();
    }

    #[test]
    fn prune_stale_skips_non_files_and_missing_dir() {
        let dir = tdir("prune-nonfile");
        // A subdirectory should be skipped, not unlinked.
        fs::create_dir(dir.join("subdir")).unwrap();
        // A file that is kept should survive.
        fs::write(dir.join("KEEP_ME"), b"data").unwrap();
        fs::write(dir.join(MANAGED_SENTINEL), b"").unwrap();

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
}
