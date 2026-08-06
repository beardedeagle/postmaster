//! Secret file operations — writing, cleanup, and pruning of plaintext
//! secret files on RAM-backed filesystems.
//!
//! All file operations use `O_NOFOLLOW` and fd-based permissions to
//! eliminate TOCTOU race conditions against symlink attacks. The secrets
//! directory is pinned once by an open fd (`O_DIRECTORY|O_NOFOLLOW`) and
//! every create, stat, and unlink is relative to that pinned inode —
//! paths are never re-resolved.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
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

/// Open and pin a secrets directory by fd: `O_RDONLY|O_DIRECTORY|
/// O_NOFOLLOW|O_CLOEXEC` rejects a symlink or non-directory at open and
/// pins the inode, so subsequent `*at` operations are relative to it
/// rather than to a re-resolved path (audit 2026-08-02 A12).
pub(crate) fn open_secrets_dir(dir: &Path) -> rustix::io::Result<OwnedFd> {
    rustix::fs::open(
        dir,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
}

/// Enumerate entry names beneath an already-pinned directory fd,
/// excluding `.` and `..`. `Dir::read_from` re-opens `.` beneath the
/// fd, so enumeration is relative to the pinned inode and the caller's
/// fd offset is untouched. A directory removed after it was pinned
/// reads as empty.
pub(crate) fn read_dir_names(dir_fd: impl AsFd) -> rustix::io::Result<Vec<OsString>> {
    let reader = match rustix::fs::Dir::read_from(dir_fd) {
        Ok(r) => r,
        // Raced away between the open and here: nothing inside.
        Err(rustix::io::Errno::NOENT) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut names = Vec::new();
    for entry in reader {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.push(OsString::from_vec(name.to_vec()));
    }
    Ok(names)
}

/// Writes `value` to `key` beneath the pinned secrets-dir fd `dir_fd`
/// and returns `dir.join(key)` for the `{KEY}_FILE` pointer. Invariant
/// this enforces: plaintext lands only on the mount `verify_ramdisk`
/// already checked — a symlink planted at the target path (e.g. by
/// leftover/attacker-controlled state in a per-service ramdisk dir that
/// persists across restarts) must never be followed onto persistent
/// disk, so the open refuses symlinks (`O_NOFOLLOW`) and fails closed
/// instead. The directory is pinned by the caller's fd (audit
/// 2026-08-02 A12): a symlink swapped in at `dir` after the caller's
/// checks is rejected, and the file open is relative to the pinned
/// directory inode, not a path re-resolution. On any post-open error
/// the just-created/truncated target is unlinked fd-relative before the
/// error is returned — the caller only learns the names of successful
/// writes, so it could never clean up a partial file itself.
pub fn write_secret_file(
    dir_fd: impl AsFd,
    dir: &Path,
    key: &str,
    value: &[u8],
) -> Result<PathBuf, String> {
    let dir_fd = dir_fd.as_fd();
    let path = dir.join(key);
    // Drop the managed-dir sentinel (audit 2026-08-02 A19): prune_stale
    // and cleanup refuse to bulk-delete in a non-empty dir lacking it.
    let _sentinel_fd = rustix::fs::openat(
        dir_fd,
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
        dir_fd,
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
    if let Err(e) = rustix::fs::fchmod(&fd, rustix::fs::Mode::from_bits_truncate(0o600)) {
        // Post-open failure: unlink the just-created target fd-relative
        // so partial plaintext never survives a failed write.
        let _ = rustix::fs::unlinkat(dir_fd, key, rustix::fs::AtFlags::empty());
        return Err(format!("{}: fchmod: {e}", path.display()));
    }
    let mut f = fs::File::from(fd);
    if let Err(e) = f.write_all(value).and_then(|()| f.flush()) {
        // Same invariant: the truncated/partially-written target must
        // not persist as stale plaintext on the ramdisk.
        let _ = rustix::fs::unlinkat(dir_fd, key, rustix::fs::AtFlags::empty());
        return Err(format!("{}: write: {e}", path.display()));
    }
    Ok(path)
}

/// Unlink the named entries beneath the pinned secrets-dir fd
/// (best-effort) after a mid-loop failure so stale plaintext files do
/// not persist on the ramdisk/tmpfs. Unlinking by NAME relative to the
/// pinned fd (not by path) keeps the deletes on the inode the writes
/// went to even if the directory path has been swapped since. The
/// caller must only push names of successfully-written secret files
/// here; an already-vanished entry is ignored.
pub fn cleanup_written(dir_fd: impl AsFd, names: &[String]) {
    let dir_fd = dir_fd.as_fd();
    for name in names {
        let _ = rustix::fs::unlinkat(dir_fd, name, rustix::fs::AtFlags::empty());
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
    // Pin the directory by fd: O_DIRECTORY|O_NOFOLLOW rejects a symlinked
    // or non-directory secrets dir at open, and the sentinel check, the
    // per-entry stat, and every unlink below are all relative to the
    // pinned inode — no path is ever re-resolved (audit 2026-08-02 A12).
    let dir_fd = match open_secrets_dir(dir) {
        Ok(fd) => fd,
        // If the directory does not exist yet, there is nothing to prune.
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(e @ (rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR)) => {
            return Err(format!(
                "{}: prune: refusing a symlinked or non-directory secrets dir ({e})",
                dir.display()
            ));
        }
        Err(e) => return Err(format!("{}: prune: {e}", dir.display())),
    };
    let names = read_dir_names(&dir_fd).map_err(|e| format!("{}: prune: {e}", dir.display()))?;
    // An empty directory is trivially safe (first launch).
    if names.is_empty() {
        return Ok(());
    }
    // Managed-dir guard (audit 2026-08-02 A19): non-empty and no
    // sentinel means postmaster never wrote here — bulk deletes could
    // hit foreign files. Refuse.
    match rustix::fs::statat(
        &dir_fd,
        MANAGED_SENTINEL,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(stat) if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() => {}
        _ => {
            return Err(format!(
                "{}: prune: no {MANAGED_SENTINEL} sentinel; refusing to bulk-delete in a directory postmaster did not write to",
                dir.display()
            ));
        }
    }
    for name in &names {
        let Some(name_str) = name.to_str() else {
            continue;
        };
        // The sentinel is infrastructure, not a secret — never prune it.
        if name_str == MANAGED_SENTINEL || keep.contains(name_str) {
            continue;
        }
        // Only unlink regular files; skip subdirectories and symlinks to
        // avoid following attacker-controlled links in a shared dir. Both
        // the stat (SYMLINK_NOFOLLOW) and the unlink are relative to the
        // pinned dir fd, so a swapped entry cannot redirect either one.
        let path = dir.join(name);
        match rustix::fs::statat(&dir_fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() => {
                if let Err(e) = rustix::fs::unlinkat(&dir_fd, name, rustix::fs::AtFlags::empty()) {
                    crate::server::log(&format!("{}: prune: {e}", path.display()));
                }
            }
            Ok(stat) => {
                crate::server::log(&format!(
                    "{}: prune: skipping non-file (type {:?})",
                    path.display(),
                    rustix::fs::FileType::from_raw_mode(stat.st_mode)
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
    fn write_secret_file_writes_0600_via_pinned_fd() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tdir("write-ok");
        let dir_fd = open_secrets_dir(&dir).unwrap();

        let path = write_secret_file(&dir_fd, &dir, "KEY", b"plaintext").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"plaintext");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "secret file must be owner-only"
        );
        assert!(
            dir.join(MANAGED_SENTINEL).exists(),
            "the write drops the managed-dir sentinel (A19)"
        );
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

        let dir_fd = open_secrets_dir(&dir).unwrap();
        let result = write_secret_file(&dir_fd, &dir, "KEY", b"attacker-controlled-plaintext");

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
    fn prune_stale_refuses_symlinked_dir() {
        // A symlink swapped in at the secrets-dir path itself must be
        // rejected at open (O_DIRECTORY|O_NOFOLLOW), never traversed.
        let dir = tdir("prune-symlinked");
        let real = dir.join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("FOREIGN"), b"not-ours").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = prune_stale(&link, &[]).unwrap_err();

        assert!(err.contains("refusing"), "{err}");
        assert!(real.join("FOREIGN").exists(), "nothing may be deleted");
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
        // A symlink is skipped too — prune never follows links in a
        // shared dir.
        std::os::unix::fs::symlink(dir.join("KEEP_ME"), dir.join("a-link")).unwrap();
        fs::write(dir.join(MANAGED_SENTINEL), b"").unwrap();

        prune_stale(&dir, &["KEEP_ME".to_string()]).unwrap();
        assert!(dir.join("KEEP_ME").exists());
        assert!(dir.join("subdir").is_dir(), "subdir should not be removed");
        assert!(
            fs::symlink_metadata(dir.join("a-link"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlink should be skipped, not unlinked"
        );

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
        let dir_fd = open_secrets_dir(&dir).unwrap();

        // A name that does not exist is ignored (best-effort).
        cleanup_written(
            &dir_fd,
            &["A".to_string(), "B".to_string(), "MISSING".to_string()],
        );

        assert!(!f1.exists(), "cleanup should unlink f1");
        assert!(!f2.exists(), "cleanup should unlink f2");
    }
}
