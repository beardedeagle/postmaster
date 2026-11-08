//! Secret file operations — writing, cleanup, and pruning of plaintext
//! secret files on RAM-backed filesystems.
//!
//! All file operations use `O_NOFOLLOW` and fd-based permissions to
//! eliminate TOCTOU race conditions against symlink attacks. The secrets
//! directory is pinned once by an open fd (`O_DIRECTORY|O_NOFOLLOW`) and
//! output creation, entry checks, and cleanup are relative to that pinned inode.
//! Exported-path validation separately checks lexical and resolved ancestry.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
mod acl;

/// Remove extended grants before writing private file contents.
pub(crate) fn clear_file_acl(fd: impl AsFd) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    acl::clear(fd)?;
    #[cfg(not(target_os = "macos"))]
    let _ = fd;
    Ok(())
}

/// Check private-file ACL grants on the opened inode without changing it.
pub(crate) fn validate_private_file_acl(fd: impl AsFd) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    acl::validate_private_file(fd)?;
    #[cfg(not(target_os = "macos"))]
    let _ = fd;
    Ok(())
}

/// Resolved values keyed by name, each zeroized on drop.
pub type Resolved = Vec<(String, Zeroizing<Vec<u8>>)>;

/// Marker file postmaster creates in any secrets_dir it writes to.
/// `prune_stale` and `cleanup` refuse to
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
/// O_NOFOLLOW|O_CLOEXEC` rejects a final-component symlink or non-directory and
/// pins the inode, so subsequent `*at` operations are relative to it
/// rather than to a re-resolved path.
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

/// Verify every lexical and resolved ancestor before exporting a pathname.
/// Root and the effective user are trusted; sticky shared parents protect their entries.
pub(crate) fn validate_directory_path(dir: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt as _;
    let absolute = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("current directory: {e}"))?
            .join(dir)
    };
    let euid = rustix::process::geteuid().as_raw();
    let check = |path: &Path, symlink: bool| -> Result<(), String> {
        let md = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if md.uid() != 0 && md.uid() != euid {
            return Err(format!(
                "{}: directory path is owned by an untrusted user",
                path.display()
            ));
        }
        if symlink && md.file_type().is_symlink() {
            return Ok(());
        }
        if !md.is_dir() || md.mode() & 0o022 != 0 && md.mode() & 0o1000 == 0 {
            return Err(format!(
                "{}: directory path permits untrusted replacement",
                path.display()
            ));
        }
        #[cfg(target_os = "macos")]
        {
            let fd = open_secrets_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
            acl::validate(&fd).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(())
    };
    let mut lexical = PathBuf::new();
    for component in absolute.components() {
        lexical.push(component);
        check(&lexical, true)?;
        // Check symlink targets too: trusting the link alone does not protect its target.
        let resolved =
            fs::canonicalize(&lexical).map_err(|e| format!("{}: {e}", lexical.display()))?;
        let mut prefix = PathBuf::new();
        for component in resolved.components() {
            prefix.push(component);
            check(&prefix, false)?;
        }
    }
    fs::canonicalize(&absolute).map_err(|e| format!("{}: {e}", absolute.display()))
}

/// Check that an exported directory still names the inode used for writes.
pub(crate) fn validate_projection(dir_fd: impl AsFd, dir: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt as _;
    let canonical = validate_directory_path(dir)?;
    let pinned = rustix::fs::fstat(dir_fd).map_err(|e| format!("{}: stat: {e}", dir.display()))?;
    let named = fs::metadata(&canonical).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(target_os = "macos")]
    let device = pinned.st_dev as u64;
    #[cfg(target_os = "linux")]
    let device = pinned.st_dev;
    if device != named.dev() || pinned.st_ino != named.ino() {
        return Err(format!(
            "{}: directory changed during validation",
            dir.display()
        ));
    }
    Ok(canonical)
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

/// Reject foreign, linked or special existing files before publication.
pub(crate) fn check_file(dir_fd: impl AsFd, name: &std::ffi::OsStr) -> Result<(), String> {
    use rustix::fs::{AtFlags, FileType, statat};
    match statat(dir_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st)
            if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile
                && st.st_uid == rustix::process::geteuid().as_raw()
                && st.st_nlink == 1 =>
        {
            Ok(())
        }
        Ok(_) => Err("refusing foreign, linked or non-regular file".into()),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(format!("stat: {e}")),
    }
}

/// Publish a fresh owner-only inode beneath a pinned directory.
/// Existing read handles retain the old contents. Failed writes remove only the new inode.
pub(crate) fn replace_file(
    dir_fd: impl AsFd,
    name: &std::ffi::OsStr,
    value: &[u8],
) -> Result<(), String> {
    use rustix::fs::{AtFlags, Mode, OFlags, openat, renameat, unlinkat};
    let dir_fd = dir_fd.as_fd();
    check_file(dir_fd, name)?;
    #[cfg(target_os = "macos")]
    acl::validate(dir_fd)?;
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|e| format!("random temporary name: {e}"))?;
    let temporary = format!(".postmaster-{}", hex::encode(random));
    let fd = openat(
        dir_fd,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| format!("create temporary file: {e}"))?;
    let result = (|| {
        rustix::fs::fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|e| format!("fchmod: {e}"))?;
        clear_file_acl(&fd)?;
        let mut file = fs::File::from(fd);
        file.write_all(value)
            .and_then(|()| file.flush())
            .map_err(|e| format!("write: {e}"))?;
        check_file(dir_fd, name)?;
        renameat(dir_fd, temporary.as_str(), dir_fd, name).map_err(|e| format!("publish: {e}"))
    })();
    if result.is_err() {
        let _ = unlinkat(dir_fd, temporary.as_str(), AtFlags::empty());
    }
    result
}

/// Write a fresh 0600 file beneath the pinned directory and return its consumer path.
/// Refuse foreign, linked and special existing entries; refresh regular owner-held files atomically.
pub fn write_secret_file(
    dir_fd: impl AsFd,
    dir: &Path,
    key: &str,
    value: &[u8],
) -> Result<PathBuf, String> {
    if !crate::keys::is_ident(key) {
        return Err("secret filename must be an identifier".into());
    }
    let dir_fd = dir_fd.as_fd();
    let path = dir.join(key);
    let sentinel = std::ffi::OsStr::new(MANAGED_SENTINEL);
    check_file(dir_fd, sentinel).map_err(|e| format!("{}: sentinel: {e}", path.display()))?;
    let sentinel_fd = rustix::fs::openat(
        dir_fd,
        sentinel,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    );
    match sentinel_fd {
        Ok(fd) => {
            clear_file_acl(&fd)?;
        }
        Err(rustix::io::Errno::EXIST) => {
            check_file(dir_fd, sentinel)
                .map_err(|e| format!("{}: sentinel: {e}", path.display()))?;
        }
        Err(e) => return Err(format!("{}: sentinel: {e}", path.display())),
    }
    replace_file(dir_fd, std::ffi::OsStr::new(key), value)
        .map_err(|e| format!("{}: {e}", path.display()))?;
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
    prune_stale_at(&dir_fd, dir, keep_keys)
}

/// Prune through the same pinned directory used for verification and writes.
pub(crate) fn prune_stale_at(
    dir_fd: impl AsFd,
    dir: &Path,
    keep_keys: &[String],
) -> Result<(), String> {
    let dir_fd = dir_fd.as_fd();
    let keep: std::collections::HashSet<&str> = keep_keys.iter().map(String::as_str).collect();
    let names = read_dir_names(dir_fd).map_err(|e| format!("{}: prune: {e}", dir.display()))?;
    // An empty directory is trivially safe (first launch).
    if names.is_empty() {
        return Ok(());
    }
    // Managed-dir guard (audit 2026-08-02 A19): non-empty and no
    // sentinel means postmaster never wrote here — bulk deletes could
    // hit foreign files. Refuse.
    match rustix::fs::statat(
        dir_fd,
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
            // Every other skip in this loop logs; a foreign file with a
            // non-UTF8 name must not persist silently (sweep 2026-08-07 X7).
            crate::server::log(&format!(
                "{}: prune: skipping non-UTF8 entry name",
                dir.display()
            ));
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
        match rustix::fs::statat(dir_fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() => {
                if let Err(e) = rustix::fs::unlinkat(dir_fd, name, rustix::fs::AtFlags::empty()) {
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

    fn tdir(tag: &str) -> crate::test_util::temp_dir::TestDir {
        let d = crate::test_util::temp_dir::TestDir::new(tag);
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
    fn refresh_does_not_write_to_old_handles_or_linked_inodes() {
        use std::io::Read as _;
        use std::os::unix::fs::MetadataExt as _;
        let dir = tdir("refresh");
        let fd = open_secrets_dir(&dir).unwrap();
        let path = write_secret_file(&fd, &dir, "KEY", b"old").unwrap();
        let old_inode = fs::metadata(&path).unwrap().ino();
        let mut old_handle = fs::File::open(&path).unwrap();
        write_secret_file(&fd, &dir, "KEY", b"new").unwrap();
        assert_ne!(old_inode, fs::metadata(&path).unwrap().ino());
        let mut old = Vec::new();
        old_handle.read_to_end(&mut old).unwrap();
        assert_eq!(old, b"old");
        assert_eq!(fs::read(&path).unwrap(), b"new");
        fs::hard_link(&path, dir.join("LINK")).unwrap();
        assert!(write_secret_file(&fd, &dir, "KEY", b"never").is_err());
        assert_eq!(fs::read(dir.join("LINK")).unwrap(), b"new");
        assert!(
            !read_dir_names(&fd)
                .unwrap()
                .iter()
                .any(|n| n.to_string_lossy().starts_with(".postmaster-") && n != MANAGED_SENTINEL)
        );
    }

    #[test]
    fn special_secret_and_sentinel_files_fail_without_opening() {
        let dir = tdir("special");
        let fd = open_secrets_dir(&dir).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(dir.join("KEY"))
                .status()
                .unwrap()
                .success()
        );
        assert!(write_secret_file(&fd, &dir, "KEY", b"never").is_err());
        fs::remove_file(dir.join(MANAGED_SENTINEL)).unwrap();
        std::os::unix::fs::symlink(dir.join("target"), dir.join(MANAGED_SENTINEL)).unwrap();
        assert!(write_secret_file(&fd, &dir, "OTHER", b"never").is_err());
        assert!(!dir.join("target").exists());
    }

    #[test]
    fn projection_checks_ancestors_and_preserves_sticky_and_trusted_aliases() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tdir("ancestry");
        let shared = dir.join("shared");
        let secret = shared.join("service");
        fs::create_dir_all(&secret).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        let fd = open_secrets_dir(&secret).unwrap();
        let error = validate_projection(&fd, &secret).unwrap_err();
        assert!(error.contains("untrusted replacement"), "{error}");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        assert_eq!(validate_projection(&fd, &secret).unwrap(), secret);
        std::os::unix::fs::symlink(&shared, dir.join("alias")).unwrap();
        assert_eq!(
            validate_projection(&fd, &dir.join("alias/service")).unwrap(),
            secret
        );
        write_secret_file(&fd, &secret, "KEY", b"secret").unwrap();
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "cat \"$KEY_FILE\""])
            .env("KEY_FILE", secret.join("KEY"))
            .output()
            .unwrap();
        assert!(child.status.success());
        assert_eq!(child.stdout, b"secret");
    }

    #[test]
    fn untrusted_user_cannot_replace_exported_sticky_paths_or_receive_refreshes() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::os::unix::process::CommandExt as _;
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let dir = tdir("projection-user");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let shared = dir.join("shared");
        let service = shared.join("service");
        fs::create_dir_all(&service).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        let fd = open_secrets_dir(&service).unwrap();
        let projected = validate_projection(&fd, &service).unwrap();
        write_secret_file(&fd, &projected, "KEY", b"protected").unwrap();
        let attempt = std::process::Command::new("/bin/mv")
            .arg(&service)
            .arg(shared.join("replaced"))
            .uid(65534)
            .gid(65534)
            .output()
            .unwrap();
        assert!(!attempt.status.success());
        let child = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                "test \"$(cat \"$KEY_FILE\")\" = protected && cat \"$CREDENTIALS_DIRECTORY/KEY\"",
            ])
            .env("KEY_FILE", projected.join("KEY"))
            .env("CREDENTIALS_DIRECTORY", &projected)
            .output()
            .unwrap();
        assert!(child.status.success());
        assert_eq!(child.stdout, b"protected");
        let foreign = service.join("FOREIGN");
        fs::write(&foreign, b"old").unwrap();
        fs::set_permissions(&foreign, fs::Permissions::from_mode(0o644)).unwrap();
        rustix::fs::chown(&foreign, Some(rustix::fs::Uid::from_raw(65534)), None).unwrap();
        assert!(write_secret_file(&fd, &service, "FOREIGN", b"never").is_err());
        assert_eq!(fs::read(&foreign).unwrap(), b"old");
        assert_eq!(
            fs::metadata(&foreign).unwrap().permissions().mode() & 0o777,
            0o644
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
