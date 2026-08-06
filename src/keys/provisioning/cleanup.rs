//! `postmaster cleanup` command path.

use std::os::fd::AsFd;
use std::path::Path;

use crate::secret_files::{MANAGED_SENTINEL, open_secrets_dir, read_dir_names};
use crate::server::log;

/// `postmaster cleanup`: remove all secret files from the secrets_dir
/// configured in the exec config. Intended for `ExecStopPost` in systemd
/// or equivalent lifecycle hooks. Does not decrypt — only removes files
/// that postmaster would have written. Bulk removal is guarded by the
/// `.postmaster-managed` sentinel: a non-empty directory lacking it is
/// refused (postmaster only bulk-deletes directories it manages). The
/// sentinel is removed last, and ONLY when every managed regular file
/// was removed successfully — on any stat/unlink failure the sentinel
/// is RETAINED and the command fails, so a retry is not refused as
/// unmanaged while plaintext files survive. Safe to run even if the
/// directory is empty or does not exist.
pub fn cleanup(config_path: &Path) -> Result<(), String> {
    let cfg = crate::launcher::parse_exec_config(config_path)?;
    let dir = cfg
        .secrets_dir
        .as_deref()
        .ok_or("cleanup: config has no secrets_dir — nothing to clean up")?;
    // Pin the directory by fd: O_DIRECTORY|O_NOFOLLOW rejects a symlinked
    // or non-directory secrets dir at open, and the sentinel check, the
    // per-entry stat, and every unlink below are all relative to the
    // pinned inode — no path is ever re-resolved (audit 2026-08-02
    // A12/A19).
    let dir_fd = match open_secrets_dir(dir) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => {
            log(&format!(
                "cleanup: {} does not exist; nothing to clean up",
                dir.display()
            ));
            return Ok(());
        }
        Err(e @ (rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR)) => {
            return Err(format!(
                "{}: cleanup: refusing a symlinked or non-directory secrets dir ({e})",
                dir.display()
            ));
        }
        Err(e) => return Err(format!("{}: cleanup: {e}", dir.display())),
    };
    let names = read_dir_names(&dir_fd).map_err(|e| format!("{}: cleanup: {e}", dir.display()))?;
    if names.is_empty() {
        log(&format!(
            "cleanup: {} is empty; nothing to clean up",
            dir.display()
        ));
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
                "{}: cleanup: no {MANAGED_SENTINEL} sentinel; refusing to bulk-delete in a directory postmaster did not write to",
                dir.display()
            ));
        }
    }
    let mut removed = 0_usize;
    let mut had_failure = false;
    for name in &names {
        // The sentinel is infrastructure, not a secret — skipped here
        // and removed last, so an interrupted cleanup can be re-run.
        if name.to_str() == Some(MANAGED_SENTINEL) {
            continue;
        }
        let path = dir.join(name);
        match rustix::fs::statat(&dir_fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() => {
                match rustix::fs::unlinkat(&dir_fd, name, rustix::fs::AtFlags::empty()) {
                    Ok(()) => removed += 1,
                    Err(e) => {
                        had_failure = true;
                        log(&format!("{}: cleanup: {e}", path.display()));
                    }
                }
            }
            Ok(stat) => {
                // Subdirectories and symlinks are skipped, not failures.
                log(&format!(
                    "{}: cleanup: skipping non-file (type {:?})",
                    path.display(),
                    rustix::fs::FileType::from_raw_mode(stat.st_mode)
                ));
            }
            Err(e) => {
                had_failure = true;
                log(&format!("{}: cleanup: stat: {e}", path.display()));
            }
        }
    }
    finish_cleanup(&dir_fd, dir, removed, had_failure)
}

/// Sentinel disposition after the removal pass. The sentinel is removed
/// last (so an interrupted cleanup can be re-run), and ONLY when every
/// managed regular file came out: on any stat/unlink failure it is
/// retained and the command fails — removing it would make the next
/// retry refuse the directory as unmanaged and strand the surviving
/// plaintext files.
fn finish_cleanup(
    dir_fd: impl AsFd,
    dir: &Path,
    removed: usize,
    had_failure: bool,
) -> Result<(), String> {
    if had_failure {
        return Err(format!(
            "{}: cleanup: not all files could be removed; retaining the {MANAGED_SENTINEL} sentinel so a retry is not refused as unmanaged",
            dir.display()
        ));
    }
    // Remove the sentinel last (see above); best-effort — with every
    // secret gone, a surviving sentinel is harmless.
    match rustix::fs::unlinkat(dir_fd, MANAGED_SENTINEL, rustix::fs::AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(e) => log(&format!(
            "{}: cleanup: {e}",
            dir.join(MANAGED_SENTINEL).display()
        )),
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
    use std::fs;

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
        fs::write(dir.join(MANAGED_SENTINEL), b"").unwrap();

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
            !dir.join(MANAGED_SENTINEL).exists(),
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

    #[test]
    fn cleanup_retains_sentinel_after_a_failed_removal() {
        // Root bypasses directory permission checks (CAP_DAC_OVERRIDE),
        // so the induced unlink failure below only occurs for non-root.
        if rustix::process::geteuid().is_root() {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pm-keyprov-partial-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.join("KEY_A"), b"secret-a").unwrap();
        fs::write(dir.join(MANAGED_SENTINEL), b"").unwrap();
        let cfg_path = dir.join("exec.json");
        fs::write(
            &cfg_path,
            format!(
                r#"{{"mode":"files","keys":["environment"],"env_files":["/nonexistent"],"secrets_dir":"{}"}}"#,
                dir.display()
            ),
        )
        .unwrap();
        // Make every unlink inside the dir fail (EACCES): removal needs
        // write permission on the containing directory. Enumeration and
        // stat still work (r-x), so KEY_A is found and its removal fails.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();

        let err = cleanup(&cfg_path).unwrap_err();

        // Restore write permission so the temp dir can be cleaned up.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(err.contains("retaining"), "{err}");
        assert!(
            dir.join(MANAGED_SENTINEL).exists(),
            "the sentinel must be retained so a retry is not refused as unmanaged"
        );
        assert!(
            dir.join("KEY_A").exists(),
            "the file whose removal failed must still be there"
        );
    }

    #[test]
    fn finish_cleanup_removes_sentinel_only_without_failures() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pm-keyprov-finish-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.join(MANAGED_SENTINEL), b"").unwrap();
        let dir_fd = open_secrets_dir(&dir).unwrap();

        // Failure leg: the sentinel is retained and the command fails.
        let err = finish_cleanup(&dir_fd, &dir, 0, true).unwrap_err();
        assert!(err.contains("retaining"), "{err}");
        assert!(dir.join(MANAGED_SENTINEL).exists());

        // Clean leg: the sentinel goes and the command succeeds.
        finish_cleanup(&dir_fd, &dir, 1, false).unwrap();
        assert!(!dir.join(MANAGED_SENTINEL).exists());
    }
}
