//! `postmaster cleanup` command path.

use std::fs;
use std::path::Path;

use crate::server::log;

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
