//! `.env.keys` file loading with on-fd stat hardening (no TOCTOU window).

use std::path::Path;

use zeroize::Zeroizing;

use super::KeyRing;
use crate::adapter::KeyNaming;

/// Implementation of [`KeyRing::load`]; the contract is documented on the
/// method.
pub(super) fn load(path: &Path, namings: &[KeyNaming]) -> Result<KeyRing, String> {
    let oflags =
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    let fd = rustix::fs::open(path, oflags, rustix::fs::Mode::empty()).map_err(|e| {
        format!(
            "keys file {}: {e} (refusing to follow a symlink)",
            path.display()
        )
    })?;
    let stat =
        rustix::fs::fstat(&fd).map_err(|e| format!("keys file {}: fstat: {e}", path.display()))?;
    let mode = rustix::fs::Mode::from_bits_truncate(stat.st_mode);
    // Reject group or world accessibility. 0o077 masks both RWXG and RWXO.
    if mode.intersects(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO) {
        return Err(format!(
            "keys file {}: permissions {:#o} are group/world accessible; expected 0400 or 0600 (fail closed)",
            path.display(),
            stat.st_mode
        ));
    }
    let euid = rustix::process::geteuid().as_raw();
    if stat.st_uid != euid {
        return Err(format!(
            "keys file {}: owned by uid {} but postmaster euid is {euid} (fail closed)",
            path.display(),
            stat.st_uid
        ));
    }
    let file = std::fs::File::from(fd);
    let iter = dotenvy::from_read_iter(file);
    let mut pairs = Vec::new();
    for item in iter {
        let (k, v) = item.map_err(|e| format!("keys file {}: {e}", path.display()))?;
        pairs.push((k, Zeroizing::new(v)));
    }
    KeyRing::from_pairs(pairs, namings).map_err(|e| format!("keys file {}: {e}", path.display()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, unused_qualifications)]
mod tests {
    use super::*;
    use crate::keys::tests::{tdir, with_temp_keys};
    use std::io::Write;

    #[test]
    fn load_rejects_bad_hex() {
        let content = "DOTENV_PRIVATE_KEY=not-hex\n";
        with_temp_keys(content, |p| match KeyRing::load(p, &[KeyNaming::Env]) {
            Err(e) if e.contains("not valid hex") => {}
            other => panic!("expected bad hex error, got {other:?}"),
        });
    }

    #[test]
    fn load_rejects_world_readable_keys_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "postmaster-test-keys-worldread-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "DOTENV_PRIVATE_KEY={}", "11".repeat(32)).unwrap();
        }
        // 0644: world-readable — must be rejected.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        match KeyRing::load(&path, &[KeyNaming::Env]) {
            Err(e) if e.contains("group/world accessible") => {}
            other => panic!("expected group/world permission error, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_group_readable_keys_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "postmaster-test-keys-groupread-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "DOTENV_PRIVATE_KEY={}", "11".repeat(32)).unwrap();
        }
        // 0640: group-readable — must be rejected.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        match KeyRing::load(&path, &[KeyNaming::Env]) {
            Err(e) if e.contains("group/world accessible") => {}
            other => panic!("expected group permission error, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_symlink_keys_file() {
        let dir = tdir("symlink-keys");
        let real = dir.join("real-keys");
        std::fs::write(&real, format!("DOTENV_PRIVATE_KEY={}\n", "11".repeat(32))).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join(".env.keys");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        match KeyRing::load(&link, &[KeyNaming::Env]) {
            Err(e) if e.contains("symlink") => {}
            other => panic!("expected symlink rejection error, got {other:?}"),
        }
    }

    #[test]
    fn load_accepts_0600_keys_file() {
        // Sanity: a properly locked-down keys file (0600, owned by euid)
        // loads normally. This guards against false positives from the
        // permission and ownership checks.
        let content = format!("DOTENV_PRIVATE_KEY={}\n", "11".repeat(32));
        with_temp_keys(&content, |p| {
            KeyRing::load(p, &[KeyNaming::Env]).expect("0600 keys file owned by euid should load");
        });
    }

    #[test]
    fn load_accepts_0400_keys_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "postmaster-test-keys-0400-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "DOTENV_PRIVATE_KEY={}", "11".repeat(32)).unwrap();
        }
        // 0400: read-only by owner — stricter than 0600, must pass.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        KeyRing::load(&path, &[KeyNaming::Env]).expect("0400 keys file owned by euid should load");
        let _ = std::fs::remove_file(&path);
    }
}
