//! macOS ramdisk verification — ensures plaintext secret files land only
//! beneath a verified RAM-backed HFS mount: the mount proves RAM-backed
//! via hdiutil, and the pinned `secrets_dir` must use that device and be
//! owned by the service user. The final component cannot be a symlink.
//!
//! The launcher uses this check when `verify_ramdisk` is configured on macOS.
//! Linux integrations provide and secure their own RAM-backed storage.

use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

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
    // /dev/disk8       /Volumes/Postmaster
    //
    // Device rows can include partition types and mount paths. Match the
    // first token, then find image-path within the same image entry.

    let lines: Vec<&str> = hdiutil_out.lines().collect();
    let device_line = device.trim();
    for (idx, line) in lines.iter().enumerate() {
        if line.split_whitespace().next() == Some(device_line) {
            // Scan backwards from the device line to find image-path
            for prev in lines[..idx].iter().rev() {
                let trimmed = prev.trim();
                if let Some((name, value)) = trimmed.split_once(':')
                    && name.trim() == "image-path"
                {
                    return value.trim().starts_with("ram://");
                }
                // Partition rows share image properties; only the image
                // separator ends the search.
                if trimmed.starts_with("====") {
                    break;
                }
            }
            return false;
        }
    }
    false
}

/// True when `dir` names a path lexically beneath `mount_point`
/// (component-wise, with no `..` escape). This lexical filter must be paired
/// with a backing-device check on the opened directory.
fn path_beneath(dir: &Path, mount_point: &Path) -> bool {
    match dir.strip_prefix(mount_point) {
        Ok(rest) => !rest
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir)),
        Err(_) => false,
    }
}

/// Verify a macOS RAM-backed mount and a contained directory owned by this user.
///
/// This verification-only API does not retain the directory handle. The
/// launcher uses `open_verified_ramdisk_dir` to keep the verified inode pinned.
pub fn verify_ramdisk(mount_point: &Path, secrets_dir: &Path) -> Result<(), String> {
    open_verified_ramdisk_dir(mount_point, secrets_dir).map(drop)
}

/// Verify the RAM backing and return the pinned directory for plaintext I/O.
pub(crate) fn open_verified_ramdisk_dir(
    mount_point: &Path,
    secrets_dir: &Path,
) -> Result<OwnedFd, String> {
    // Trust boundary (audit 2026-08-02 O2): a compromised /sbin/mount or
    // hdiutil could report persistent disk as the RAM-backed postmaster
    // ramdisk and let plaintext land on persistent storage. Verify both
    // helpers before invoking.
    crate::keys::verify_external_binary(Path::new("/sbin/mount"))?;
    crate::keys::verify_external_binary(Path::new("/usr/bin/hdiutil"))?;
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
    let device_md = fs::metadata(&device).map_err(|e| format!("{device}: {e}"))?;
    if !device_md.file_type().is_block_device() {
        return Err(format!(
            "{device}: ramdisk backing device is not a block device"
        ));
    }
    open_verified_dir(mount_point, secrets_dir, device_md.rdev())
}

/// Pin a contained, service-owned directory on the expected backing device.
fn open_verified_dir(
    mount_point: &Path,
    secrets_dir: &Path,
    device: u64,
) -> Result<OwnedFd, String> {
    if !path_beneath(secrets_dir, mount_point) {
        return Err(format!(
            "{}: secrets_dir is not beneath the verified ramdisk mount {}; refusing to write plaintext outside the ramdisk",
            secrets_dir.display(),
            mount_point.display()
        ));
    }
    let fd = crate::secret_files::open_secrets_dir(secrets_dir).map_err(|e| {
        format!(
            "{}: {e} (refusing a symlinked or non-directory secrets_dir)",
            secrets_dir.display()
        )
    })?;
    let dir = fs::File::from(fd);
    let md = dir.metadata().map_err(|e| {
        format!(
            "{}: {e} (is postmaster-ramdisk healthy?)",
            secrets_dir.display()
        )
    })?;
    if !md.is_dir() || md.uid() != rustix::process::geteuid().as_raw() {
        return Err(format!(
            "{}: missing or not owned by this service user (is postmaster-ramdisk healthy?)",
            secrets_dir.display()
        ));
    }
    // O_NOFOLLOW covers only the final component; an ancestor can redirect
    // the open. Check the pinned inode, then retain it for every plaintext I/O.
    if md.dev() != device {
        return Err(format!(
            "{}: secrets_dir is not on the verified ramdisk device; refusing to write plaintext outside the ramdisk",
            secrets_dir.display()
        ));
    }
    Ok(dir.into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::Path;

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
--
framework name  : DiskImages
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
    fn device_is_ram_backed_accepts_mounted_device_columns() {
        let output = "================================================\n\
            image-path      : ram://32768\n\
            /dev/disk5\t\t/Volumes/Postmaster Test\n";
        assert!(device_is_ram_backed("/dev/disk5", output));
        assert!(!device_is_ram_backed("/dev/disk", output));
        assert!(!device_is_ram_backed("/dev/disk50", output));
    }

    #[test]
    fn device_is_ram_backed_keeps_partition_rows_in_their_image() {
        let output = "================================================\n\
            image-path      : ram://32768\n\
            /dev/disk8\tGUID_partition_scheme\n\
            /dev/disk8s1\tApple_HFS\t/Volumes/RAM\n\
            =================================================\n\
            image-path      : /tmp/file-backed.dmg\n\
            /dev/disk9\tGUID_partition_scheme\n\
            /dev/disk9s1\tApple_HFS\t/Volumes/File Image\n\
            =================================================\n\
            image-path-other: ram://32768\n\
            /dev/disk10\t\t/Volumes/Unknown\n";
        for (device, expected) in [
            ("/dev/disk8", true),
            ("/dev/disk8s1", true),
            ("/dev/disk9", false),
            ("/dev/disk9s1", false),
            ("/dev/disk10", false),
        ] {
            assert_eq!(device_is_ram_backed(device, output), expected, "{device}");
        }
    }

    #[test]
    fn path_beneath_enforces_containment() {
        // sweep 2026-08-07 X1: the guard must relate secrets_dir to the
        // verified mount, not check each independently.
        let mp = Path::new("/private/var/run/postmaster");
        assert!(path_beneath(
            Path::new("/private/var/run/postmaster/myapp"),
            mp
        ));
        assert!(path_beneath(mp, mp), "the mount root itself is contained");
        assert!(!path_beneath(Path::new("/private/var/run/other"), mp));
        // Component-wise: a sibling whose name merely shares a prefix is
        // NOT contained.
        assert!(!path_beneath(
            Path::new("/private/var/run/postmaster-evil"),
            mp
        ));
        // `..` escape after a lexical prefix is rejected.
        assert!(!path_beneath(
            Path::new("/private/var/run/postmaster/../other"),
            mp
        ));
    }

    fn test_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pm-ramdisk-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn verified_dir_rejects_an_intermediate_link_to_another_device() {
        let root = test_dir("ancestor-link");
        let mount = root.join("mount");
        let outside = root.join("outside");
        fs::create_dir(&mount).unwrap();
        fs::create_dir_all(outside.join("service")).unwrap();
        std::os::unix::fs::symlink(&outside, mount.join("link")).unwrap();
        let candidate = mount.join("link/service");
        assert!(path_beneath(&candidate, &mount));
        assert!(fs::symlink_metadata(&candidate).unwrap().is_dir());
        // /dev is a distinct filesystem on supported Linux/macOS hosts.
        let expected_device = fs::metadata("/dev").unwrap().dev();
        assert_ne!(expected_device, fs::metadata(&candidate).unwrap().dev());

        let err = open_verified_dir(&mount, &candidate, expected_device).unwrap_err();

        assert!(err.contains("not on the verified ramdisk device"), "{err}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verified_dir_allows_internal_links_but_rejects_a_final_symlink() {
        let root = test_dir("internal-link");
        let service = root.join("nested/service");
        fs::create_dir_all(&service).unwrap();
        std::os::unix::fs::symlink(root.join("nested"), root.join("link")).unwrap();
        let device = fs::metadata(&root).unwrap().dev();
        let fd = open_verified_dir(&root, &root.join("link/service"), device).unwrap();
        assert_eq!(
            fs::File::from(fd).metadata().unwrap().ino(),
            fs::metadata(&service).unwrap().ino()
        );
        std::os::unix::fs::symlink(&service, root.join("final")).unwrap();
        let err = open_verified_dir(&root, &root.join("final"), device).unwrap_err();
        assert!(err.contains("symlinked"), "{err}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verified_handle_pins_prune_write_and_cleanup_across_path_replacement() {
        use crate::secret_files::{cleanup_written, prune_stale_at, write_secret_file};

        let root = test_dir("path-replacement");
        let service = root.join("service");
        let original = root.join("original");
        let outside = root.join("outside");
        fs::create_dir(&service).unwrap();
        fs::create_dir(&outside).unwrap();
        let device = fs::metadata(&root).unwrap().dev();
        let fd = open_verified_dir(&root, &service, device).unwrap();
        write_secret_file(&fd, &service, "OLD", b"stale").unwrap();
        fs::write(outside.join("OLD"), b"foreign-old").unwrap();
        fs::write(outside.join("SECRET"), b"foreign-secret").unwrap();
        fs::rename(&service, &original).unwrap();
        std::os::unix::fs::symlink(&outside, &service).unwrap();

        prune_stale_at(&fd, &service, &[]).unwrap();
        assert!(!original.join("OLD").exists());
        assert_eq!(fs::read(outside.join("OLD")).unwrap(), b"foreign-old");
        write_secret_file(&fd, &service, "SECRET", b"test-secret").unwrap();
        assert_eq!(fs::read(original.join("SECRET")).unwrap(), b"test-secret");
        cleanup_written(&fd, &["SECRET".into()]);
        assert!(!original.join("SECRET").exists());
        assert_eq!(fs::read(outside.join("SECRET")).unwrap(), b"foreign-secret");
        fs::remove_dir_all(root).unwrap();
    }
}
