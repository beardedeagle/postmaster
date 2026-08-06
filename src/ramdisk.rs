//! macOS ramdisk verification — ensures plaintext secret files land only
//! on a RAM-backed HFS disk image owned by the service user.
//!
//! This module implements the `ramdiskGuard` invariant that was previously
//! templated in `modules/darwin.nix`. On Linux the ramdisk check is not
//! used (tmpfs is already RAM-backed by definition).

use std::fs;
use std::os::unix::fs::MetadataExt;
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
pub fn verify_ramdisk(mount_point: &Path, secrets_dir: &Path) -> Result<(), String> {
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
}
