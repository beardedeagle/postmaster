//! Integrity verification of external binaries invoked on
//! secret-handling paths.

use std::path::Path;

/// Check platform trust requirements before invoking an external helper.
///
/// On macOS, `codesign -v <path>` checks the code signature. Callers use
/// fixed system paths protected by SIP.
///
/// On Linux: verify the file is a regular file, owned by root (uid 0),
/// and not writable by group or others. These are ownership and permission
/// checks, not a content-signature check.
///
/// Bootstrap limitation: on macOS the verifier
/// itself invokes `/usr/bin/codesign`. Self-verifying codesign with
/// codesign is circular — a compromised codesign would vouch for
/// itself. The verifier trusts the system's SIP protection for that tool.
pub fn verify_external_binary(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/bin/codesign")
            .args(["-v", path.to_str().unwrap_or("")])
            .output()
            .map_err(|e| format!("{}: codesign verification failed: {e}", path.display()))?;
        if !out.status.success() {
            return Err(format!(
                "{}: code signature verification failed (binary trust boundary)",
                path.display()
            ));
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::symlink_metadata(path)
            .map_err(|e| format!("{}: cannot stat external binary: {e}", path.display()))?;
        if md.file_type().is_symlink() {
            return Err(format!(
                "{}: external binary is a symlink; refusing to trust a symlinked binary",
                path.display()
            ));
        }
        if !md.is_file() {
            return Err(format!(
                "{}: external binary is not a regular file",
                path.display()
            ));
        }
        if md.uid() != 0 {
            return Err(format!(
                "{}: external binary owned by uid {} (expected root/0); refusing to trust",
                path.display(),
                md.uid()
            ));
        }
        if md.mode() & 0o022 != 0 {
            return Err(format!(
                "{}: external binary is group/other writable; refusing to trust",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, unused_qualifications)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn root_owned_helpers_reject_group_and_other_write_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let dir = crate::test_util::temp_dir::TestDir::new("helper-modes");
        let path = dir.join("helper");
        std::fs::write(&path, b"root-controlled helper").unwrap();
        for mode in [0o775, 0o757, 0o777] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                verify_external_binary(&path).is_err(),
                "mode {mode:o} must fail"
            );
        }
        for mode in [0o555, 0o755] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            verify_external_binary(&path).unwrap();
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn verify_external_binary_accepts_codesigned_binary() {
        // /usr/bin/security is Apple-signed and SIP-protected; the codesign
        // verification must pass. This guards against a hypothetical SIP
        // bypass or a misconfigured environment where the binary has been
        // replaced.
        verify_external_binary(std::path::Path::new("/usr/bin/security"))
            .expect("codesigned system binary should pass verification");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn verify_external_binary_rejects_unsigned_file() {
        // A temp file with no code signature must be rejected by codesign -v.
        let dir = crate::test_util::temp_dir::TestDir::new("verify");
        let path = dir.join("fixture");
        std::fs::write(&path, b"not a signed binary").unwrap();
        let result = verify_external_binary(&path);
        let _ = std::fs::remove_file(&path);
        assert!(
            result.is_err(),
            "unsigned file should fail code signature verification"
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn verify_external_binary_rejects_non_root_owned() {
        // Root creates a root-owned fixture, which the verifier must accept.
        if rustix::process::geteuid().is_root() {
            return;
        }
        // On Linux, a non-root-owned binary in /tmp must be rejected.
        let dir = crate::test_util::temp_dir::TestDir::new("verify");
        let path = dir.join("fixture");
        std::fs::write(&path, b"fake binary").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let result = verify_external_binary(&path);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err(), "non-root-owned binary should be rejected");
    }
}
