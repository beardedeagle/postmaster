//! Integrity verification of external binaries invoked on
//! secret-handling paths.

use std::path::Path;

/// Verify the integrity of an external binary before invoking it as part
/// of a secret-handling path. This is a defense-in-depth trust boundary
/// check (audit finding #3): the binary path is a trust root, and we
/// verify it has not been tampered with before exec.
///
/// On macOS: `codesign -v <path>` verifies the code signature. The binary
/// is additionally SIP-protected, so this catches a hypothetical SIP
/// bypass or a misconfigured environment.
///
/// On Linux: verify the file is a regular file, owned by root (uid 0),
/// and not world-writable. There is no universal code-signing mechanism
/// on Linux, so ownership and permission checks are the practical
/// defense-in-depth boundary.
///
/// Bootstrap limitation (audit 2026-08-02 O2): on macOS the verifier
/// itself invokes `/usr/bin/codesign`. Self-verifying codesign with
/// codesign is circular — a compromised codesign would vouch for
/// itself — so codesign is trusted via SIP alone. Moving verification
/// onto the Security.framework StaticCode API (the `security-framework`
/// crate route already chosen for keychain access) would remove this
/// residual trust gap.
pub fn verify_external_binary(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/bin/codesign")
            .args(["-v", path.to_str().unwrap_or("")])
            .output()
            .map_err(|e| format!("{}: codesign verification failed: {e}", path.display()))?;
        if !out.status.success() {
            return Err(format!(
                "{}: code signature verification failed (audit finding #3 trust boundary)",
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
        if md.mode() & 0o002 != 0 {
            return Err(format!(
                "{}: external binary is world-writable; refusing to trust",
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
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "postmaster-test-unsigned-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
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
        // On Linux, a non-root-owned binary in /tmp must be rejected.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "postmaster-test-binary-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, b"fake binary").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let result = verify_external_binary(&path);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err(), "non-root-owned binary should be rejected");
    }
}
