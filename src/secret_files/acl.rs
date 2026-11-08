//! Darwin extended ACL checks; POSIX mode bits alone do not describe access.

use std::ffi::{c_int, c_void};
use std::os::fd::{AsFd, AsRawFd as _};

const EXTENDED: c_int = 0x100;
const ALLOW: c_int = 1;
const FILE_INHERIT: c_int = 1 << 5;
// sys/acl.h: add file/subdirectory, delete, delete child, write attributes/security, change owner.
const MUTATE: u64 =
    (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13);

unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
    fn acl_init(count: c_int) -> *mut c_void;
    fn acl_set_fd_np(fd: c_int, acl: *mut c_void, kind: c_int) -> c_int;
    fn acl_free(value: *mut c_void) -> c_int;
    fn acl_get_entry(acl: *mut c_void, index: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
    fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> c_int;
    fn acl_get_qualifier(entry: *mut c_void) -> *mut c_void;
    fn acl_get_flagset_np(entry: *mut c_void, flags: *mut *mut c_void) -> c_int;
    fn acl_get_flag_np(flags: *mut c_void, flag: c_int) -> c_int;
    fn mbr_uid_to_uuid(uid: u32, uuid: *mut u8) -> c_int;
}

struct Allocation(*mut c_void);

impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: owned allocations returned by the ACL API are released exactly once.
        unsafe {
            acl_free(self.0);
        }
    }
}

/// Clear inherited extended grants before writing plaintext to a fresh inode.
pub(super) fn clear(fd: impl AsFd) -> Result<(), String> {
    // SAFETY: live fd and owned ACL storage; the API copies the ACL before storage is freed.
    unsafe {
        let acl = Allocation(acl_init(0));
        if acl.0.is_null() {
            return Err("cannot allocate empty ACL".into());
        }
        if acl_set_fd_np(fd.as_fd().as_raw_fd(), acl.0, EXTENDED) != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ENOTSUP) {
                return Err(format!("cannot clear file ACL: {e}"));
            }
        }
    }
    Ok(())
}

/// Reject extended grants that let another principal replace directory entries.
pub(super) fn validate(fd: impl AsFd) -> Result<(), String> {
    // SAFETY: every out pointer is initialized storage, entry pointers borrow the live ACL,
    // and qualifiers are owned UUID allocations with the platform's fixed 16-byte layout.
    unsafe {
        let acl = Allocation(acl_get_fd_np(fd.as_fd().as_raw_fd(), EXTENDED));
        if acl.0.is_null() {
            let e = std::io::Error::last_os_error();
            // Darwin reports ENOENT when a live inode has no extended ACL.
            return if matches!(e.raw_os_error(), Some(libc::ENOTSUP | libc::ENOENT)) {
                Ok(())
            } else {
                Err(format!("cannot read directory ACL: {e}"))
            };
        }
        let mut root = [0; 16];
        let mut user = [0; 16];
        if mbr_uid_to_uuid(0, root.as_mut_ptr()) != 0
            || mbr_uid_to_uuid(rustix::process::geteuid().as_raw(), user.as_mut_ptr()) != 0
        {
            return Err("cannot resolve trusted ACL principals".into());
        }
        for index in 0..=1024 {
            let mut entry = std::ptr::null_mut();
            if acl_get_entry(acl.0, index, &mut entry) != 0 {
                let e = std::io::Error::last_os_error();
                return if e.raw_os_error() == Some(libc::EINVAL) {
                    Ok(())
                } else {
                    Err(format!("cannot read ACL entry: {e}"))
                };
            }
            if index == 1024 {
                return Err("directory ACL has too many entries".into());
            }
            let mut tag = 0;
            let mut permissions = 0;
            if acl_get_tag_type(entry, &mut tag) != 0
                || acl_get_permset_mask_np(entry, &mut permissions) != 0
            {
                return Err("cannot inspect directory ACL permissions".into());
            }
            if tag != ALLOW {
                continue;
            }
            let mut flags = std::ptr::null_mut();
            if acl_get_flagset_np(entry, &mut flags) != 0 {
                return Err("cannot inspect directory ACL inheritance".into());
            }
            let inherited = acl_get_flag_np(flags, FILE_INHERIT);
            if inherited < 0 {
                return Err("cannot inspect directory ACL inheritance".into());
            }
            // An inherited grant can expose a fresh inode before its ACL is cleared.
            if permissions & MUTATE == 0 && !(inherited == 1 && permissions & (1 << 1) != 0) {
                continue;
            }
            let qualifier = Allocation(acl_get_qualifier(entry));
            if qualifier.0.is_null() {
                return Err("cannot read ACL principal".into());
            }
            let uuid = std::slice::from_raw_parts(qualifier.0.cast::<u8>(), 16);
            if uuid != root && uuid != user {
                return Err("directory ACL permits untrusted replacement".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn extended_grants_cannot_replace_paths_or_reach_new_plaintext() {
        let dir = crate::test_util::temp_dir::TestDir::new("acl");
        let fd = crate::secret_files::open_secrets_dir(&dir).unwrap();
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow add_file,delete_child"])
                .arg(&*dir)
                .status()
                .unwrap()
                .success()
        );
        assert!(validate(&fd).unwrap_err().contains("untrusted replacement"));
        assert!(
            std::process::Command::new("/bin/chmod")
                .arg("-N")
                .arg(&*dir)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow read,file_inherit"])
                .arg(&*dir)
                .status()
                .unwrap()
                .success()
        );
        assert!(validate(&fd).is_err());
        assert!(crate::secret_files::write_secret_file(&fd, &dir, "KEY", b"private").is_err());
        assert!(
            std::process::Command::new("/bin/chmod")
                .arg("-N")
                .arg(&*dir)
                .status()
                .unwrap()
                .success()
        );
        validate(&fd).unwrap();
        crate::secret_files::write_secret_file(&fd, &dir, "KEY", b"private").unwrap();
        let file = std::fs::File::open(dir.join("KEY")).unwrap();
        // SAFETY: the returned owned ACL remains live while its first entry is queried.
        unsafe {
            let acl = Allocation(acl_get_fd_np(file.as_raw_fd(), EXTENDED));
            if !acl.0.is_null() {
                let mut entry = std::ptr::null_mut();
                assert_eq!(acl_get_entry(acl.0, 0, &mut entry), -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINVAL)
                );
            }
        }
    }
}
