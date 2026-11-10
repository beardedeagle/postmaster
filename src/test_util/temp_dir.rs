//! Private, atomically created test workspaces with scoped cleanup.
#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// A private test directory; path access never releases its cleanup guard.
#[derive(Debug)]
pub struct TestDir {
    path: PathBuf,
    _guard: tempfile::TempDir,
}

impl TestDir {
    /// Create a fresh owner-only workspace, or fail before any fixture writes.
    pub fn new(tag: &str) -> Self {
        // Short names leave room for Unix socket paths on Darwin.
        let guard = tempfile::Builder::new()
            .prefix("pm-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap_or_else(|e| panic!("test directory ({tag}): {e}"));
        let path = std::fs::canonicalize(guard.path()).unwrap();
        Self {
            path,
            _guard: guard,
        }
    }
}

impl std::ops::Deref for TestDir {
    type Target = PathBuf;

    fn deref(&self) -> &PathBuf {
        &self.path
    }
}

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
