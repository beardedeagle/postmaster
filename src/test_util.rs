//! Test-only shared utilities (compiled under `#[cfg(test)]` only).

pub(crate) mod aad_fixture;
pub(crate) mod pty;
pub(crate) mod temp_dir;

/// Whether `/` is owned by root or the current effective user.
pub(crate) fn root_has_trusted_owner() -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let owner = std::fs::metadata("/").expect("stat filesystem root").uid();
    owner == 0 || owner == rustix::process::geteuid().as_raw()
}

/// Process-wide lock serializing every unit test that mutates — or
/// wholesale snapshots — the process-global environment. The test
/// harness runs tests in parallel threads of one process, so
/// unsynchronized `set_var`/`remove_var`, or a full `vars()` scan
/// racing another test's mutation, is a data race; edition 2024 marks
/// those calls `unsafe`.
///
/// Environment-mutating and whole-environment snapshot tests hold this lock
/// for the full scope. Separate module-local locks would not exclude each other.
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
