//! Test-only shared utilities (compiled under `#[cfg(test)]` only).

/// Process-wide lock serializing every unit test that mutates — or
/// wholesale snapshots — the process-global environment. The test
/// harness runs tests in parallel threads of one process, so
/// unsynchronized `set_var`/`remove_var`, or a full `vars()` scan
/// racing another test's mutation, is a data race; edition 2024 marks
/// those calls `unsafe`.
///
/// ALL env-touching tests in every module hold this ONE lock for the
/// mutation's full scope. Module-local locks do not exclude each other:
/// separate per-module statics raced, and the loser's panic poisoned a
/// mutex, failing unrelated tests (~1 in 5 baseline runs, observed
/// 2026-08-04).
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
