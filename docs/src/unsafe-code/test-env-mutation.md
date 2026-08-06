# Test-Only env Mutation

## Location

```
src/test_util.rs                 — the shared ENV_LOCK itself
src/keys/source.rs (test module) — 4 sites
src/keys/env.rs (test module)    — 1 test, 2 set/remove pairs
src/keys/provisioning/mod.rs (test module) — 1 test, 2 set/remove pairs + a full vars() scan
```

## Purpose

Edition 2024 marks `std::env::set_var`/`remove_var` `unsafe`: mutating
the process environment is a data race in a multithreaded process, and
the Rust test harness runs tests in parallel threads of one process.
Several key-source tests must set or clear `DOTENV_PRIVATE_KEY*` /
`CREDENTIALS_DIRECTORY` to exercise source selection.

## UB Vectors and Mitigations

| Vector | Description | Mitigation |
|--------|-------------|------------|
| Concurrent env access | Two tests mutating/reading env at once | Every call site holds the single process-wide `ENV_LOCK` (`crate::test_util`) for the mutation's full scope |
| Lock-ordering | Multiple env-mutating tests in one binary | One shared mutex for the whole test binary; no nested acquisition |

Each site carries a SAFETY comment naming the serialization discipline.

## Why one process-wide lock

The discipline was previously **per-module**: `keys/source.rs` and
`keys/provisioning/mod.rs` each had their own `ENV_LOCK` static, and
`keys/env.rs`'s `from_env_loads_and_fails_closed` mutated env holding no
lock at all. Module-local locks do not exclude each other, so two such
tests still raced — the loser's panic poisoned a mutex and failed
unrelated tests (~1 in 5 baseline runs, observed 2026-08-04). Since
2026-08-06 every env-mutating test in every module acquires the single
`crate::test_util::ENV_LOCK`; any new env-touching test must do the same.

## Tests

These sites exist *in* tests; the shared-lock discipline is their
correctness property, exercised by every suite run.
