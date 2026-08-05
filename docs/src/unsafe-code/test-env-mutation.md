# Test-Only env Mutation

## Location

```
src/keys/source.rs (test module) — 4 sites
src/keys/env.rs   (test module) — 2 sites
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
| Concurrent env access | Two tests mutating/reading env at once | Every call site holds a module-level `ENV_LOCK` mutex for the mutation's full scope |
| Lock-ordering | Multiple env-mutating tests in one binary | Single mutex per module; no nested acquisition |

Each site carries a SAFETY comment naming the serialization discipline.

## Known Gap (tracked)

The discipline is currently **per-module, not per-process**:
`keys/source.rs` and `keys/env.rs` (and `keys/mod.rs`'s tests) use
*separate* `ENV_LOCK` statics, and
`keys::tests::from_env_loads_and_fails_closed` mutates env without
holding any lock. Two such tests can still race — the loser may poison a
mutex and fail unrelated tests (~1 in 5 baseline runs observed). The
fix is one shared lock for every env-mutating test; it is tracked on the
project board and deliberately not smuggled into unrelated changes.

## Tests

These sites exist *in* tests; the flaky-race card above doubles as their
correctness tracking.
