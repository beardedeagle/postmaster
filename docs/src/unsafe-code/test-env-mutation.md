# Test-only environment mutation

Some tests must change the process environment,
which Rust 2024 marks `unsafe` because it can race other threads.
Every such test holds one shared process-wide lock, so env-mutating
tests can never run — or race — concurrently.

## Location

```text
src/test_util.rs                 — the shared ENV_LOCK itself
src/keys/source.rs (test module) — credential and source-selection tests
src/keys/env.rs (test module)    — environment key-loading tests
src/keys/provisioning/mod.rs (test module) — environment provisioning checks
```

## Purpose

Edition 2024 marks `std::env::set_var`/`remove_var` `unsafe`: mutating
the process environment is a data race in a multithreaded process, and
the Rust test harness runs tests in parallel threads of one process.
Several key-source tests must set or clear `DOTENV_PRIVATE_KEY*` /
`POSTMASTER_KEY*` / `CREDENTIALS_DIRECTORY` to exercise source
selection.

## UB vectors and mitigations

| Vector | Description | Mitigation |
|--------|-------------|------------|
| Concurrent env access | Two tests mutating/reading env at once | Every call site holds the single process-wide `ENV_LOCK` (`crate::test_util`) for the mutation's full scope |
| Lock-ordering | Multiple env-mutating tests in one binary | One shared mutex for the whole test binary; no nested acquisition |

Each site carries a SAFETY comment naming the serialization discipline.

## Why one process-wide lock

Module-local locks do not exclude tests in other modules. Every test that
mutates the environment, or reads variables another test mutates, must hold
`crate::test_util::ENV_LOCK` for that scope. The lock serializes cooperating
tests; it does not control environment access inside unrelated libraries.

## Tests

These sites exist *in* tests; the shared-lock discipline is their
correctness property, exercised by every suite run.
