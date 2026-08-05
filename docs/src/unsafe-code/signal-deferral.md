# Signal Deferral (macOS)

## Location

```
src/launcher.rs — struct TerminationGuard (macOS cfg only)
Blocks: block() (sigmask), pending() (sigpending), die_by() (re-raise), Drop (restore)
```

## Purpose

Audit 2026-08-02 A11: on macOS, plaintext secret files persist on the
ramdisk until explicitly removed, so a SIGTERM landing *during* the
plaintext-write window would leave material on disk with no cleanup.
`TerminationGuard` blocks SIGTERM/SIGINT/SIGHUP/SIGQUIT from just after
config validation until just before `execvp`. Before `execvp`, the
launcher synchronously checks `sigpending`; if a termination signal
arrived during the window, it runs `cleanup_written` and then dies by
that signal (`die_by`). The saved mask is always restored before exec —
a child must never inherit blocked termination signals.

Linux needs no equivalent: tmpfs does not persist across reboots,
systemd's `ExecStopPost` runs `postmaster cleanup`, and the next
launch's `prune_stale` removes residuals (documented decision, A11).

## Why Unsafe

Raw libc signal operations — `sigemptyset`/`sigaddset`,
`pthread_sigmask`, `sigpending`, `signal`, `raise`, `_exit` — are
invisible to Rust's type system: a wrong mask, an invalid `sigset_t`, or
a bad pointer is undefined behavior the compiler cannot reject. Darwin's
stable kernel ABI is libc, so there is no raw-syscall alternative.

## UB Vectors and Mitigations

| Vector | Description | Mitigation |
|--------|-------------|------------|
| Invalid `sigset_t` | Uninitialized set passed to libc | `zeroed()` (valid empty representation) then `sigemptyset` |
| Dangling pointers | set/old must outlive each call | Locals live for the full block; no pointers escape |
| Thread-model mismatch | `sigprocmask` is unspecified in multithreaded processes | `pthread_sigmask` form used throughout |
| Async-signal context | Work inside a handler would be unsound | **No handlers are ever installed** — deferral is mask-only; the pending check is synchronous |
| Mask leak to child | Child inheriting blocked termination signals | Mask restored before `execvp` on every path (explicit + `Drop` on early-Err) |
| Lost signal | Deferred signal swallowed | `die_by` resets `SIG_DFL`, restores the saved mask, re-raises; `libc::_exit(128 + sig)` if `raise` itself fails |

## Remaining Risks

| Risk | Likelihood | Impact |
|------|------------|--------|
| Kernel/libc signal quirks on future Darwin versions | Very low | Missed deferral (fail-open to pre-A11 behavior) |
| Operator sends SIGKILL | n/a | Unblockable by design; ramdisk contents persist until next boot — accepted residual |

For the design-level race in how the guard is *used* (pending-check →
mask-restore → exec — a property of the launch flow, not of these
unsafe blocks), see the threat model's
[plaintext persistence window](../architecture/threat-model.md#plaintext-file-persistence-window-files-mode--mitigated)
section.

## Tests

Exercised by the exec integration suites (`tests/exec_check.rs`,
`tests/exec_conformance/`) for the surrounding write/exec contract. The
guard's restore-before-exec is structural (consuming `Drop`); a direct
signal-race unit test would be timing-flaky by nature and is documented
as intentionally absent.
