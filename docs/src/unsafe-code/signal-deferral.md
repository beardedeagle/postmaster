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
config validation until just before `execvp`. At the end of the window
the guard is *disarmed*: while the signals are still blocked (so nothing
can be delivered mid-install), a flag-recording handler is installed for
the four signals, and only then is the saved mask restored. Any signal
pending from the window is delivered to that handler — never to the
default disposition — so no termination signal can kill the launcher
without `cleanup_written` running first. If the flag is set, the
launcher removes the plaintext and dies by that signal (`die_by`);
otherwise it `execvp`s. Caught-signal dispositions reset to default at
exec, so the child starts with a clean signal state.

Linux needs no equivalent: tmpfs does not persist across reboots,
systemd's `ExecStopPost` runs `postmaster cleanup`, and the next
launch's `prune_stale` removes residuals (documented decision, A11).

## Why Unsafe

Raw libc signal operations — `sigemptyset`/`sigaddset`,
`pthread_sigmask`, `sigpending`, `sigaction`, `signal`, `raise`,
`_exit` — are invisible to Rust's type system: a wrong mask, an invalid
`sigset_t`, or a bad pointer is undefined behavior the compiler cannot
reject. Darwin's stable kernel ABI is libc, so there is no raw-syscall
alternative. Note that the `sigaction` install added for the race
closure is the *same* libc signal-operation family as the pre-existing
mask operations: the unsafe surface grows in size, not in kind.

## UB Vectors and Mitigations

| Vector | Description | Mitigation |
|--------|-------------|------------|
| Invalid `sigset_t` | Uninitialized set passed to libc | `zeroed()` (valid empty representation) then `sigemptyset` |
| Dangling pointers | set/old must outlive each call | Locals live for the full block; no pointers escape |
| Thread-model mismatch | `sigprocmask` is unspecified in multithreaded processes | `pthread_sigmask` form used throughout |
| Handler soundness | Any non-reentrant work in a handler is unsound | The handler body is a single atomic store (`PENDING_SIG`) — the canonical async-signal-safe operation. Registry rule: it must NEVER grow logging, allocation, or locking |
| `sigaction` validity | Malformed struct/mask/handler pointer is UB | Zeroed struct + `sigemptyset` mask; handler has the C signal-handler ABI; every `sigaction` rc is checked — any failure falls back to the pre-handler pending check (the documented residual then applies to that launch) |
| Install-time delivery | Signal delivered between the four `sigaction` calls | All four signals are still blocked during install, so nothing can be delivered mid-install |
| Signal floods | Many termination signals while blocked | Non-realtime signals coalesce in the kernel; the flag records one — any of them means die |
| Mask leak to child | Child inheriting blocked termination signals | Mask restored before `execvp` on every path (explicit + `Drop` on early-Err) |
| Lost signal | Deferred signal swallowed | `die_by` resets `SIG_DFL`, restores the saved mask, re-raises; `libc::_exit(128 + sig)` if `raise` itself fails |
| Signal after final check | TERM lands between flag check and `execvp` | The flag is read a second time immediately before `execvp`; only a signal inside the execve path itself (~microseconds) can slip through — recorded but unexamined, the manager's escalation (SIGKILL) performs the stop. Supervision-semantics, not plaintext exposure (the files are the child's by design) |

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

`launcher::tests::disarm_records_signal_raised_during_the_window`
(deterministic, macOS): blocks the guard, raises SIGTERM at the process
itself, and asserts `disarm()` returns `Some(SIGTERM)` with the process
still alive — proving the whole handoff: delivery goes to the recording
handler, never to the default disposition. The surrounding write/exec
contract is exercised by the exec integration suites
(`tests/exec_check.rs`, `tests/exec_conformance/`).
