# Signal Deferral (TerminationGuard)

## Location

```
src/launcher.rs — struct TerminationGuard (macOS and Linux legs)
Blocks: block() (sigmask), restore_mask() (sigmask), Drop (restore)
```

## Purpose

Audit 2026-08-02 A11: on macOS, plaintext secret files persist on the
ramdisk until explicitly removed, so a SIGTERM landing *during* the
plaintext-write window would leave material on disk with no cleanup.
`TerminationGuard` blocks SIGTERM/SIGINT/SIGHUP/SIGQUIT
(`monitor::STOP_SIGNALS`) from just after config validation until the
fork/exec at the end of the window — a deterministic write window: no
termination signal can kill the launcher mid-write.

At the end of the window the launcher forks the sibling monitor (see
[Sibling Launch Monitor](./monitor.md)), which **inherits the blocked
mask and keeps it for life** — the fork-child's guard is never dropped
(the monitor entry point diverges and exits via `_exit`/`exit_group`,
running no destructors). The parent calls `restore_mask()` before
`execvp` so the service starts with a clean signal state.

The guard previously also carried a sigaction flag-recording handler
(`disarm`/`recorded`) and a second pre-exec gate to close the
check/exec race. Both were **retired with the sibling-monitor design
(2026-08-05)**: the monitor owns stop semantics on every death path, so
no async handler is needed anywhere and the handler's forever-purity
constraint is gone with it. What remains — `block()` and
`restore_mask()` — is what this page covers.

The guard became real on Linux with the same change: the fork+monitor
model runs there too, and the blocked mask is the monitor's inheritance.
The Linux leg uses rustix's raw `rt_sigprocmask` (`runtime` module — the
experimental API; see the monitor page for the doctrinal discussion), so
the Linux exec path adds no libc signal FFI.

## Why Unsafe

Raw signal-mask operations — `pthread_sigmask` on Darwin (whose stable
kernel ABI is libc), `rt_sigprocmask` via rustix's `runtime` module on
Linux — are invisible to Rust's type system: a wrong mask or an invalid
`sigset_t` is undefined behavior the compiler cannot reject. The
pre-fork guard shares its platform notes with the monitor page: the
rustix `runtime` API is experimental (lockfile-pinned), and the mask set
holds only standard signals no libc reserves.

## UB Vectors and Mitigations

| Vector | Description | Mitigation |
|--------|-------------|------------|
| Invalid `sigset_t` | Uninitialized set passed to the mask call | `zeroed()` (valid empty representation) then `sigemptyset` on Darwin; `KernelSigSet::empty()` on Linux |
| Dangling pointers | set/old must outlive each call | Locals live for the full block; no pointers escape |
| Thread-model mismatch | `sigprocmask` is unspecified in multithreaded processes | `pthread_sigmask` form on Darwin; on Linux the launcher is single-threaded at this point (worker threads exist only in serve mode) |
| libc-reserved signals | Masking a signal a libc reserves is UB (rustix `runtime` safety note) | The set holds only TERM/INT/HUP/QUIT — none reserved (glibc reserves 32/33) |
| Mask clobber | Restoring a mask never captured | The Linux leg stores `None` on block failure (logged); restore then no-ops |
| Mask leak to the service | Service inheriting blocked termination signals | Mask restored before `execvp` on every path (explicit + `Drop` on early-Err) — the monitor *wants* the mask and is the only inheritor |

## Remaining Risks

| Risk | Likelihood | Impact |
|------|------------|--------|
| Kernel/libc signal quirks on future OS versions | Very low | Missed deferral (fail-open to pre-A11 behavior) |
| Operator sends SIGKILL mid-write | n/a | Unblockable by design; ramdisk contents persist until next boot (macOS) — accepted residual; the monitor covers everything *after* the fork |

For the design-level stop semantics the guard feeds into (monitor
forwarding, grace, escalation, cleanup on every death path), see the
threat model's
[plaintext persistence window](../architecture/threat-model.md#plaintext-file-persistence-window-files-mode--mitigated)
section and the [monitor page](./monitor.md).

## Tests

The guard's contract is exercised end-to-end by the monitor tests
(`monitor::tests` — every one of them blocks via
`TerminationGuard::block()` before forking the real monitor loop, exactly
mirroring production) and by the exec integration suites
(`tests/exec_check.rs`, `tests/exec_conformance/`). The retired
flag-handler test was removed with the handler.
