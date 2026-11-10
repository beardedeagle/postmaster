# Signal deferral (TerminationGuard)

While Postmaster decrypts and injects, termination
signals are blocked to protect the plaintext-write window. The launcher
restores the captured mask before exec. Masking failures are logged and
leave the write window unguarded.

## Location

```text
src/launcher.rs — struct TerminationGuard (macOS and Linux legs)
Blocks: block()/block_input() (sigmask), input_pending(), restore_mask(), Drop
```

## Purpose

On macOS, plaintext secret files persist on the ramdisk until
explicitly removed, so a SIGTERM landing *during* the plaintext-write
window would leave material on disk with no cleanup. `TerminationGuard`
blocks SIGTERM/SIGINT/SIGHUP/SIGQUIT (`monitor::STOP_SIGNALS`) from
just after config validation until the fork/exec at the end of the
window when masking succeeds. A masking failure is logged and leaves
the window unguarded. SIGKILL cannot be blocked.

At the end of the window the launcher forks the sibling monitor (see
[Sibling launch monitor](./monitor.md)), which **inherits the blocked
mask and keeps it for life** — the fork-child's guard is never dropped
(the monitor entry point diverges and exits via `_exit`/`exit_group`,
running no destructors). The parent calls `restore_mask()` before
`execvp` so the service starts with a clean signal state.

Setup reuses the guard while reading secrets from a terminal. `block_input()`
also blocks SIGTSTP, so suspension cannot hand back a terminal with echo disabled.
Terminal reads use nonblocking stdin, including buffered and noncanonical
input. Noncanonical reads temporarily use `VMIN=1` and `VTIME=0`, so an idle
read does not look like EOF. The loop checks pending signals while polling.
Failed or interrupted reads flush unread terminal input before restoring
terminal settings, stdin flags, and the saved signal mask. Successful reads
retain queued values. Prompt writes return errors, allowing restoration even
when stderr fails. Setup refuses terminal input if masking fails.
Redirected input keeps stdin's existing buffer and normal signal
behavior. Linux uses rustix's raw signal APIs; Darwin uses libc.

## Why unsafe

Raw signal-mask operations — `pthread_sigmask` on Darwin (whose stable
kernel ABI is libc), `rt_sigprocmask` via rustix's `runtime` module on
Linux — are invisible to Rust's type system: a wrong mask or an invalid
`sigset_t` is undefined behavior the compiler cannot reject. The
pre-fork guard shares its platform notes with the monitor page: the
rustix `runtime` API is experimental (lockfile-pinned), and the mask set
holds only standard signals no libc reserves.

## UB vectors and mitigations

| Vector | Description | Mitigation |
|--------|-------------|------------|
| Invalid `sigset_t` | Uninitialized set passed to the mask call | `zeroed()` (valid empty representation) then `sigemptyset` on Darwin; `KernelSigSet::empty()` on Linux |
| Dangling pointers | set/old must outlive each call | Locals live for the full block; no pointers escape |
| Thread-model mismatch | `sigprocmask` is unspecified in multithreaded processes | `pthread_sigmask` form on Darwin; on Linux the launcher is single-threaded at this point (worker threads exist only in serve mode) |
| libc-reserved signals | Masking a signal a libc reserves is UB (rustix `runtime` safety note) | The set holds only TERM/INT/HUP/QUIT, plus TSTP for input — none reserved (glibc reserves 32/33) |
| Mask clobber | Restoring a mask never captured | Both legs are Option-shaped and store `None` on block failure (logged); restore then no-ops |
| Mask leak to the service | Service inheriting blocked termination signals | Mask restored before `execvp` on every path (explicit + `Drop` on early-Err) — the monitor *wants* the mask and is the only inheritor |

## Remaining risks

| Risk | Likelihood | Impact |
|------|------------|--------|
| Kernel/libc signal quirks on future OS versions | Very low | Missed deferral (fail-open to an unguarded write window) |
| Operator sends SIGKILL mid-write | n/a | The monitor has not been forked yet. Files can remain until cleanup, RAM-disk destruction, or reboot |

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
(`tests/exec_check.rs`, `tests/exec_conformance/`).

Input tests use pseudo-terminals to check hidden single-line and multiline
input, idle noncanonical reads, prompt failures, queued values, and terminal
restoration. Real setup subprocesses cover
initial files, forced rotation, redirected input, and SIGTERM during input.
The interrupted canonical-input test checks what the next terminal reader
receives.
The test-only `openpty` call receives valid output pointers and null optional
settings; each returned descriptor transfers exactly once into an owning
`File`. The harness kills and waits for its child on teardown.
