# Sibling Launch Monitor

> **At a glance:** a sibling process watches the service until it exits.
> It forwards stop signals, escalates to SIGKILL after a 250 ms grace, and
> removes secret files after exit, a crash, or `kill -9`. It scrubs projected
> environment pairs but retains the launcher's original environment.

## Lifecycle

```mermaid
sequenceDiagram
    participant L as Launcher (parent)
    participant M as Monitor (fork-child)
    participant S as Service (exec'd parent)

    L->>L: block stop signals; materialize; wipe ring and resolved buffers
    L->>M: fork()
    Note over M: scrub projected pairs; retain original environment; keep mask blocked
    L->>S: restore mask; execvp becomes service
    loop poll tick
        M->>S: liveness (pidfd+poll / kqueue NOTE_EXIT)
        M->>M: stop signal pending? (sigpending then sigwait)
    end
    alt stop signal (TERM/INT/HUP/QUIT)
        M->>S: forward the signal
        Note over M,S: bounded grace (250 ms)
        alt service exits within the grace
            M->>M: cleanup plaintext files; exit 0
        else grace expires
            M->>S: SIGKILL
            M->>M: cleanup plaintext files; exit 0
        end
    else service death (exit, crash, kill -9)
        M->>M: cleanup plaintext files; exit 0
    end
```

## Location

```text
src/monitor.rs — the monitor loop, liveness watches, signal ops, exit
src/launcher.rs — the fork(2) site and both TerminationGuard legs (macOS + Linux)
Unsafe blocks: fork(2) (libc, both platforms); rustix `runtime`
  kernel_sigprocmask/kernel_sigwait (Linux); libc pthread_sigmask/
  sigpending/sigwait/kqueue/kevent/_exit (macOS);
  OwnedFd::from_raw_fd (macOS kqueue fd); BorrowedFd::borrow_raw (stderr)
```

## Purpose

The sibling monitor closes the launch-handoff stop-semantics gap and
adds plaintext cleanup on **every** service-death path. After
validation, plaintext writes, and zeroization of the key ring and resolved
buffers, and before `execvp`,
the launcher `fork()`s. The parent restores its
pre-guard signal mask and execs the service (MainPID unchanged); the
fork-child becomes the monitor: it keeps the four termination signals
blocked for life, consumes them synchronously (sigpending/sigwait — no
handlers anywhere), forwards stops to the service, escalates to SIGKILL
after a 250 ms grace (a single global security policy, deliberately not
configurable), watches liveness (pidfd+poll on Linux, kqueue
`EVFILT_PROC`/`NOTE_EXIT` on macOS, `kill(pid, 0)` only as fallback), and
runs `cleanup_written` before exiting — on stop, on natural exit, on
`kill -9`, on crash. The sigaction flag-handler and second pre-exec gate
were retired with this design: the monitor is the single owner of stop
semantics, so no async-signal context exists anywhere.

The scrub does not erase the monitor's original process environment.
Private keys supplied through environment variables can remain there for
the monitor's lifetime. Use a non-environment key source to avoid that
exposure. See [Private-key environment variables](../architecture/threat-model.md#private-key-environment-variables).

## Why Unsafe

- **`fork(2)` has no rustix wrapper** (a deliberate rustix omission), so
  it is a direct libc call on both platforms. On Linux this is the
  **single libc FFI call on the exec path** — an explicit, review-gated
  exception to the "rustix linux_raw / no libc FFI on Linux" doctrine.
  Everything else on the Linux leg is rustix.
- **Linux signal masking and synchronous consumption** use rustix's
  experimental runtime API (`kernel_sigprocmask`, `kernel_sigwait`,
  `kernel_sigpending`, `exit_group`) — rustix's experimental, doc-hidden
  API for libc-like runtimes. It is the only rustix route to signal masks
  (there is no `rustix::process::sigprocmask`), and taking it avoids libc
  signal FFI on Linux. Cargo.lock pins the exact rustix; an update that
  changes this unstable API fails the build loudly, never silently. The
  documented hazard class (a libc in the process reserves some signals)
  does not apply: the mask set holds only TERM/INT/HUP/QUIT/PIPE, none of
  which any libc reserves (glibc reserves 32/33).
- **Darwin has no raw-syscall ABI** and no `sigtimedwait` at all, so the
  macOS leg uses libc for `pthread_sigmask`, `sigpending`, `sigwait`,
  `kqueue`/`kevent`, and `_exit` — the same libc-signal family already on
  this boundary, plus kqueue. rustix's `runtime` module does not exist
  off Linux (it is `linux_raw_sys`-typed), and rustix's stable API has no
  signal-mask or sigwait wrappers on any platform.
- `OwnedFd::from_raw_fd` (kqueue fd) and `BorrowedFd::borrow_raw(2)`
  (monitor diagnostics) are fd-ownership assertions of the same kind as
  the systemd socket boundary.

rustix 1.x provides
`pidfd_open`/`pidfd_send_signal` (Linux-only) and `poll`, so the pidfd
leg needs no fallback in practice; `kill(pid, 0)` polling is kept only
for kernels without `pidfd_open` (< 5.3) and for kqueue failure. An
`ESRCH` from `pidfd_open`, from `kevent` registration, or from
`kill(pid, 0)` is race-free "definitely gone" and short-circuits to
cleanup (on macOS, xnu drops exited procs from the pid table before they
are reaped, so NOTE_EXIT registration on an already-exited service fails
`ESRCH` — handled as death, not as a fallback trigger).

rustix 1.1.6 exports the experimental API as `runtime_448b8ad740e2a26f`.
The launcher and monitor import it as `runtime`.

## UB Vectors and Mitigations

| Vector | Description | Mitigation |
|--------|-------------|------------|
| Fork in a threaded process | The child inherits locked malloc/stdio state | The production launcher is single-threaded at fork. The monitor first scrubs and frees projected env pairs; this exception requires that single-threaded parent. Test children pass an empty pair list. The loop then uses the syscall set documented in `monitor.rs`, without allocation or stdio locks, and exits via `_exit`/`exit_group` |
| Invalid `sigset_t` | Uninitialized set passed to sigwait/sigpending | `KernelSigSet::empty()` (rustix) / `zeroed()` + `sigemptyset` (libc) |
| Blocking sigwait hang | `sigwait` blocks until a set member is pending | Called only after `sigpending` shows a member pending — single-threaded, so nothing else can dequeue it first |
| Mask clobber | Restoring a mask never captured | Linux guard stores `None` on block failure (logged); restore then no-ops |
| Mask leak to the service | Service inheriting blocked termination signals | The parent restores the saved mask before `execvp` (explicit call + `Drop` on early-Err paths); the fork-child's guard is never dropped (`monitor::run` diverges, `_exit` runs no destructors), so the monitor keeps the mask for life |
| Wrong-fd ownership | Closing an fd not owned | `from_raw_fd` wraps a fresh `kqueue()` result exactly once; `borrow_raw(2)` never closes and never outlives the call (an absent stderr just fails the write with EBADF) |
| PID reuse | Signals/liveness hitting a recycled PID | pidfd pins the process: `poll` fires at exit (zombie-proof) and `pidfd_send_signal` cannot hit a recycled PID. `ESRCH` anywhere is treated as race-free death. Residual: the macOS stop-forward path uses plain `kill(2)` (Darwin has no pidfd) — a bounded exposure, accepted in the threat model |
| Zombie blindness | `kill(pid, 0)` succeeds on zombies | pidfd/kqueue are the primary mechanisms precisely because they fire at exit, not at reap; polling is fallback-only and documented |
| Handler unsoundness | Non-reentrant work in signal context | Eliminated by design — there are no signal handlers; consumption is synchronous in the loop |

## Remaining Risks

| Risk | Likelihood | Impact |
|------|------------|--------|
| rustix `runtime` API changes in a future rustix | Low (lockfile-pinned; build fails loudly at update time) | Build breakage, not a runtime defect |
| Monitor dies before the service | Monitor failure or external termination | Cleanup falls to integration-provided `ExecStopPost`, ramdisk teardown, and next-launch `prune_stale` |
| Job-control stop (SIGTSTP) of the monitor's process group | Interactive sessions only | The monitor suspends with the service; cleanup waits for continuation — backstops remain |
| Service unkillable in D-state after SIGKILL | Kernel pathology | The monitor's post-SIGKILL death wait is unbounded by design (abandoning cleanup is worse); the manager's own escalation path still applies |
| Polling fallback on a pre-5.3 kernel | Legacy kernels only | Zombie-blindness until the parent reaps (systemd reaps promptly); PID-reuse exposure as documented |

## Tests

`monitor::tests` fork the REAL monitor loop in a real fork-child against
real service processes (deterministic; grace/poll injectable; no env
mutation): natural `kill -9` death → cleanup + exit; TERM to the monitor
→ forwarded (service dies by TERM, proving no escalation) → cleanup +
exit; a TERM-ignoring forked service (`SIG_IGN` + `pause`) → SIGKILL only
after the grace → cleanup + exit; env-mode (no fd, empty names) → exit on
service death. The TERM-ignoring child acknowledges readiness through a
pipe after installing `SIG_IGN`; it uses only async-signal-safe calls after
fork. The parent waits for that acknowledgement before starting the monitor.
The exec integration suites
(`tests/exec_check.rs`, `tests/exec_conformance/`) exercise the full
fork+exec path and assert the post-exit cleanup contract.
