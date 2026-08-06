# Unsafe Code

Postmaster deliberately allows `unsafe` at the lint level (documented in
`[lints.rust]` in `Cargo.toml`) because it is a syscall-boundary daemon:
peer-credential checks, anti-debug hardening, signal-mask deferral, the
sibling launch monitor (fork + pidfd/kqueue liveness), and the systemd
socket-activation contract cannot be expressed in safe Rust.
This section documents every approved site.

## Policy

Every `unsafe` block requires:

1. A SAFETY comment at the site covering every UB vector
2. Minimal scope — the smallest possible unsafe block
3. Safe wrappers first — rustix (raw syscalls, no libc FFI) on Linux;
   libc only where the platform's stable ABI *is* libc (Darwin)
4. Documentation in this section (registry entry + page)
5. Tests exercising the mitigation where the platform allows

## Registry

| Location | Platform | Purpose | Page |
|----------|----------|---------|------|
| `launcher.rs` (TerminationGuard: block/restore_mask/Drop) | macOS, Linux | Defer termination signals across the plaintext-write window; the fork-child monitor inherits the mask for life | [signal-deferral](./signal-deferral.md) |
| `launcher.rs` (fork(2)) | macOS, Linux | Fork the sibling monitor before exec — the single libc FFI call on Linux (doctrine exception) | [monitor](./monitor.md) |
| `monitor.rs` (signal mask/wait ops, pidfd+poll / kqueue, `_exit`/`exit_group`, raw stderr write) | macOS, Linux | Sibling monitor: synchronous stop consumption, liveness watch, cleanup on every death path | [monitor](./monitor.md) |
| `server.rs` (`peer_euid`) | macOS | Peer credential check via `getpeereid(2)` | [macos-libc-boundary](./macos-libc-boundary.md) |
| `server.rs` (`harden_process`) | macOS, release only | `PT_DENY_ATTACH` anti-debug hardening | [macos-libc-boundary](./macos-libc-boundary.md) |
| `server.rs` (socket activation) | Linux | `UnixListener::from_raw_fd` on systemd-inherited sockets | [systemd-fd-ownership](./systemd-fd-ownership.md) |
| `keys/source.rs`, `keys/env.rs` (test modules) | all, test-only | `set_var`/`remove_var` (unsafe on edition 2024) | [test-env-mutation](./test-env-mutation.md) |

Note what is NOT in the inventory: `mlockall`, `setrlimit(Core, 0)`, and
`set_dumpable(NotDumpable)` hardening all use **safe** rustix wrappers.

## Adding Unsafe Code

1. **Exhaust safe alternatives** — rustix first; is there a safe way at all?
2. **Justify in the platform note** — why this platform has no safe route
3. **Minimize scope** — smallest possible unsafe block
4. **Mitigate all UB vectors** — each one named in the SAFETY comment
5. **Add to this section** — registry entry + a page following this format
6. **Write tests** — verify the mitigations work (or document why untestable)
7. **Get review** — unsafe requires explicit approval

The bar is intentionally high. Postmaster's design keeps plaintext custody to microseconds — decrypt at the last instant, zeroize immediately, never persist. A memory-safety bug is one of the few things that can silently break that invariant.
