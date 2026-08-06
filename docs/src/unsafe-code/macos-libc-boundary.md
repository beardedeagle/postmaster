# macOS libc Boundary

On Darwin the stable kernel ABI *is* libc, so these calls have no
raw-syscall route (contrast with Linux, where rustix's `linux_raw`
backend avoids libc FFI except `fork(2)`). This page covers the daemon's
two sites; the launcher's signal-mask guard and the sibling monitor's
kqueue/signal ops share the same justification and live on their own
pages ([signal deferral](./signal-deferral.md),
[sibling launch monitor](./monitor.md)).

## getpeereid — peer credential check

### Location

```
src/server.rs — fn peer_euid (macOS cfg only)
```

### Purpose

The credential socket must only answer the service user. On Linux the
daemon reads peer credentials with `SO_PEERCRED` (safe rustix); Darwin
has no `SO_PEERCRED`, so the equivalent is `getpeereid(2)` via libc.

### UB Vectors and Mitigations

| Vector | Description | Mitigation |
|--------|-------------|------------|
| Out-param types | `getpeereid` writes a `uid_t` and a `gid_t` | Out-params are exactly `libc::uid_t`/`libc::gid_t` |
| fd validity | The socket fd must stay valid for the call | Borrowed from `stream` for the call's duration only |

### Remaining Risks

`getpeereid` establishes *same-euid*, not *same-process*: any process
running as the service user passes. That is an accepted residual of the
UID-based peer model (see the threat model), not a defect of this
wrapper.

## PT_DENY_ATTACH — anti-debug hardening

### Location

```
src/server.rs — fn harden_process (macOS cfg, release builds only)
```

### Purpose

The ptrace-from-peers half of Linux's `PR_SET_DUMPABLE`: deny debugger
attachment to the daemon. Compiled only under `not(debug_assertions)`;
`[profile.release]` pins `debug-assertions = false` so a profile override
cannot silently compile it out (audit 2026-08-02 A23). Best-effort by
policy, but a failure is security-relevant and is logged (A10).

### UB Vectors and Mitigations

| Vector | Description | Mitigation |
|--------|-------------|------------|
| Bad arguments | `ptrace` is variadic-ish FFI | `PT_DENY_ATTACH` takes no pointer arguments: null addr, zero data — the documented invocation |
| Debug-build denial | Attaching a debugger in dev must stay possible | `#[cfg(not(debug_assertions))]` gate |

## Tests

The peer check is exercised wherever the daemon integration tests run on
macOS. `PT_DENY_ATTACH` cannot be meaningfully unit-tested (success
means a subsequent attach fails); its release-only gating is pinned by
`debug-assertions = false` in `[profile.release]` and verified by
release-profile clippy in the standard battery.
