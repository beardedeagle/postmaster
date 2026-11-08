# macOS libc Boundary

On Darwin the stable kernel ABI *is* libc, so these calls have no
raw-syscall route (contrast with Linux, where rustix's `linux_raw`
backend avoids libc FFI except `fork(2)`). This page covers peer checks, anti-
debug hardening, and extended ACLs; the launcher's signal-mask guard and the
sibling monitor's
kqueue/signal ops share the same justification and live on their own
pages ([signal deferral](./signal-deferral.md),
[sibling launch monitor](./monitor.md)).

## getpeereid — peer credential check

### Location

```text
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

```text
src/server.rs — fn harden_process (macOS cfg, release builds only)
```

### Purpose

The ptrace-from-peers half of Linux's `PR_SET_DUMPABLE`: deny debugger
attachment to the daemon. Compiled only under `not(debug_assertions)`;
`[profile.release]` sets `debug-assertions = false` by default. Enabling debug
assertions, including through a profile environment override, disables this
call. A failed attach-denial request is logged.

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

## Extended ACLs

`src/secret_files/acl.rs` binds the Darwin ACL and membership APIs that rustix
does not expose. Mode bits alone do not restrict extended ACL grants on macOS.
Directory checks reject grants to principals other than root or the effective
user that permit replacement or inherited reads of fresh files. Fresh private
files have their ACLs cleared before plaintext writes.

The wrapper owns each ACL and qualifier allocation and frees it once with
`acl_free`. Entry pointers borrow the live ACL; output pointers have initialized
storage and stay valid through each call. Qualifiers use Darwin's fixed
16-byte UUID layout and are compared with UUIDs resolved for trusted users.
Descriptor borrows keep the file open throughout each call. Failures return
errors before plaintext is written.

Native tests install replacement and inheritance grants in private fixtures,
verify rejection, and check that published files have no extended entries.
