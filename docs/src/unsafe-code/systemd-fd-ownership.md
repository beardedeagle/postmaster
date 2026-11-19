# systemd fd ownership (Linux)

On Linux, systemd hands Postmaster sockets as inherited file descriptors.
Postmaster validates the `sd_listen_fds(3)` protocol and checks that each fd is
a listening Unix stream socket before adopting it as an owned listener.

## Location

```text
src/server.rs — socket-activation path (Linux cfg only)
```

## Purpose

On Linux, postmaster is socket-activated: the `postmaster-credd.socket`
unit owns the per-(service, key) sockets and the daemon inherits them as
fds `[3, 3+n)`. Serving requires a `UnixListener`, so each inherited fd
is adopted with `UnixListener::from_raw_fd`.

## Why unsafe

`from_raw_fd` asserts *ownership*: if the fd were invalid, duplicated
elsewhere, or owned by someone else, the result is double-close /
use-after-close — undefined behavior the compiler cannot check.

The raw-fd checks use narrow libc `getsockopt` calls for `SO_DOMAIN`, `SO_TYPE`,
and `SO_ACCEPTCONN`. Each call receives initialized `c_int` storage and its exact
`socklen_t` length. A closed or invalid fd is rejected before constructing a
Rust fd reference or owner. This boundary cannot use a safe rustix borrowed-fd
wrapper until validity has been established. The listener's filesystem address
must then match a configured socket.

## UB vectors and mitigations

| Vector | Description | Mitigation |
|--------|-------------|------------|
| Wrong fd | Arbitrary fd adopted by mistake | `LISTEN_PID` must name this process; every fd must pass listening-stream socket checks and map to a configured filesystem path |
| Double ownership | Some other component also owns the fd | The protocol transfers ownership to this process; nothing else holds these fds |
| fd leak to child | Inherited socket leaking across execvp | `FD_CLOEXEC` is set on the listener immediately after adoption |
| Invalid or non-listening fd | A forged count includes a closed fd, regular file, or non-listening socket | Raw `getsockopt` checks fail before `from_raw_fd`; filesystem address checks follow adoption |

## Remaining risks

| Risk | Likelihood | Impact |
|------|------------|--------|
| Misconfigured unit files (wrong `FileDescriptorName`/count) | Low | Fails closed at startup (path mapping), never serves a wrong socket |

## Tests

Linux tests exercise descriptor validation. The macOS bind path creates its
own sockets and does not use systemd fd adoption. Daemon integration tests
exercise the serving behavior after listener acquisition.
