# systemd fd Ownership (Linux)

## Location

```
src/server.rs — socket-activation path (Linux cfg only)
```

## Purpose

On Linux, postmaster is socket-activated: the `postmaster-credd.socket`
unit owns the per-(service, key) sockets and the daemon inherits them as
fds `[3, 3+n)`. Serving requires a `UnixListener`, so each inherited fd
is adopted with `UnixListener::from_raw_fd`.

## Why Unsafe

`from_raw_fd` asserts *ownership*: if the fd were invalid, duplicated
elsewhere, or owned by someone else, the result is double-close /
use-after-close — undefined behavior the compiler cannot check.

## UB Vectors and Mitigations

| Vector | Description | Mitigation |
|--------|-------------|------------|
| Wrong fd | Arbitrary fd adopted by mistake | The `sd_listen_fds(3)` protocol is validated first: `LISTEN_PID` names this process, so fds `[3, 3+n)` are exactly the sockets systemd created for us |
| Double ownership | Some other component also owns the fd | The protocol transfers ownership to this process; nothing else holds these fds |
| fd leak to child | Inherited socket leaking across execvp | `FD_CLOEXEC` is set on the listener immediately after adoption |
| Not-a-socket | Wrong unit passed non-socket fds | `getsockname(2)` mapping to the filesystem path fails closed immediately |

## Remaining Risks

| Risk | Likelihood | Impact |
|------|------------|--------|
| Misconfigured unit files (wrong `FileDescriptorName`/count) | Low | Fails closed at startup (path mapping), never serves a wrong socket |

## Tests

Not exercised on macOS dev hosts (the macOS leg uses `--bind`, which owns
its socket paths directly). The adoption is one line inside a path that
fails closed on every validation error; the daemon's fetch-loop
integration tests cover the serving behavior that follows it.
