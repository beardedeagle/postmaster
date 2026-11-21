# CLI reference

Commands, flags, and exit codes accepted by `src/cli/mod.rs`.

## Synopsis

```console
$ postmaster --config <file.json> [--bind] [--allow-nonroot]
$ postmaster exec --config <exec.json> [--check] [--verify-keys] -- <command> [args…]
$ postmaster setup --config <exec.json> [--recheck] [--unattended] [--force] [--keys-dir <path>]
$ postmaster cleanup --config <exec.json>
$ postmaster fetch [--protocol raw|framed] [--server-uid <uid>] <socket-path>
$ postmaster help [subcommand]
$ postmaster --version
$ postmaster --help
```

## Global flags

| Flag | Description |
| --- | --- |
| `--help`, `-h` | Print top-level help and exit |
| `--version`, `-V` | Print version and exit |

## Default mode (serve)

Serve mode has no subcommand keyword — invoke it with the serve flags
directly. This is the credential server used in credentials injection
mode — socket-activated on Linux, self-binding on macOS. (Bare
`postmaster` with no arguments prints the top-level help and exits 1.)

```console
$ postmaster --config <file.json> [--bind] [--allow-nonroot]
```

| Flag | Description |
| --- | --- |
| `--config <path>` | Configuration file (required) |
| `--bind` | Bind listener sockets even if not socket-activated (macOS) |
| `--allow-nonroot` | Allow non-root connections (dev escape hatch; never overrides a configured `peer_user` ACL) |

On Linux, postmaster is socket-activated: the `postmaster-credd.socket`
unit owns the sockets and the daemon inherits them via
`sd_listen_fds`. On macOS, `--bind` causes postmaster to create its own
listener sockets.

### Daemon configuration

Each socket maps to an entry with `env_file`, `key`, `env_file_sha256`, and
optional `peer_user` and `protocol`. `env_file_sha256` is a list of SHA-256
hashes, encoded as 64 hex digits, for the exact dotenv file bytes authorized
for that entry.
Postmaster checks the hash before parsing, interpolation, or decryption, both
at startup and on every fetch. An empty list authorizes nothing. This applies
to plaintext assignments too.

Keep this configuration under trusted ownership. Compute hashes from the
trusted artifact before deployment, rather than from the writable runtime
copy. On Linux, use `sha256sum <file>`; on macOS, use `shasum -a 256 <file>`.
Line endings, whitespace, and metadata count toward the hash. Multiple hashes
allow old and new files during staged rotation; remove the old hash when that
window ends. The dotenvx ciphertext format and private-key rotation candidates
stay the same.

When binding as root, sockets for different unprivileged peers need separate
parent directories. One peer's parent cannot contain another peer's socket
parent. Postmaster resolves aliases and checks these ownership domains before
changing directories or binding sockets. Sockets for the same user can share
a parent; root-only entries and `peer_user` resolving to uid 0 share a domain.
The directory walk pins each component before creation, ownership changes,
unlinking, and binding. It checks ancestor ownership, writable modes, and macOS
ACL grants. Trusted intermediate aliases remain supported; a symlink as the
final socket parent is refused.

`protocol` selects `raw` or `framed` for that socket. It defaults to `raw`,
which sends only credential bytes for systemd's `LoadCredential=` socket
reader. Use `framed` for Postmaster clients that must reject incomplete
responses. Each configured socket uses one protocol; there is no negotiation.

## exec

Decrypt and inject secrets, then `execvp` the target binary.

```console
$ postmaster exec --config <exec.json> [--check] [--verify-keys] -- <command> [args…]
```

| Flag | Required | Description |
| --- | --- | --- |
| `--config <path>` | Yes | Path to `exec.json` (before `--`) |
| `--check` | No | Validate config shape only, no decryption (for CI) |
| `--verify-keys` | No | Preflight decryption to catch stale keys |
| `--` | Yes (unless `--check`) | Separator; everything after is the child argv |

- On success the process image is replaced (`execvp`); postmaster never
  returns.
- On failure the error is logged and the process exits non-zero.
- `--check` does not accept a command after `--`.
- `--check` conflicts with `--verify-keys`. Shape validation never decrypts.
- Paths and child arguments preserve non-UTF-8 Unix bytes.
- `--verify-keys` performs a preflight check: after loading and
  decrypting, if any value was skipped because the key ring could not
  decrypt it, the keys are stale and the exec aborts naming the key.
  This catches the `strict: false` case where stale keys would
  otherwise silently skip undecryptable values (partial or empty set).

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | `--check` passed (or exec succeeded — but exec replaces the process) |
| 1 | Any failure — usage errors, config errors, parse failure, decryption failure |

## setup

Create the keys directory, check key sources, and optionally seed macOS
Keychain accounts. Setup skips steps that are already satisfied. It derives
one required-account list in first-seen input order, without duplicate prompts.
Credentials mode needs no private-key source, so setup validates its config
without creating a keys directory. Verification uses the same ordered source
selection and private-file custody checks as runtime loading. An absent
systemd credential allows the next source; a selected source's failure is final.

```console
$ postmaster setup --config <exec.json> [--recheck] [--unattended] [--force] [--keys-dir <path>]
```

| Flag | Description |
| --- | --- |
| `--config <path>` | Path to `exec.json` (required) |
| `--recheck` | Verification-only — no creation or seeding |
| `--unattended` | Fail closed without prompting (for CI/automation). Alias: `--non-interactive` |
| `--force` | Re-create/re-seed even if already correct |
| `--keys-dir <path>` | Override default keys directory |

`--recheck` conflicts with `--force`.

Default keys directory:

- Linux: `/var/lib/postmaster`
- macOS: `~/Library/Application Support/postmaster` (falls back to
  `/var/lib/postmaster` when `HOME` is empty or unset)

Secret terminal input has echo disabled until the read finishes. Postmaster
restores terminal settings before delivering a pending termination or suspend
signal. Key files accept multiline input through EOF; Keychain values use one
trimmed line. Failed or interrupted terminal reads discard unread input before
restoration. Successful reads retain queued values. Redirected input keeps the
same format and queued values. Setup reads directly into zeroizing buffers
without retaining secret input in a global stdin buffer. Secret input and key
files are capped at 16 MiB.

Forced key-file replacement verifies ownership, regular-file type, and single
link count before changing permissions. It pins the parent, checks that the
original inode still occupies the name after input, and publishes a fresh
0600 inode. Existing read handles keep the old contents. A declined replacement
keeps the existing contents; unattended replacement fails without prompting.

## cleanup

Remove plaintext secret files from the secrets directory after the
child exits.

```console
$ postmaster cleanup --config <exec.json>
```

| Flag | Description |
| --- | --- |
| `--config <path>` | Path to `exec.json` (reads `secrets_dir` from config) |

Cleanup refuses to bulk-delete a non-empty directory without the
`.postmaster-managed` sentinel. The marker identifies a managed directory,
not individual files, so keep one `secrets_dir` per service. Empty or missing
directories need no cleanup. If a secret-file stat or removal fails, the command
retains the sentinel and returns an error so cleanup can be retried. Removing
the sentinel after successful cleanup is best effort.
Cleanup validates directory ancestry and requires the sentinel and removable
files to be regular, owned by the effective user, and single-linked. Unsafe
entries are retained and reported.

Integrations can wire this to `ExecStopPost` in systemd. On macOS, the
ramdisk destruction handles cleanup automatically when the launchd job
stops.

## fetch

Connect to a local Unix socket and write its decrypted value to stdout. This
command is available on Linux and macOS. Connect and read share a five-second
deadline, and the credential payload is capped at 16 MiB. Failed reads produce
no credential output.

```console
$ postmaster fetch /run/postmaster-credd/myapp/DATABASE_URL.sock
$ postmaster fetch --protocol framed --server-uid 0 /run/postmaster-credd/myapp/DATABASE_URL.framed.sock
```

| Flag | Description |
| --- | --- |
| `--protocol raw\|framed` | Socket protocol; defaults to `raw` |
| `--server-uid <uid>` | Expected kernel-reported peer UID; required for `framed`, optional for `raw` |

The UID check runs before any credential bytes are read. It identifies the
listener's account, not an executable. On Linux, socket-activated listeners
report the credentials captured when the service manager called `listen()`,
which can differ from the accepting daemon's user. Configure that
expected identity explicitly.

`raw` reads credential bytes to EOF. An empty or oversized response fails,
but a nonempty response cut short by EOF cannot be distinguished from a
complete shorter secret. `framed` validates the versioned length header,
requires the exact payload and EOF, and rejects partial or extra data. The
configured daemon endpoint must use the same protocol.

The credentials-mode launcher uses this client path on both supported systems.

## help

Print help text for a subcommand or the top-level help. Every
subcommand also accepts `--help`/`-h` directly (`postmaster exec
--help`).

```console
$ postmaster help           # top-level help
$ postmaster help exec       # exec subcommand help
$ postmaster help setup      # setup subcommand help
$ postmaster help cleanup    # cleanup subcommand help
$ postmaster help fetch      # fetch subcommand help
```

## version

```console
$ postmaster --version
$ postmaster -V
```
