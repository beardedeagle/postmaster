# CLI reference

All postmaster commands, flags, and exit codes. The CLI is hand-rolled
with no external parsing library — every flag below is the complete
set, directly from the argument parser in `cli/mod.rs`.

## Synopsis

```console
$ postmaster --config <file.json> [--bind] [--allow-nonroot]
$ postmaster exec --config <exec.json> [--check] [--verify-keys] -- <command> [args…]
$ postmaster setup --config <exec.json> [--recheck] [--unattended] [--force] [--keys-dir <path>]
$ postmaster cleanup --config <exec.json>
$ postmaster fetch <socket-path>
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
- `--check` combined with `--verify-keys` silently ignores verification —
  check validates the config shape and never decrypts.
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

Create keys directory, verify permissions, optionally seed keychain
(macOS), validate environment. Idempotent — skips steps that are
already correct.

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

Default keys directory:

- Linux: `/var/lib/postmaster`
- macOS: `~/Library/Application Support/postmaster` (falls back to
  `/var/lib/postmaster` when `HOME` is unset)

## cleanup

Remove plaintext secret files from the secrets directory after the
child exits.

```console
$ postmaster cleanup --config <exec.json>
```

| Flag | Description |
| --- | --- |
| `--config <path>` | Path to `exec.json` (reads `secrets_dir` from config) |

Safety guard: cleanup refuses to bulk-delete a **non-empty** directory
that lacks the `.postmaster-managed` sentinel file (dropped by postmaster
when it writes there) — a misconfigured `secrets_dir` can never wipe a
directory postmaster doesn't manage. Empty or missing directories are
fine.

Integrations can wire this to `ExecStopPost` in systemd. On macOS, the
ramdisk destruction handles cleanup automatically when the launchd job
stops.

## fetch

macOS credential fetch client — connects to a postmaster socket and
reads the decrypted value to EOF. Reads are hard-capped at 16 MiB;
an oversize stream fails rather than truncates.

```console
$ postmaster fetch /run/postmaster-credd/myapp/DATABASE_URL.sock
```

Used internally by the wrapper in credentials mode on macOS. Not
typically called directly.

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
