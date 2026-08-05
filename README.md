# postmaster

**postmaster** is a standalone, format-neutral local secret
materialization engine. It decrypts encrypted secret inputs at process
launch time and injects them into a child process via environment
variables, files, or systemd credentials — then `execvp`s your binary
directly. No Node, no shell, no separate CLI process in the runtime path.

The first input adapter is wire-compatible with
[dotenvx](https://github.com/dotenvx/dotenvx)-encrypted `.env` files (same
ECIES/secp256k1 + HKDF-SHA256 + AES-256-GCM crypto path), so existing
`.env` files encrypted with the dotenvx CLI decrypt byte-exact through
postmaster's native Rust implementation. dotenvx is one adapter, not the
ceiling — the architecture supports file-based (`.env`), HashiCorp Vault,
AWS SSM, and other secret providers (1Password, etc.) as source/custody
backends.

Postmaster works with Nix, AWS CDK, Ansible, SaltStack, Puppet,
Terraform, and OpenTofu as deployment automation targets, all sharing
the same `exec.json` contract.

The trick that makes this compose: the ciphertext is *designed* to be
public. Every value is ECIES/secp256k1-encrypted individually, and the
embedded public key only permits encrypting *new* values. So the
world-readable Nix store — normally the reason secrets and Nix don't
mix — stops being an adversary. Encrypted env files ship inside the
closure, deploy atomically, roll back with the generation, and the
entire secret surface collapses to one 64-hex private key per
environment.

Runtime flow per service (systemd path):

```text
1. Nix store holds the encrypted .env file (ciphertext, public)
        ↓
2. systemd LoadCredential= places key material in $CREDENTIALS_DIRECTORY
   (ramfs, unit-private, unswappable)
        ↓
3. ExecStart runs: postmaster exec --config <exec.json>
   postmaster reads the encrypted file, decrypts with ECIES,
   injects secrets as env vars or files on a private tmpfs
        ↓
4. postmaster calls execvp — process image replaced with your binary
   MainPID = your binary from its first instruction
```

macOS runs the same flow under launchd, with a RAM disk replacing the
private tmpfs.

Plaintext never touches persistent disk. Postmaster decrypts natively
and `execvp`s your binary directly from the same process
image — no Node, no separate CLI process, no shell in the startup path.

## CLI

```console
$ postmaster exec --config <exec.json> -- <command> [args…]
$ postmaster exec --config <exec.json> --check
$ postmaster exec --config <exec.json> [--verify-keys] -- <command> [args…]
$ postmaster setup --config <exec.json> [--recheck] [--unattended] [--force] [--keys-dir <path>]
$ postmaster cleanup --config <exec.json>
$ postmaster --version
$ postmaster --help
```

- `exec` — decrypt and inject secrets, then `execvp` the target binary
- `exec --check` — validate config shape only (no decryption, for CI)
- `exec --verify-keys` — preflight decryption to catch stale keys
- `setup` — create keys directory, verify permissions, optionally seed
  keychain (macOS), validate environment. Idempotent.
- `setup --recheck` — verify key source accessibility without decrypting
- `cleanup` — remove plaintext secret files after child exits

## Injection modes

**`mode = "env"` (default).** Decrypted values are exported into the
process environment and the wrapper `exec`s your binary. Correct for
12-factor apps.

**`mode = "files"`.** Values are written one-file-per-key onto a
namespace-private tmpfs (`TemporaryFileSystem=/run/postmaster`; on macOS,
a per-service directory on an HFS RAM disk) and only `<KEY>_FILE` pointer
variables are exported — the Docker-secrets convention. Secrets are
absent from environ, `ps e`, crash-dump environment sections, and
ambient child inheritance.

**`mode = "credentials"`.** Real systemd credentials, served on demand by
the postmaster daemon. The consumer's unit gets
`LoadCredential=<KEY>:/run/postmaster-credd/<svc>/<KEY>.sock` per key and
the app reads `$CREDENTIALS_DIRECTORY/<KEY>` from unit-private, unswappable
ramfs. Strongest hygiene of the three.

## Key sources

Postmaster reads private keys from local terminal sources only — it never
fetches from remote systems:

- **systemd credentials** (`LoadCredential=`) — PID 1 places key material
  in `$CREDENTIALS_DIRECTORY` before postmaster starts. Includes
  TPM2/host-sealed credentials via `LoadCredentialEncrypted=`.
- **Files** — a `.env.keys`-format file on local disk (not in the Nix
  store)
- **macOS Keychain** — key material stored as generic-password items,
  read natively by postmaster via the Security.framework API
- **Environment** — `DOTENV_PRIVATE_KEY*` variables in the process
  environment (set by the service manager)

## Integration

Postmaster is the local secret materialization stage in a 5-stage
pipeline: custody (Vault/SSM/1Password/TPM2) → rendering (Nix/Terraform/
CDK/Ansible/Salt/Puppet) → delivery (credentials/files/keychain/env) →
materialization (postmaster) → launch (execvp). Each stage is owned by a
different system; postmaster owns exactly materialization.

The `exec.json` contract and `postmaster exec --check` conformance suite
are the interface between postmaster and every integration. An
integration is correct if and only if the `exec.json` it emits passes
`--check` and the conformance suite.

## Documentation

Full documentation is in the [docs/](docs/) directory, buildable with
[mdBook](https://rust-lang.github.io/mdBook/):

```console
$ mdbook serve docs
```

See [docs/src/SUMMARY.md](docs/src/SUMMARY.md) for the table of contents.

## Building

```console
$ just build           # debug build
$ just test            # run tests
$ just clippy          # lint
$ just fmt-check       # format check
$ just ci-rust         # all of the above in one command
$ just build-matrix max macos-arm  # optimized release
```

See `just build-help` for the full build matrix (optimization levels
and cross-compilation targets).

With Nix:

```console
$ nix build
$ nix flake check
```

## License

MIT
