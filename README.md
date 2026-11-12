# postmaster

Postmaster decrypts local secret inputs at process launch and delivers values
through environment variables, files, or systemd credentials. It then replaces
the launcher with your binary through `execvp`.

The first input adapter is wire-compatible with
[dotenvx](https://github.com/dotenvx/dotenvx)-encrypted `.env` files (same
ECIES/secp256k1 + HKDF-SHA256 + AES-256-GCM crypto path), so existing
`.env` files encrypted with the dotenvx CLI decrypt through Postmaster's
native Rust implementation. Postmaster also reads encrypted
`postmaster_bundle` JSON files. External systems such as Vault, AWS SSM,
and 1Password can deliver private keys to its local key sources before launch.

Deployment tools such as Nix, AWS CDK, Ansible, SaltStack, Puppet, Terraform,
and OpenTofu can generate the same `exec.json` contract. Postmaster doesn't
fetch secrets from those tools or remote stores.

Encrypted values can be public: each value is ECIES/secp256k1-encrypted,
and the embedded public key permits encryption but not decryption.
Encrypted env files can ship in the Nix closure and roll back with the
generation. Keep private keys separate and protect artifact write access:
anyone with the public key can encrypt replacement values. Plaintext
passthrough entries are public too, so they must not contain secrets in a
public artifact.

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

Postmaster decrypts natively and replaces the launcher with your binary.
Deployments must provide RAM-backed storage for secret files and configure
swap and dump protections. A hand-written `files` config without
`verify_ramdisk` does not establish that its directory is RAM-backed.

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

**`mode = "env"`.** Postmaster exports resolved values into the application
environment and replaces the launcher with your binary.

**`mode = "files"`.** Values are written one-file-per-key onto a
namespace-private tmpfs (`TemporaryFileSystem=/run/postmaster`; on macOS,
a per-service directory on an HFS RAM disk) and only `<KEY>_FILE` pointer
variables are exported by default, following the Docker-secrets convention.
`passthrough` also exports selected values. File-only projected secrets are
absent from environ, `ps e`, crash-dump environment sections, and
ambient child inheritance.

**`mode = "credentials"`.** The launcher exports pointers to credentials
that systemd has already supplied, or fetches them from configured local
Postmaster sockets. With daemon-backed systemd delivery, the consumer gets
`LoadCredential=<KEY>:/run/postmaster-credd/<svc>/<KEY>.sock` per key and
the app reads `$CREDENTIALS_DIRECTORY/<KEY>` from unit-private, unswappable
ramfs. The deployment controls credential storage and access.

## Key sources

Postmaster reads private keys from four local sources:

- **systemd credentials** (`LoadCredential=`) — PID 1 places key material
  in `$CREDENTIALS_DIRECTORY` before postmaster starts. Includes
  TPM2/host-sealed credentials via `LoadCredentialEncrypted=`.
- **Files** — a `.env.keys`-format file on local disk (not in the Nix
  store)
- **macOS Keychain** — key material stored as generic-password items,
  read natively by postmaster via the Security.framework API
- **Environment** — `DOTENV_PRIVATE_KEY*` variables in the process
  environment (set by the service manager); bundle configs use
  `POSTMASTER_KEY` instead

## Integration

Postmaster is the local secret materialization stage in a 5-stage
pipeline: custody (Vault/SSM/1Password/TPM2) → rendering (Nix/Terraform/
CDK/Ansible/Salt/Puppet) → delivery (credentials/files/keychain/env) →
materialization (postmaster) → launch (execvp). Each stage has a separate
responsibility. Postmaster handles local materialization and the handoff to
the target process. The
stage-by-stage breakdown lives in
[The secret pipeline](docs/src/architecture/postmaster.md#the-secret-pipeline).

The `exec.json` contract and `postmaster exec --check` conformance suite
are the interface between postmaster and every integration. An
integration must emit configs accepted by `--check` and verify its launch
behavior against the conformance suite. Host permissions, key availability,
and service-manager wiring need separate validation.

## Documentation

Full documentation is in the [docs/](docs/) directory, buildable with
[mdBook](https://rust-lang.github.io/mdBook/):

```console
$ just docs-serve
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

Source builds require Rust 1.99.1 or newer. `just build-help` lists the
optimization levels and cross-compilation targets.

[Release instructions](docs/src/development/releases.md) cover attested
checksums and archives, binary installation, and tag or manual
publication.

Cross builds use `cargo zigbuild` and require the Rust target, `cargo-zigbuild`,
and Zig to be installed; Darwin cross builds also require a macOS SDK.
The matrix preserves compiler flags and profile environment overrides. Its
`max` level remaps checkout and Cargo registry source paths in build outputs.

With Nix:

```console
$ nix build
$ nix flake check
```

The flake exports packages and an overlay. Service-manager bindings live in
deployment integrations; they must render `exec.json` and configure storage,
permissions, cleanup, and hardening.

## License

MIT
