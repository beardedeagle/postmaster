# Materialization ABI

`postmaster` is the local secret materialization engine. Its ABI is the
contract between public deployment artifacts, local private key material,
and the process that receives plaintext at runtime.

## Audience quickstart

Deployment integrations generate local inputs for Postmaster. This contract
defines those inputs, key sources, resolution rules, and output projections.

### Who this is for

| Reader | What to take |
| -------- | ------------ |
| Integration author | The entire page — this is your contract |
| Security engineer | "Non-goals" and "Resolution" |
| New user | "Current ABI instance" and the exec.json example |
| Platform / SRE | "Key sources" and "Validation" — what the host needs |

### Quick glossary

| Term | Plain meaning |
| ------ | --------------- |
| **ABI** | Application Binary Interface — the contract between config files, key material, and the launcher |
| **exec.json** | A JSON file that selects inputs, key sources, and projection mode. The launch command is supplied separately after `--`. |
| **Projection** | Where decrypted secrets go — env vars, files, or systemd credentials |
| **Adapter** | An input format (.env, postmaster_bundle) — postmaster supports multiple, not just one |

The ABI is deliberately local:

- encrypted secret artifacts may be public and declarative
- private key material arrives through local terminal sources
- `postmaster` decrypts and projects plaintext on the host
- plaintext is handed to the target process through one selected projection
- required validation and decryption checks finish before `exec`

This page describes the ABI and how `exec.json` fits inside it. It is a
contract for bindings and documentation recipes. Remote provider clients
belong in the delivery tooling, outside `postmaster`.

## Non-goals

`postmaster` must not become:

- an AWS SSM client
- a Vault client
- a Terraform/OpenTofu/CDK/Ansible/Salt/Puppet plugin host
- a general remote secret-store SDK wrapper
- a process that fetches secrets over the network in the secret path

Vault, AWS SSM, 1Password, and other centralized stores are source or
custody systems. Automation tools (Nix, CDK, Ansible, SaltStack, Puppet,
Terraform, OpenTofu) are renderers and installers. Their job is to deliver
local artifacts, local key material, config, and service wiring around the
ABI. Runtime decrypt and injection remain inside `postmaster`.

## Contract layers

The ABI has five layers.

```mermaid
flowchart TD
    art["(1) Artifact descriptors<br/>identify encrypted local inputs"]
    key["(2) Key-source descriptors<br/>identify local private key material"]
    res["(3) Resolution rules<br/>turn encrypted entries into plaintext"]
    proj["(4) Projection policy<br/>decides where bytes appear"]
    launch["(5) Launch semantics<br/>execvp replaces postmaster with target"]

    art --> res
    key --> res
    res --> proj
    proj --> launch
```

1. Artifact descriptors identify encrypted local inputs.
2. Key-source descriptors identify local private key material.
3. Resolution rules turn encrypted entries into named plaintext byte values.
4. Projection policy decides where those bytes may appear.
5. Launch semantics replace the wrapper process with the target command only
   after validation and materialization succeed.

All ABI data intended for generated config must be safe to store in the Nix
store or an equivalent world-readable deployment artifact. Secret bytes and
private keys are never config fields.

## Current ABI instance

`exec.json` is the first ABI instance. It is implicitly:

- ABI version: `0`
- input adapters: `.env` and `postmaster_bundle`
- artifact fields: `env_files` and `bundle_files`
- key variables: `DOTENV_PRIVATE_KEY*` for dotenv, `POSTMASTER_KEY` for bundles
- projection modes: `env`, `files`, and `credentials`

The current parser does not accept explicit `version` or `adapter` fields.
Bindings must not emit those fields until the Rust parser and schema define
them.

The current shape is:

```json
{
  "mode": "files",
  "keys": [{ "credential": "postmaster-myapp" }, "environment"],
  "env_files": ["/nix/store/.../.env.production"],
  "strict": true,
  "overload": false,
  "secrets_dir": "/run/postmaster",
  "passthrough": ["RUST_LOG"]
}
```

`env_files` are encrypted `.env` files, wire-compatible with dotenvx. They
must follow the `.env[.<environment>]` basename convention because the
filename selects the private key variable:

- `.env` maps to `DOTENV_PRIVATE_KEY`
- `.env.production` maps to `DOTENV_PRIVATE_KEY_PRODUCTION`
- environment names must be non-empty `[A-Za-z0-9_]` (letters fold to
  upper case); anything else is rejected

The bundle adapter below provides another input format under the same
projection contract.

## Neutral bundle adapter

The `postmaster_bundle` adapter reads structured JSON artifacts alongside
dotenv inputs. Producers can represent binary and UTF-8 entries without
encoding their native data model as a dotenv file.

The on-disk format is a JSON container. JSON keeps generated artifacts easy
for Terraform, OpenTofu, CDK, Ansible, Salt, Puppet, and Nix to render and
diff, while encrypted values remain opaque base64 strings.

```json
{
  "format": "postmaster.bundle",
  "version": 1,
  "profile": "production",
  "suite": "ecies-secp256k1-hkdf-sha256-aes-256-gcm-entry-aad",
  "recipients": [
    {
      "id": "host:api-01",
      "public_key": "02..."
    }
  ],
  "entries": {
    "DATABASE_URL": {
      "encoding": "utf8",
      "ciphertext": "base64..."
    },
    "TLS_KEY": {
      "encoding": "bytes",
      "ciphertext": "base64..."
    }
  }
}
```

All fields above are public metadata except `ciphertext`, which is encrypted
and authenticated. Each entry's ciphertext is additionally bound to its key
name as AES-GCM additional authenticated data (the `-entry-aad` suite): a
store or repo adversary who cuts a ciphertext from one entry and pastes it
under another key name gets an authentication failure at decryption, not a
mislabeled secret.

The decoded envelope is a 65-byte uncompressed secp256k1 ephemeral public key,
a 16-byte nonce, a 16-byte authentication tag, then ciphertext. HKDF-SHA256
uses the uncompressed ephemeral and shared points, matching `ecies` defaults.
The entry name's exact UTF-8 bytes are the AAD; plaintext is returned only
after AES-256-GCM authentication succeeds.

The remaining metadata, including profile, recipient IDs, and encodings, is
not cryptographically bound. A format that authenticates those fields would
need canonical serialized bytes for reproducible builds and stable vectors.

The design constraints are:

- `format` and integer `version` are mandatory and fail closed on unknown
  values.
- `suite` is mandatory so cryptographic suites can be explicit rather
  than inferred from payload length.
- `profile` and `recipients` are public metadata. They are parsed but do not
  select local private keys or filter entries.
- Private key material comes from the `POSTMASTER_KEY` variable:
  comma-separated rotation candidates are admitted, and
  `POSTMASTER_KEY_<suffix>` variants match by the same predicate as
  `DOTENV_PRIVATE_KEY_*`. There is no per-environment filename mapping —
  bindings select bundle paths through `bundle_files`.
- `entries` keys must use the same identifier rule as `.env`-derived keys:
  `[A-Za-z_][A-Za-z0-9_]*`.
- `encoding` is either `utf8` or `bytes`. A `utf8` entry must decrypt to valid
  UTF-8. Env projection rejects NUL bytes; files preserve byte-exact values.
- Bundles are accepted in `env` and `files` modes. The credential daemon
  resolves dotenv entries; `credentials` mode does not accept `bundle_files`.
- A bundle can contain many entries for one projection, but it does not
  encode service-manager policy. Projection remains in the `postmaster`
  config, not inside the encrypted artifact.

The bundle preserves the same runtime invariants: local-only resolution,
no network egress, no plaintext config fields, deterministic failure before
launch, and the same output projection semantics as `.env` values.

The implementation ships with conformance vectors for:

- minimal valid bundle
- invalid key name
- unknown version
- tampered `format`/`version`/`suite` values (fail-closed parsing)
- wrong local private key
- replayed ciphertext under a different entry name

## Key sources

Implemented launcher key sources are local and terminal:

- `{"credential": "<name>"}` reads from `$CREDENTIALS_DIRECTORY/<name>` and
  is skippable when absent, so generated configs can fall through to another
  source. The name must be a single relative path component.
- `{"file": "/path/to/.env.keys"}` reads a local file and fails closed if the
  file is unavailable or under `/nix/store`.
- `{"keychain": "<service>"}` reads from macOS Keychain and is terminal.
- `"environment"` reads the required adapters' private-key variables from the
  process environment and is terminal.

Provider names such as `aws_ssm` and `vault` are reserved contract language,
but they are not implemented key sources. A Vault Agent, cloud-init step,
systemd oneshot, `systemd-creds` workflow, or platform bootstrap process can
fetch or seal material before launch and hand it to one of the implemented
local sources.

## Resolution

Resolution must:

- parse every configured encrypted artifact before launching the target
- build the wanted private-key set from configured artifact names and formats
- load key material from the ordered local sources
- decrypt with the selected adapter
- reject malformed key names
- respect `strict` fail-closed behavior
- respect `overload` precedence
- keep plaintext out of stdout, generated config, and persistent public
  artifacts

For the `.env` adapter, this is implemented by `resolve_all` and the same
native ECIES path used by the credential daemon.

`strict: false` permits undecryptable dotenv values to be logged and omitted.
`--verify-keys` rejects those omissions. Bundle authentication always fails
closed, independent of `strict`.

## Diagnostics and redaction

Failures identify the field, artifact, key name, or projection that failed
without printing decrypted values, private keys, or secret-bearing command
output. Diagnostics may include public paths, key names, mode names, source
kinds, and parser errors. They must not include plaintext secret bytes,
`.env.keys` contents, ECIES private keys, or values fetched from postmaster
sockets.

Bindings follow the same rule. Generated validation logs and CI output can
show which config failed and why, but not the material that would allow
decryption or disclose the decrypted result.

## Projection modes

Projection modes are shared ABI behavior.

### `env`

All resolved values are exported as real environment variables, then the
target command is executed directly. Values containing NUL bytes are rejected
because POSIX environment variables cannot carry them safely.

### `files`

Each resolved value is written as a `0600` file under `secrets_dir`.
`postmaster` exports `<KEY>_FILE` pointers for each secret.

The deployment must supply RAM-backed storage. The launcher does not establish
RAM backing when `verify_ramdisk` is absent.

The launcher refuses to follow symlinks when writing secret files. On macOS,
when `verify_ramdisk` is set, it verifies the configured mount and the opened
directory's device and ownership before writing plaintext.

`passthrough` may additionally export selected keys as real environment
variables. Passthrough values containing NUL bytes are rejected.

### `credentials`

On systemd, PID 1 has already materialized credentials and the launcher only
exports `<KEY>_FILE` pointers into `$CREDENTIALS_DIRECTORY`.

When `sockets` is configured, the launcher fetches values from local
Postmaster sockets, writes them beneath `secrets_dir`, and exports
credential-style pointers. This path is normally used with launchd. RAM
backing is verified only when `verify_ramdisk` is set on macOS.

Every `credential_keys` entry must be a valid identifier before any fetch or
write occurs.

## Validation

The ABI needs two validation surfaces:

- JSON Schema for generated config and documentation fixtures
- `postmaster exec --check` for parser-authoritative structural validation

The current `exec.json` schema lives at `docs/schema/exec.schema.json`.
Fixture examples live under `docs/examples/` and are exercised by the Rust
test suite, so documentation examples cannot silently drift from the parser.

`--check` reads only the config file. It rejects malformed JSON, unknown
fields, unknown modes or key-source kinds, missing mode-required fields,
invalid env-file basenames, invalid identifier fields, forbidden
private-key paths under `/nix/store`, and incomplete credential socket maps.
It does not resolve keys, decrypt values, read local key files, inspect
`secrets_dir`, probe sockets, mount-check ramdisks, contact remote systems, or
depend on host-specific secret state. That makes it suitable for CI and for
automation tools that want to validate generated config before deployment.

**Limitation:** `--check` validates config shape only, not key source
accessibility. A config can pass `--check` in CI but fail at runtime because
the key file is missing, the keychain item is absent, or the credential
source is not provisioned. The launcher's fail-closed behavior is the
runtime guarantee; `--check` cannot substitute for it.

`postmaster setup --config <exec.json> --recheck` checks local provisioning
without decrypting secrets. File sources receive descriptor-based ownership,
permission, and macOS ACL checks. Credential sources receive path-presence and
regular-file checks. Keychain checks look for the required items; environment
checks look for required variables. These checks do not prove that the keys
can decrypt the configured inputs. Run `--check` in CI for config shape and
`setup --recheck` on the host for provisioning checks.

The full `postmaster setup` command goes beyond verification: it
creates the keys directory with 0700 permissions, verifies or creates
key files with owner-only permissions, and optionally seeds macOS Keychain
items interactively. It derives a unique required-account list in first-seen
input order. Steps already satisfied are skipped.
Flags: `--recheck` (verification only), `--unattended` (non-interactive,
fail closed), `--force` (re-create/re-seed), `--keys-dir <path>` (override
default path).

## Integration responsibilities

Bindings and recipes are correct when they produce local ABI inputs and prove
them before launch.

Source or custody systems should document:

- where private key material lives
- how it is delivered to a local terminal source
- rotation behavior
- audit behavior
- failure behavior

Automation systems should document:

- how encrypted artifacts are installed
- how `exec.json` or its successor is rendered
- how service manager wiring invokes `postmaster`
- how `postmaster exec --check` is run
- how plaintext persistence is avoided

No integration should reimplement decrypt/inject semantics. If an external
tool needs to participate, it should chain through the ABI.

## Conformance

Each supported adapter has conformance fixtures:

- valid minimal config
- valid full config per projection mode
- invalid unknown source kind
- invalid unknown mode
- invalid identifier
- missing required mode fields
- adapter-specific malformed artifact
- strict undecryptable value behavior
- precedence behavior for `overload`

Provider or automation repositories claim compatibility by showing that
their generated artifacts pass the schema, `--check`, and the shared fixture
suite without adding provider logic to `postmaster`.
