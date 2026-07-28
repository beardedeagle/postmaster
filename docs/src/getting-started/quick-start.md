# Quick start

This page shows how to get postmaster running with an encrypted `.env`
file in under 10 minutes.

## Audience Quickstart

**What this is:** a hands-on walkthrough of the simplest path —
encrypting secrets, provisioning keys, and launching a service with
postmaster.

## Prerequisites

- A Rust toolchain (`rustup`, stable)
- [dotenvx CLI](https://github.com/dotenvx/dotenvx) (or any tool producing
  the same ECIES format) for encrypting secrets
- postmaster built from source (or from the Nix flake)

## Step 1: Author secrets

Create a `.env` file and encrypt it:

```console
$ dotenvx set DATABASE_URL 'postgres://user:pass@localhost:5432/myapp' \
    -f secrets/.env.production
$ dotenvx set API_TOKEN 'secret-token-here' \
    -f secrets/.env.production
```

The `.env.production` file now contains encrypted values. It is safe to
commit to git — the ciphertext is public, the private key is the real
secret.

```ini
DOTENV_PUBLIC_KEY="0x04a1b2c3..."
DATABASE_URL="encrypted:BGAAAAAADWzz..."
API_TOKEN="encrypted:BGAAAAAADWyy..."
```

## Step 2: Provision keys

Postmaster needs the private key to decrypt the values. The key lives in
a `.env.keys` file:

```console
$ dotenvx keys -f secrets/.env.production
DOTENV_PRIVATE_KEY_PRODUCTION="a1b2c3d4e5f6..."
```

Place the keys file on the host (Linux):

```console
$ sudo install -d -m 0700 /var/lib/postmaster
$ sudo install -m 0400 /dev/stdin /var/lib/postmaster/.env.keys <<'EOF'
DOTENV_PRIVATE_KEY_PRODUCTION="a1b2c3d4e5f6..."
EOF
```

On macOS, you can also use the keychain:

```console
$ security add-generic-password -a DOTENV_PRIVATE_KEY_PRODUCTION \
    -s postmaster -w "a1b2c3d4e5f6..."
```

## Step 3: Create exec.json

Postmaster reads an `exec.json` config that specifies what to decrypt,
how to inject, and what binary to launch:

```json
{
  "mode": "env",
  "env_files": ["/path/to/.env.production"],
  "keys": [
    {"file": "/var/lib/postmaster/.env.keys"}
  ]
}
```

See the [Launcher contract](../reference/launcher-contract.md) for all
config fields and modes.

## Step 4: Validate config

```console
$ postmaster exec --config exec.json --check
```

This validates the config shape without decrypting, reading key
material, or launching anything. Use it in CI.

To verify key sources are accessible on the host without decrypting:

```console
$ postmaster setup --config exec.json --recheck
```

## Step 5: Launch

```console
$ postmaster exec --config exec.json -- /usr/bin/env
DATABASE_URL=postgres://user:pass@localhost:5432/myapp
API_TOKEN=secret-token-here
```

Postmaster decrypted the values, injected them as environment variables,
and `execvp`'d `/usr/bin/env` — which printed them. In a real deployment,
the service manager (systemd or launchd) runs postmaster, which
replaces itself with your binary.

```mermaid
flowchart TB
    cfg["exec.json"]
    env["encrypted .env"]
    keys[".env.keys"]
    pm["postmaster exec"]
    child["your binary"]

    cfg --> pm
    env --> pm
    keys --> pm
    pm -->|decrypt and inject| child
    pm -.->|execvp| child
```

## Next steps

- [CLI reference](../reference/cli.md) — all commands, flags, and exit
  codes
- [Launcher contract](../reference/launcher-contract.md) — the full
  `exec.json` specification
- [Threat model](../architecture/threat-model.md) — what postmaster
  protects and what it cannot prevent
