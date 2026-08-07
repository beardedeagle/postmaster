# Executive overview

A one-page briefing on postmaster for engineering leadership and
product/project management. No code, no commands — what it is, why it
exists, and what it does and does not promise.

## What it is

postmaster is a small, single-purpose Unix tool that decrypts a
service's secrets at launch time and hands them directly to the
service — then removes itself from the picture. It replaces the common
practice of shell scripts or long-lived helper processes holding
plaintext secrets in memory for the service's entire lifetime.

## The problem it solves

Most deployments get secrets to production one of a few ways, and each
leaves plaintext somewhere an incident can reach it:

- **Plaintext files on disk** — readable by any process, any backup
  job, any accidental `cat` in a debugging session.
- **Deploy-time environment variables** — visible in process listings,
  unit files, and crash dumps.
- **Wrapper scripts and parent processes** — keep decrypted secrets in
  a long-lived process's memory for as long as the service runs.

The common thread is plaintext with a long lifetime and a wide blast
radius. postmaster's entire design is collapsing that lifetime to
microseconds and that radius to one process.

## What it guarantees

- **No plaintext at rest.** Decrypted secrets exist only in memory,
  in the moments between decryption and launch. Where a deployment
  mode needs files, they live on a ramdisk and are deleted on every
  service-death path — including `kill -9` — by a dedicated monitor
  process.
- **Ciphertext is safe to publish.** Encrypted secret files can live
  in git or a world-readable artifact store; only one 64-character
  private key per environment needs protection, and it can itself be
  sealed to the host (TPM2) or held in the macOS keychain.
- **Small, auditable surface.** One dependency-lean Rust binary, no
  network client, no plugin system, no shell in the runtime path.
  Every `unsafe` block is catalogued with its justification and
  mitigations.
- **Fail closed.** A missing key, a stale key, or a malformed config
  stops the launch loudly and names the problem — a service never
  starts with partial or wrong secrets.

## What it does not do

- It is not a secret store and does not replace Vault, SSM, or
  1Password — those systems keep custody of keys. postmaster is the
  last hop, and it will never grow a network client for them.
- It does not supervise services (restarts, health checks) — that
  stays with systemd/launchd. Its tiny monitor process handles only
  stop-signal forwarding and secret cleanup.
- It does not hold secrets over time: the process that decrypted them
  is gone the moment the service binary starts.

## Operational footprint

- One small Rust binary per host; one tiny monitor process per service
  for the service's lifetime.
- Linux (systemd) and macOS (launchd); no kernel modules, no network
  calls, no privileges beyond what the service itself needs.
- Rollout is per-service and reversible: postmaster wraps the existing
  launch command.

## Assurance posture

- Pure-Rust cryptography — no openssl in the binary.
- An executable conformance suite mirrors the documented launch
  contract, so documented behavior is tested behavior.
- Every finding from the 2026-08 security audits is fixed and listed
  in the changelog with its finding ID.

## Where to go next

| Audience | Read |
| -------- | ---- |
| Engineering leadership | This page, then the [Threat model](./architecture/threat-model.md) |
| Product / project management | This page and the [Introduction](./introduction.md) |
| Engineers integrating a service | [Quick start](./getting-started/quick-start.md) |
