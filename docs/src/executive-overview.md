# Executive overview

A briefing for engineering leadership and product managers on what
postmaster does, where it fits, and which protections depend on the deployment.

## What it is

Postmaster is a Unix tool that decrypts a service's secrets at launch and
delivers them through environment variables, files, or systemd credentials.
Its launcher replaces itself with the service binary. A separate monitor
forwards stop signals and removes secret files when the service exits.

## The problem it solves

Secret delivery can leave plaintext accessible beyond the process that needs it:

- Files on persistent disk can reach backups or remain after a service stops.
- Environment variables can appear in process listings, diagnostics, or dumps.
- A wrapper that stays alive can retain its copy of keys and decrypted values.

Postmaster decrypts at launch and wipes its key ring and resolved buffers
before replacing the launcher. The application still needs access to its
secrets for as long as it uses them.

## Protections and their limits

- **RAM-backed secret files.** Deployments must provide private RAM-backed
  storage for file projections. The monitor removes
  files after service exit, a crash, or `kill -9`, provided the monitor survives.
- **Public ciphertext.** Encrypted artifacts can live in git or a public
  artifact store. Private keys need separate protection, and write access to
  artifacts still controls which values the application receives.
- **Local decryption.** One Rust binary handles decryption and injection.
  It has no remote secret-store client, plugin system, or shell evaluation of
  secret values. The unsafe-code reference records the syscall boundaries.
- **Strict decryption by default.** A decryption failure stops launch.
  `strict: false` allows undecryptable dotenv values to be omitted;
  `--verify-keys` makes those omissions fatal. Bundle decryption always fails
  if an entry cannot authenticate.

## What it does not do

- Vault, SSM, and 1Password keep custody of keys. External tooling delivers
  keys to local sources before Postmaster starts.
- The service manager owns restarts and health checks. Postmaster's monitor
  handles stop-signal forwarding and cleanup.
- The monitor retains the launcher's original environment. Use a file,
  keychain, or credential key source to avoid leaving environment-supplied
  private keys in that process.
- The optional credential daemon is long-lived and retains its key ring to
  decrypt requests. It is separate from the per-service launcher and monitor.

## Operational footprint

- One Rust binary per host; one monitor process per service
  for the service's lifetime.
- Linux with systemd and macOS with launchd. Bindings configure filesystem
  permissions, credential access, RAM-backed storage, and service hardening.
- Rollout is per-service and reversible: postmaster wraps the existing
  launch command.

## Assurance posture

- RustCrypto and released ECIES dependencies provide the cryptographic
  operations. Postmaster owns the bundle's name-bound AAD envelope decoder.
- The conformance suite checks configuration examples and launch behavior.
- The threat model records residual exposure, deployment requirements, and
  the limits of cleanup and memory hardening.

## Where to go next

| Audience | Read |
| -------- | ---- |
| Engineering leadership | This page, then the [Threat model](./architecture/threat-model.md) |
| Product / project management | This page and the [Introduction](./introduction.md) |
| Engineers integrating a service | [Quick start](./getting-started/quick-start.md) |
