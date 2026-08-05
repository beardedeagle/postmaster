# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-28

### Added

- Standalone postmaster binary — a format-neutral local secret
  materialization engine that decrypts encrypted inputs at process
  launch time, injects them into a child process, and `execvp`s the
  target binary.
- `.env` input adapter — wire-compatible with dotenvx-encrypted `.env`
  files (ECIES/secp256k1 + HKDF-SHA256 + AES-256-GCM).
- `postmaster_bundle` JSON container format as a second input adapter.
- `KeyNaming` enum (Env, Bundle) for compile-time exhaustive adapter
  dispatch — zero vtable overhead, controlled adapter set.
- Three injection modes: `env` (environment variables), `files`
  (one-file-per-secret on RAM-backed filesystem), `credentials`
  (systemd credentials via postmaster daemon).
- Four key sources: systemd credentials (`LoadCredential=`), files
  (`.env.keys` on disk), macOS keychain, environment variables.
- `postmaster exec --check` for config shape validation (CI).
- `postmaster setup --recheck` for runtime key source verification
  (host).
- `postmaster setup` interactive command — idempotent, creates keys
  directory, verifies permissions, optionally seeds keychain (macOS).
- `postmaster cleanup --config <exec.json>` subcommand for plaintext
  secret file removal. Wired to `ExecStopPost` in systemd.
- `--verify-keys` flag on `exec` for stale key detection after rotation.
- `OFlags::CLOEXEC` on all `rustix::fs::open` call sites.
- RAM backing verification via `hdiutil info` on macOS.
- Pre-execvp zeroization of `KeyRing` and `Resolved` values.
- Symlink rejection at every secret path: `O_NOFOLLOW`, `fstat`,
  `symlink_metadata`, `fchmod` on socket fd.
- External binary verification: `codesign -v` on macOS, root-owned
  check on Linux.
- Input validation: NUL byte rejection, path traversal rejection,
  identifier validation, no shell expansion invariant.
- Threat model documentation covering memory residency, hardening
  inheritance across execvp, and the 5-stage secret pipeline.
- Nix flake with rust-overlay for hermetic builds independent of
  nixpkgs channel rustc version.
- `preventSwap` defaults to `true` — per-service `MemorySwapMax=0`.
- Child reads secrets via `$KEY_FILE` pointers (Docker secrets /
  systemd credentials / 12-factor `_FILE` convention).
- `verify_key_freshness` uses `KeyNaming::Env.metadata_prefix()`.
- Two security audits conducted (provider handoff + destination
  handoff), all findings fixed.
- Memory hardening audit conducted, all findings fixed.
- 12 verified-safe security properties documented in the threat model.
