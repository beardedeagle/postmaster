# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Remediated all 33 findings of the 2026-08-02 security audit (5 HIGH,
  11 MEDIUM, 17 LOW/INFO — 12 fixed, 4 documented as accepted).
- Bundle entries are now name-bound: a ciphertext decrypts only under its
  own entry name (AES-GCM AAD); relocating it fails authentication.
  Suite bumped to `ecies-secp256k1-hkdf-sha256-aes-256-gcm-entry-aad`;
  pre-AAD bundles are rejected. AAD support comes from the additive
  `encrypt_with_aad`/`decrypt_with_aad` on the ecies fork (upstream PR
  ecies/rs#159), consumed via a git+rev `[patch.crates-io]` pin.
- Hardening: macOS termination-signal deferral across the plaintext-write
  window, with a flag-handler handoff closing the check/exec race (no
  death before exec without cleanup); logged hardening failures; fd-pinned secret-file writes and
  fd-relative prune/cleanup; `O_NOFOLLOW` ciphertext opens;
  sentinel-guarded bulk cleanup (`.postmaster-managed`); keychain reads
  via the Security.framework API (no `/usr/bin/security`); `--verify-keys`
  fails on ANY undecryptable value, including under `strict:false`;
  daemon config rejects unknown fields (root and nested); Linux `id`
  resolved from verified absolute paths only; setup verification reuses
  the runtime key-variable predicate; bundle `encoding: "utf8"` is
  validated at resolution.

### Changed

- Module restructure per file-size limits (500/750/1000 LOC bands):
  `keys/`, `cli/`, `adapter/` domains; conformance suite split under
  `tests/exec_conformance/`.
- Dependencies: base64 0.23 plus the minor/patch set (libc 0.2.189,
  serde family 1.0.229, serde_json 1.0.151, syn 3.0.3).
- CI automation conforms to the repo doctrine: in-repo composites only
  (setup-rust, setup-nix — the latter verifies the pinned installer's
  sha256 before executing), actions pinned by sha, workflows consume
  just recipes.

### Added

- "Unsafe Code" documentation section: exception policy and a registry
  of every unsafe site (signal deferral, macOS libc boundary, systemd fd
  ownership, test-only env mutation).
- `multiple_crate_versions` clippy lint plus `[bans] multiple-versions`
  in deny.toml (syn skipped for the wasm-gated duplicate).

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
