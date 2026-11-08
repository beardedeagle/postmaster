# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Launched applications no longer inherit private-key variables from either
  adapter namespace, regardless of key source or projection mode. Bundle
  entries using reserved private-key names are rejected before launch.
- Bundle entries are now name-bound: a ciphertext decrypts only under its
  own entry name (AES-GCM AAD); relocating it fails authentication.
  Suite bumped to `ecies-secp256k1-hkdf-sha256-aes-256-gcm-entry-aad`;
  pre-AAD bundles are rejected. Postmaster owns the compatible AAD envelope
  decoder, using released `ecies` curve/HKDF helpers and RustCrypto AES-GCM.
- Hardening: a sibling launch monitor now owns stop semantics on the
  exec path — the launcher forks after zeroization, the parent execs the
  service (MainPID unchanged), and the fork-child supervises it:
  synchronous stop-signal forwarding with a fixed 250 ms grace before
  SIGKILL escalation, pidfd/kqueue liveness, and plaintext-file cleanup
  on EVERY service-death path (natural exit, `kill -9`, crash) — the
  macOS termination-signal deferral across the plaintext-write window
  remains, while the sigaction flag-handler and second pre-exec gate are
  retired (the monitor subsumes the race; fork(2) on Linux is the one
  libc FFI call there, review-gated); logged hardening failures;
  fd-pinned secret-file writes and fd-relative prune/cleanup;
  `O_NOFOLLOW` ciphertext opens; sentinel-guarded bulk cleanup
  (`.postmaster-managed`); keychain reads via the Security.framework API
  (no `/usr/bin/security`); `--verify-keys` fails on ANY undecryptable
  value, including under `strict:false`; daemon config rejects unknown
  fields (root and nested); Linux `id` resolved from verified absolute
  paths only; setup verification reuses the runtime key-variable
  predicate; bundle `encoding: "utf8"` is validated at resolution.
- Hardening: redacted `Debug` on `KeyRing` and `Resolution` (latent
  key-material/plaintext leak channels); env key loading skips non-UTF-8
  entries instead of panicking under panic=abort; credential-source
  stat errors are terminal rather than fall-through; `setup --force` is
  real (keychain re-seed, keys-file re-prompt; force+unattended fails
  closed); daemon refuses a symlinked socket parent and non-absolute
  config paths, and rejects empty credentials at preflight;
  `--allow-nonroot` no longer overrides a configured `peer_user` ACL;
  ramdisk verification enforces lexical path containment; NUL in an
  env-bound bundle value is a hard error under any strictness (one rule
  for every env-bound value).

### Changed

- Build matrix preserves compiler flags and profile environment overrides,
  uses `cargo zigbuild` for cross builds, and remaps source paths at `max`.
  Help describes the configured release profile without performance estimates.
- Bundle files follow the same first-file-wins precedence as dotenv inputs;
  `overload` selects the last definition. Dotenv files precede bundle files.
- Module restructure per file-size limits (500/750/1000 LOC bands):
  `keys/`, `cli/`, `adapter/` domains; conformance suite split under
  `tests/exec_conformance/`.
- Dependencies: base64 0.23.1, ecies 0.2.13, serde 1.0.229,
  serde_json 1.0.154, zeroize 1.9.1, rustix 1.1.6, and libc 0.2.191.
  The ECIES git patch is replaced by registry releases; AES-GCM 0.11.1
  provides bundle authentication with key-schedule zeroization enabled.
- CI automation conforms to the repo doctrine: in-repo composites only
  (setup-rust, setup-nix — the latter verifies the pinned installer's
  sha256 before executing), actions pinned by sha, workflows consume
  just recipes.
- Monitor tests extracted to `src/monitor/tests.rs` (`monitor.rs`
  797 → 503 lines, same module path and visibility).
- Markdown linting consolidated into `.markdownlint-cli2.jsonc` (cli2
  never read `.markdownlintignore`); the two dead config files were
  deleted and `just lint-md` (pinned markdownlint-cli2) now gates in
  lefthook pre-commit, with `deny`+`audit` in pre-push.
- CI housekeeping: the duplicated `deny` job left ci.yml (security.yml
  owns it), security.yml's path filters include the workflow file
  itself, the docs job installs a pinned mdbook/mdbook-mermaid, and
  cargo-deny/cargo-audit installs are version-pinned.
- `ci-rust` now includes `clippy-release` and `clippy-linux` recipes,
  and rust-toolchain.toml pins the `x86_64-unknown-linux-gnu` target.

### Added

- "Unsafe Code" documentation section: exception policy and a registry
  of every unsafe site (signal deferral, macOS libc boundary, systemd fd
  ownership, test-only env mutation).
- `multiple_crate_versions` clippy lint plus `[bans] multiple-versions`
  in deny.toml (syn skipped for the wasm-gated duplicate).
- Daemon end-to-end conformance (`tests/exec_conformance/daemon.rs`):
  the real binary under `--bind --allow-nonroot`, a real `fetch`
  roundtrip with a socket-mode assertion, and preflight refusal before
  any bind.
- Regression coverage across secret-handling edges: the `read_capped`
  cap boundary, symlink refusal end-to-end (env file, bundle file,
  secrets dir), execvp-failure cleanup leaving only the sentinel,
  passthrough-NUL cleanup, bundle precedence and NUL semantics,
  provisioning primitive modes, the positive credential-source leg, and
  the monitor's pre-dead-service leg.
- Executive overview page (leadership/PM audience) plus at-a-glance
  intros across the unsafe-code section and a monitor lifecycle
  mermaid diagram.

### Fixed

- Documentation matches strict-mode exceptions, dotenv interpolation, bundle
  metadata, monitor inheritance, and deployment hardening requirements.
  Rustdoc placeholders render as code, and the overview states protections
  without timing claims or unconditional cleanup guarantees.
- Bundle configs resolve keys end-to-end again: `load_ring` admitted
  only `DOTENV_PRIVATE_KEY*` (Env naming) at every source leg, so
  `POSTMASTER_KEY` never entered the ring and every bundle exec failed
  ("key ring has no POSTMASTER_KEY entry"). The ring now admits exactly
  the namings the config's artifacts require — no more (least
  privilege), no less.
- Darwin serve mode starts: `acquire_listeners` fchmod()ed the bound
  socket fd, but Darwin `fchmod(2)` rejects socket fds (EINVAL) — every
  `--bind` startup failed. Socket permissions are now umask-borne at
  bind time on darwin (no TOCTOU window; Linux keeps the fd-based
  fchmod). Caught by the new daemon end-to-end conformance test.
- `docs/schema/exec.schema.json` realigned with the parser:
  `bundle_files` added, env/files modes accept `env_files` and/or
  `bundle_files`, credentials mode rejects `bundle_files`, and the `$id`
  points at postmaster — guarded by a fields-vs-schema tripwire test
  and a new bundle example.
- Documentation corrections: a phantom exit code 2, `env` mislabeled as
  the default mode, argv-exposing keychain seeding examples, a
  store-path key-source example the parser rejects, "does not
  supervise" contradicting the sibling monitor, stale unsafe-code
  counts, undocumented `POSTMASTER_KEY` and 16 MiB read cap, and
  envelope/dotenvx naming in the examples.

### Removed

- Dead `/postmaster/target/` gitignore line and the inert `docs/book/`
  gitattributes pattern (gitattributes has no dir-recursion syntax).
- Duplicated `key_var_for` test copies in keys/exec_config (the legs
  live in adapter/mod.rs where the mapping lives).

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
