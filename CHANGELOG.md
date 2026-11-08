# Changelog

Version `0.1.0` is the first planned release.
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-28

### Added

- Provides a standalone, format-neutral secret materialization engine for
  Linux and macOS. Postmaster decrypts local inputs, injects values into the
  application, and replaces the launcher with the target binary through
  `execvp`.
- Decrypts dotenvx-compatible `.env` files with ECIES/secp256k1,
  HKDF-SHA256, and AES-256-GCM.
- Reads encrypted `postmaster_bundle` JSON containers alongside dotenv
  inputs in `env` and `files` modes. Bundle entries support UTF-8 and binary
  values; UTF-8 entries must decode successfully.
- Binds each bundle ciphertext to its entry name with AES-GCM AAD under
  the `ecies-secp256k1-hkdf-sha256-aes-256-gcm-entry-aad` suite.
  Postmaster owns the envelope decoder and uses released ECIES curve/HKDF
  helpers and RustCrypto AES-GCM with key-schedule zeroization.
- Uses an exhaustive `KeyNaming` enum for dotenv and bundle adapter
  dispatch. The key ring admits only the namespaces required by the
  configured inputs.
- Loads private keys from systemd credentials, local key files, macOS
  Keychain, or environment variables. Dotenv inputs use
  `DOTENV_PRIVATE_KEY*`; bundles use `POSTMASTER_KEY`.
- Reads macOS Keychain items through the Security.framework API.
- Selects key sources in order. Missing systemd credentials allow the next
  source; file, Keychain, and environment sources are terminal and fail
  closed when unavailable or invalid.
- Checks private key files through an opened descriptor for ownership and
  restrictive permissions. It rejects final-component symlinks and private
  key paths in the Nix store.
- Keeps runtime key loading and setup verification on the same
  key-variable naming rules. Environment loading skips non-UTF-8 entries.
- Supports `env` mode for direct environment injection.
- Supports `files` mode with one file per secret, `KEY_FILE` pointers,
  and optional environment passthrough. Deployment integrations provide
  RAM-backed storage and configure swap, dump, and cleanup policies.
- Supports `credentials` mode with pointers to systemd credentials or
  selected values fetched from local Postmaster sockets.
- Resolves dotenv files before bundles. The first file defining a name
  wins unless `overload` selects the last; the last assignment within one
  dotenv file wins. Existing environment values take precedence unless
  overload is enabled.
- Rejects undecryptable dotenv values by default. With `strict: false`,
  it logs and omits those values; `--verify-keys` makes any omission fatal.
  Bundle authentication failures always abort the launch.
- Rejects private-key variable names in bundles and removes recognized
  private-key variables from the application's environment after
  projection, regardless of key source or mode.
- Validates identifiers, credential-source path components, and NUL bytes
  at the relevant input and projection boundaries. Encrypted values reach
  the application without shell evaluation. Plaintext dotenv values follow
  dotenv parsing rules, including variable substitution.
- Zeroizes the key ring and resolved value buffers before launch.
  `KeyRing` and `Resolution` debug output redacts secret material.
- Keeps the application as the service's main PID. A sibling monitor
  forwards stop signals, allows a 250 ms grace period before SIGKILL, and
  tracks service exit with Linux pidfds or macOS kqueue. It attempts file
  cleanup after natural exit, forced termination, or a crash.
- Defers termination signals across the plaintext write window on Linux
  and macOS. The monitor consumes signals synchronously; the launcher
  restores its signal mask before exec.
- Pins the secrets directory for pruning, writes, cleanup, and monitoring.
  File creation rejects final-component symlinks, sets mode `0600` through
  the descriptor, and attempts to unlink partial output on write failure.
- Guards bulk cleanup with a `.postmaster-managed` sentinel. Bulk cleanup
  retains the marker on failure so the operation can be retried.
  Launch-failure cleanup uses the same pinned directory.
- Verifies macOS RAM backing through `mount` and `hdiutil info`.
  The pinned directory must be beneath the configured mount, owned by the
  service user, and on the verified RAM device. Mounted and partitioned
  device rows stay associated with their own image; cross-device ancestor
  symlinks fail the check.
- Opens ciphertext files with `O_NOFOLLOW` and sets `CLOEXEC` on the file
  descriptors it opens. Config, bundle, and credential-response reads
  enforce their documented size limits.
- Verifies external tools before use with macOS code-signature checks or
  Linux ownership and permission checks. Linux `id` lookup uses verified
  absolute paths.
- Validates daemon configuration at the root and nested credential
  mappings. Startup rejects relative paths, symlinked socket parents,
  and empty credentials.
- Applies a configured `peer_user` ACL independently of
  `--allow-nonroot`. Socket permissions use a bind-time umask on Linux
  and macOS, with the prior mask restored immediately afterward.
- Applies process hardening on secret-handling command paths and logs
  failures. Help, version output, and structural config checks avoid
  secret-path hardening work.
- Provides `postmaster exec --check` for offline config-shape validation.
  The JSON Schema covers dotenv and bundle inputs, mode-specific fields,
  and strict unknown-field handling. Tested examples exercise the parser
  and guard schema agreement.
- Provides `postmaster exec --verify-keys` to check decryption before
  launching with keys that may be stale after rotation.
- Provides interactive and unattended `postmaster setup` workflows.
  Setup creates a `0700` keys directory, verifies owner-only key files,
  and optionally seeds macOS Keychain items.
- Provides `setup --recheck` for key-source accessibility checks and
  `--keys-dir` for an explicit key directory. `--force` re-prompts for
  key files or re-seeds Keychain items; force with unattended mode fails
  closed.
- Provides `postmaster cleanup --config <exec.json>` for managed
  plaintext-file cleanup and `fetch` for local credential retrieval.
- Separates key handling, CLI parsing, and adapters into focused modules.
  Monitor tests live beside the monitor module, adapter mapping tests live
  with the adapters, and binary conformance tests cover each launch mode.
- Uses registry dependencies including base64 0.23.1, ecies 0.2.13,
  serde 1.0.229, serde_json 1.0.154, zeroize 1.9.1, rustix 1.1.6, and
  libc 0.2.191. AES-GCM 0.11.1 handles bundle authentication.
- Requires Rust 1.99.1 or newer. Release builds use LTO, stripped symbols,
  overflow checks, and `panic = "abort"`.
- Provides a Nix package and overlay with rust-overlay for toolchain
  selection. Service-manager bindings live in deployment integrations.
- Provides native and cross builds through the Justfile build matrix.
  Cross builds use `cargo zigbuild`; builds preserve compiler flags and
  profile overrides, and `max` builds remap source paths.
- Uses Justfile recipes for local checks and GitHub workflow definitions.
  In-repo setup actions configure toolchains; Nix installation verifies
  the pinned installer digest before execution. Official GitHub actions
  and helper tools use pinned versions. Nix installer temporary files
  work with GNU and macOS `mktemp`.
- Runs formatting, Clippy, and Markdown lint from pre-commit hooks.
  Pre-push hooks run the Rust gate, dependency policy, and advisory checks.
  The Rust gate includes native, release, and Linux-target Clippy; the
  toolchain configuration includes `x86_64-unknown-linux-gnu`.
- Keeps Markdown lint rules in `.markdownlint-cli2.jsonc` and excludes
  generated Cargo and mdBook output. Dependency policy checks duplicate
  crate versions, sources, licenses, and advisories, with a documented
  allowance for the wasm-gated `syn` duplicate.
- Exercises daemon startup, socket permissions, and real `fetch`
  roundtrips in binary conformance tests. Regression tests cover read
  limits, symlink refusal, partial-write and launch-failure cleanup, NUL
  handling, precedence, provisioning permissions, key-source selection,
  and monitor lifecycle behavior.
- Documents the launcher contract, five-stage secret pipeline, threat
  model, deployment requirements, and memory-residency limits. The book
  includes an executive overview, configuration examples, and monitor
  lifecycle diagrams.
- Documents unsafe-code boundaries for signal deferral, monitoring,
  macOS libc calls, systemd descriptor ownership, and test-only
  environment mutation.
