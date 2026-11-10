set dotenv-load

stable_toolchain := "stable"

default:
    @just --list

# =============================================================================
# postmaster (Rust)
# =============================================================================

fmt:
    cargo +{{stable_toolchain}} fmt --all

fmt-check:
    cargo +{{stable_toolchain}} fmt --all --check

clippy:
    cargo +{{stable_toolchain}} clippy --all-targets -- -D warnings

# Check release-only code paths with Clippy.
clippy-release:
    cargo +{{stable_toolchain}} clippy --all-targets --release -- -D warnings

# Check Linux-only code paths; rust-toolchain.toml declares the target.
clippy-linux:
    cargo +{{stable_toolchain}} clippy --all-targets --target x86_64-unknown-linux-gnu -- -D warnings

build:
    cargo +{{stable_toolchain}} build --locked

test:
    cargo +{{stable_toolchain}} test --locked

# =============================================================================
# Nix
# =============================================================================

flake-check:
    nix flake check

# Eval-only flake check across all supported systems (no builds)
flake-check-eval-all:
    nix flake check --all-systems --no-build

# =============================================================================
# Docs
# =============================================================================

docs:
    #!/usr/bin/env bash
    set -euo pipefail
    cp CHANGELOG.md docs/src/changelog.md
    mdbook build docs
    rm -f docs/src/changelog.md
    echo "Documentation built: docs/book/"

docs-serve:
    #!/usr/bin/env bash
    set -euo pipefail
    cp CHANGELOG.md docs/src/changelog.md
    trap 'rm -f docs/src/changelog.md' EXIT
    (cd docs && mdbook serve --open)

# Markdown rules and ignores live in .markdownlint-cli2.jsonc; pin the linter version.
lint-md:
    npx --yes markdownlint-cli2@0.23.2 "**/*.md"

# =============================================================================
# Dependency policy
# =============================================================================

deny:
    cargo deny check

audit:
    cargo audit --deny warnings

# =============================================================================
# Aggregate
# =============================================================================

ci-rust: fmt-check clippy clippy-release clippy-linux build test
ci: ci-rust flake-check

# =============================================================================
# Build Matrix — Cross-platform builds with varying optimization levels
# =============================================================================
#
# Optimization Levels:
#   debug     - Fast compile, no optimizations, debug symbols (for development)
#   release   - Cargo.toml release profile (opt-level=3, fat LTO, stripped)
#   optimized - Release profile with thin LTO and one codegen unit
#   max       - Release profile with CPU targeting and source path remapping
#
# Targets:
#   native    - Current platform
#   linux     - x86_64-unknown-linux-gnu
#   linux-musl - x86_64-unknown-linux-musl (static binary, no glibc dependency)
#   linux-arm - aarch64-unknown-linux-gnu (ARM64 Linux: Graviton, Pi 4/5)
#   macos     - x86_64-apple-darwin (Intel Mac)
#   macos-arm - aarch64-apple-darwin (Apple Silicon: M1 through M5)
#
# Usage:
#   just build-matrix optimized linux      # Build optimized for Linux
#   just build-matrix max macos-arm        # Max optimization for Apple Silicon
#   just build-matrix release               # Release build for current platform
#   just build-all optimized               # Build all platforms at optimization level
# =============================================================================

# Build with a specific optimization level and optional target; preserve env overrides.
build-matrix level target="native":
    #!/usr/bin/env bash
    set -euo pipefail

    LEVEL="{{level}}"
    TARGET="{{target}}"

    # Validate optimization level
    case "$LEVEL" in
        debug|release|optimized|max) ;;
        *)
            echo "Error: Invalid optimization level '$LEVEL'"
            echo "Valid levels: debug, release, optimized, max"
            exit 1
            ;;
    esac

    # Map target alias to Rust target triple
    case "$TARGET" in
        native)       RUST_TARGET="" ;;
        linux)        RUST_TARGET="x86_64-unknown-linux-gnu" ;;
        linux-musl)   RUST_TARGET="x86_64-unknown-linux-musl" ;;
        linux-arm)    RUST_TARGET="aarch64-unknown-linux-gnu" ;;
        macos)        RUST_TARGET="x86_64-apple-darwin" ;;
        macos-arm)    RUST_TARGET="aarch64-apple-darwin" ;;
        *)
            echo "Error: Invalid target '$TARGET'"
            echo "Valid targets: native, linux, linux-musl, linux-arm, macos, macos-arm"
            exit 1
            ;;
    esac

    CARGO_ARGS=(--locked)
    # Set optimization defaults without replacing caller overrides.
    case "$LEVEL" in
        debug)
            export CARGO_PROFILE_DEV_OPT_LEVEL="${CARGO_PROFILE_DEV_OPT_LEVEL:-0}"
            echo "Building: debug (fast compile, no optimizations)"
            ;;
        release)
            CARGO_ARGS+=(--release)
            echo "Building: release (Cargo.toml release profile)"
            ;;
        optimized)
            CARGO_ARGS+=(--release)
            export CARGO_PROFILE_RELEASE_LTO="${CARGO_PROFILE_RELEASE_LTO:-thin}"
            export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-1}"
            echo "Building: optimized (thin LTO by default)"
            ;;
        max)
            CARGO_ARGS+=(--release)
            export CARGO_PROFILE_RELEASE_LTO="${CARGO_PROFILE_RELEASE_LTO:-fat}"
            export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-1}"
            export CARGO_PROFILE_RELEASE_OPT_LEVEL="${CARGO_PROFILE_RELEASE_OPT_LEVEL:-3}"
            export CARGO_PROFILE_RELEASE_STRIP="${CARGO_PROFILE_RELEASE_STRIP:-symbols}"
            # Cargo prefers encoded flags; use that format for paths containing spaces.
            if [[ -n "${CARGO_ENCODED_RUSTFLAGS+x}" ]]; then
                configured_flags="$CARGO_ENCODED_RUSTFLAGS"
                build_flags=()
            else
                configured_flags="${RUSTFLAGS:-}"
                IFS=$' \t\n' read -r -d '' -a build_flags < <(printf '%s\0' "$configured_flags")
            fi
            build_flags+=(
                "--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}/registry/src=/cargo/registry"
                "--remap-path-prefix=$PWD=/workspace"
            )
            if [[ "$configured_flags" != *target-cpu* ]]; then
                case "$TARGET" in
                    native) build_flags+=(-C target-cpu=native) ;;
                    linux|linux-musl|macos) build_flags+=(-C target-cpu=x86-64-v3) ;;
                esac
            fi
            build_flags_encoded="$(IFS=$'\x1f'; printf '%s' "${build_flags[*]}")"
            if [[ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]]; then
                build_flags_encoded="$CARGO_ENCODED_RUSTFLAGS"$'\x1f'"$build_flags_encoded"
            fi
            export CARGO_ENCODED_RUSTFLAGS="$build_flags_encoded"
            echo "Building: max (CPU targeting and source path remapping)"
            ;;
    esac

    HOST_TRIPLE="$(rustc +{{stable_toolchain}} -vV | awk '/^host:/ { print $2 }')"
    CARGO_SUBCOMMAND=build
    if [[ -n "$RUST_TARGET" ]]; then
        echo "Target: $RUST_TARGET"
        CARGO_ARGS+=(--target "$RUST_TARGET")
        if [[ "$RUST_TARGET" != "$HOST_TRIPLE" ]]; then
            if ! command -v cargo-zigbuild >/dev/null 2>&1 || ! command -v zig >/dev/null 2>&1; then
                echo "Error: cross-compilation requires cargo-zigbuild and Zig on PATH." >&2
                exit 1
            fi
            CARGO_SUBCOMMAND=zigbuild
        fi
    else
        echo "Target: native ($HOST_TRIPLE)"
    fi
    cargo +{{stable_toolchain}} "$CARGO_SUBCOMMAND" "${CARGO_ARGS[@]}"
    if [[ -n "$RUST_TARGET" ]]; then
        echo "Output: target/$RUST_TARGET/$([ "$LEVEL" = "debug" ] && echo "debug" || echo "release")/postmaster"
    else
        echo "Output: target/$([ "$LEVEL" = "debug" ] && echo "debug" || echo "release")/postmaster"
    fi

# Build all platforms at a given optimization level (requires cross-compilation setup)
build-all level="release":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building all platforms at '{{level}}' optimization level..."
    echo "Note: cross targets need their toolchains installed first"
    echo "      (e.g. 'rustup target add <triple>'); a missing toolchain fails loudly."
    echo "Cross-compilation also requires cargo-zigbuild, Zig, and a macOS SDK for Darwin targets."
    for target in native linux linux-musl linux-arm macos macos-arm; do
        echo ""
        echo "=== Building target: $target ==="
        just build-matrix {{level}} "$target"
    done

# Show build matrix help
build-help:
    @echo "Build Matrix — Cross-platform builds with optimization levels"
    @echo ""
    @echo "USAGE:"
    @echo "  just build-matrix <level> [target]"
    @echo ""
    @echo "ARGUMENTS:"
    @echo "  level    Required. Optimization level (see below)"
    @echo "  target   Optional. Platform target (default: native)"
    @echo ""
    @echo "OPTIMIZATION LEVELS:"
    @echo "  debug      Fast compile, no optimizations, includes debug symbols"
    @echo "             Best for: development, debugging, quick iteration"
    @echo ""
    @echo "  release    Cargo.toml release profile (opt-level=3, fat LTO, stripped)"
    @echo ""
    @echo "  optimized  LTO (thin) + single codegen unit"
    @echo ""
    @echo "  max        Release with CPU targeting and source path remapping"
    @echo ""
    @echo "TARGETS:"
    @echo "  native      Current platform (default)"
    @echo "  linux       x86_64-unknown-linux-gnu"
    @echo "  linux-musl  x86_64-unknown-linux-musl (static binary)"
    @echo "  linux-arm   aarch64-unknown-linux-gnu (ARM64: Graviton, Pi 4/5)"
    @echo "  macos       x86_64-apple-darwin (Intel Mac)"
    @echo "  macos-arm   aarch64-apple-darwin (Apple Silicon: M1-M5)"
    @echo ""
    @echo "EXAMPLES:"
    @echo "  just build-matrix debug                         # Quick dev build"
    @echo "  just build-matrix release                       # Standard release"
    @echo "  just build-matrix optimized linux               # Optimized for Linux"
    @echo "  just build-matrix max macos-arm                  # Max for Apple Silicon"
    @echo "  just build-matrix max linux-arm                  # Max for ARM Linux"
    @echo ""
    @echo "OVERRIDES AND PREREQUISITES:"
    @echo "  Existing RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS and profile overrides are preserved."
    @echo "  max defaults: native CPU for native, x86-64-v3 for x86 targets, baseline for ARM."
    @echo "  Matching host/target triples use cargo build; cross builds use cargo zigbuild."
    @echo "  Install the Rust target, cargo-zigbuild, and Zig before cross-compiling."
    @echo "  Darwin cross builds also require a macOS SDK."
