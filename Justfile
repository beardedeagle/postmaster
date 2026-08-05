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

ci-rust: fmt-check clippy build test
ci: ci-rust flake-check

# =============================================================================
# Build Matrix — Cross-platform builds with varying optimization levels
# =============================================================================
#
# Optimization Levels:
#   debug     - Fast compile, no optimizations, debug symbols (for development)
#   release   - Cargo defaults (opt-level=3, no LTO)
#   optimized - Thin LTO + single codegen unit (good balance of size/speed)
#   max       - Fat LTO + strip + CPU targeting (smallest, fastest binary)
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

# Build with specific optimization level, optional target
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

    # Set optimization flags based on level
    case "$LEVEL" in
        debug)
            CARGO_ARGS=""
            export CARGO_PROFILE_DEV_OPT_LEVEL=0
            echo "Building: debug (fast compile, no optimizations)"
            ;;
        release)
            CARGO_ARGS="--release"
            echo "Building: release (Cargo defaults)"
            ;;
        optimized)
            CARGO_ARGS="--release"
            export CARGO_PROFILE_RELEASE_LTO=thin
            export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
            echo "Building: optimized (LTO=thin, codegen-units=1)"
            ;;
        max)
            CARGO_ARGS="--release"
            export CARGO_PROFILE_RELEASE_LTO=fat
            export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
            export CARGO_PROFILE_RELEASE_OPT_LEVEL=3
            export CARGO_PROFILE_RELEASE_STRIP=symbols
            # CPU targeting: `native` describes the build HOST, so only apply
            # it when the target IS the host. Explicit ARM targets get no
            # target-cpu override (toolchain baseline); x86 targets use
            # x86-64-v3.
            if [[ "$TARGET" == "native" ]]; then
                case "$(uname -m)" in
                    arm64|aarch64) export RUSTFLAGS="-C target-cpu=native" ;;
                    *)             export RUSTFLAGS="-C target-cpu=x86-64-v3" ;;
                esac
            elif [[ "$TARGET" == "linux-arm" || "$TARGET" == "macos-arm" ]]; then
                : # cross-building: no target-cpu override, use toolchain baseline
            else
                export RUSTFLAGS="-C target-cpu=x86-64-v3"
            fi
            echo "Building: max (LTO=fat, strip, target-cpu optimized)"
            ;;
    esac

    # Build command
    if [[ -n "$RUST_TARGET" ]]; then
        echo "Target: $RUST_TARGET"
        cargo +{{stable_toolchain}} build --locked $CARGO_ARGS --target "$RUST_TARGET"
        echo "Output: target/$RUST_TARGET/$([ "$LEVEL" = "debug" ] && echo "debug" || echo "release")/postmaster"
    else
        echo "Target: native ($(rustc +{{stable_toolchain}} -vV | grep host | cut -d' ' -f2))"
        cargo +{{stable_toolchain}} build --locked $CARGO_ARGS
        echo "Output: target/$([ "$LEVEL" = "debug" ] && echo "debug" || echo "release")/postmaster"
    fi

# Build all platforms at a given optimization level (requires cross-compilation setup)
build-all level="release":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building all platforms at '{{level}}' optimization level..."
    echo "Note: cross targets need their toolchains installed first"
    echo "      (e.g. 'rustup target add <triple>'); a missing toolchain fails loudly."
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
    @echo "  release    Cargo defaults (opt-level=3, no LTO)"
    @echo "             Best for: testing release behavior, CI builds"
    @echo ""
    @echo "  optimized  LTO (thin) + single codegen unit"
    @echo "             Best for: staging deployments, performance testing"
    @echo ""
    @echo "  max        LTO (fat) + strip + CPU targeting (x86-64-v3 or native ARM)"
    @echo "             Best for: production deployments, final releases"
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
    @echo "TRADE-OFFS (times/sizes vary with codebase growth):"
    @echo "  Level      Compile Time    Binary Size    Runtime Perf"
    @echo "  ---------  -------------   -----------    ------------"
    @echo "  debug      fastest         largest        1x (baseline)"
    @echo "  release    ~1.3x debug     ~3-4x smaller  3-5x faster"
    @echo "  optimized  ~2x debug       ~4-5x smaller  5-7x faster"
    @echo "  max        ~3x debug       smallest       7-10x faster"
