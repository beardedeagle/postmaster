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

# =============================================================================
# Docs
# =============================================================================

docs:
    mdbook build docs

docs-serve:
    cd docs && mdbook serve

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
