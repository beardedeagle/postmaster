//! Thin binary entry point.
//!
//! Real logic (and all security properties) live in the library crate so
//! they can be unit-tested. See `lib.rs` and the submodule docs for the
//! full security posture, fail-closed design, and invariants.

// See src/lib.rs for why this allow exists (wasm-bindgen's wasm32-gated
// syn 2 vs serde_derive's syn 3; uncontrollable, deny.toml keeps watch).
#![allow(clippy::multiple_crate_versions)]

fn main() -> std::process::ExitCode {
    postmaster::main()
}
