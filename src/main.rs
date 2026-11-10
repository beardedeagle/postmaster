//! Thin binary entry point.
//!
//! The library crate owns CLI dispatch and secret handling so tests can call
//! those paths directly. See `lib.rs` and the submodule contracts.

// See src/lib.rs for why this allow exists (wasm-bindgen's wasm32-gated
// syn 2 vs serde_derive's syn 3; uncontrollable, deny.toml keeps watch).
#![allow(clippy::multiple_crate_versions)]

fn main() -> std::process::ExitCode {
    postmaster::main()
}
