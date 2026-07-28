//! Thin binary entry point.
//!
//! Real logic (and all security properties) live in the library crate so
//! they can be unit-tested. See `lib.rs` and the submodule docs for the
//! full security posture, fail-closed design, and invariants.

fn main() -> std::process::ExitCode {
    postmaster::main()
}
