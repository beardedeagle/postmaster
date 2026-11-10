//! CLI dispatch and secret handling for Postmaster.
//!
//! Submodules expose key loading, resolution, argument parsing, and serving
//! logic to tests without launching the binary entry point.

// `multiple_crate_versions` is warn-level in Cargo.toml; allowed here for
// exactly one uncontrollable case: syn 2 + syn 3 coexist only because
// wasm-bindgen (target-gated to wasm32-unknown-unknown inside the ecies
// dependency, never compiled for postmaster's real targets) pins syn 2
// while serde_derive uses syn 3. cargo-deny `[bans].multiple-versions`
// (warn, with syn skipped) keeps watch for the tree converging and for any
// NEW duplicates — remove this allow when syn 2 leaves the tree.
#![allow(clippy::multiple_crate_versions)]

mod aad;
pub mod adapter;
pub mod cli;
pub mod exec_config;
pub mod keys;
pub mod launcher;
pub(crate) mod monitor;
pub mod ramdisk;
pub mod secret_files;
pub mod server;
#[cfg(test)]
pub(crate) mod test_util;

/// Public alias for the bundle adapter.
pub use adapter::bundle;
/// Public alias for CLI parsing and daemon configuration.
pub use cli as config;
pub use cli::{Invocation, parse_args, parse_args_from};
pub use keys::provisioning::{cleanup, setup};
/// Public alias for ordered key-source selection.
pub use keys::source as key_source;
pub use server::{fetch, harden_process, run};

/// Dispatch a parsed invocation from the binary or tests.
pub fn main() -> std::process::ExitCode {
    // Harden only the arms that can touch secret material: --help/--version and --check
    // must not print hardening noise (e.g. an mlockall failure) for invocations that
    // never decrypt. Serve/Exec/Fetch/Setup/Cleanup stay hardened BEFORE any decryption
    // and before execvp.
    let result = match parse_args() {
        Ok(Invocation::Serve(args)) => {
            harden_process();
            run(&args)
        }
        Ok(Invocation::Fetch(path)) => {
            harden_process();
            fetch(&path)
        }
        Ok(Invocation::Exec {
            config,
            check: true,
            ..
        }) => launcher::check_config(&config),
        Ok(Invocation::Exec {
            config,
            check: false,
            verify_keys,
            argv,
        }) => {
            harden_process();
            launcher::exec(&config, &argv, verify_keys)
        }
        Ok(Invocation::Setup {
            config,
            recheck,
            unattended,
            force,
            keys_dir,
        }) => {
            harden_process();
            setup(&config, recheck, unattended, force, keys_dir)
        }
        Ok(Invocation::Cleanup { config }) => {
            harden_process();
            cleanup(&config)
        }
        #[allow(clippy::print_stdout, clippy::print_stderr)]
        Ok(Invocation::Help(sub)) => {
            let text = match sub.as_deref() {
                Some("exec") => config::HELP_EXEC,
                Some("fetch") => config::HELP_FETCH,
                Some("setup") => config::HELP_SETUP,
                Some("cleanup") => config::HELP_CLEANUP,
                Some(unknown) => {
                    eprintln!("error: unknown subcommand `{unknown}` for help");
                    eprintln!("\nAvailable subcommands: exec, fetch, setup, cleanup");
                    return std::process::ExitCode::FAILURE;
                }
                None => config::HELP_TOP,
            };
            print!("{text}");
            return std::process::ExitCode::SUCCESS;
        }
        #[allow(clippy::print_stdout)]
        Ok(Invocation::Version) => {
            println!("postmaster {}", config::VERSION);
            return std::process::ExitCode::SUCCESS;
        }
        Err(e) => Err(e),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            server::log(&e);
            std::process::ExitCode::FAILURE
        }
    }
}
