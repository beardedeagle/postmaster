//! postmaster library.
//!
//! The bulk of the logic lives in the submodules so that unit tests can
//! exercise key loading, resolution, argument parsing, and serving logic
//! without going through main().
//!
//! Security and fail-closed semantics are preserved exactly.

// `multiple_crate_versions` is warn-level in Cargo.toml; allowed here for
// exactly one uncontrollable case: syn 2 + syn 3 coexist only because
// wasm-bindgen (target-gated to wasm32-unknown-unknown inside the ecies
// dependency, never compiled for postmaster's real targets) pins syn 2
// while serde_derive uses syn 3. cargo-deny `[bans].multiple-versions`
// (warn, with syn skipped) keeps watch for the tree converging and for any
// NEW duplicates — remove this allow when syn 2 leaves the tree.
#![allow(clippy::multiple_crate_versions)]

pub mod adapter;
pub mod cli;
pub mod exec_config;
pub mod keys;
pub mod launcher;
pub(crate) mod monitor;
pub mod ramdisk;
pub mod secret_files;
pub mod server;

/// The bundle adapter, re-exported so `crate::bundle` keeps resolving.
pub use adapter::bundle;
/// The CLI module under its former name, so `crate::config` keeps resolving.
pub use cli as config;
pub use cli::{Invocation, parse_args, parse_args_from};
/// Key provisioning under its former name, so `crate::key_provisioning`
/// keeps resolving.
pub use keys::provisioning as key_provisioning;
pub use keys::provisioning::{cleanup, setup};
/// Key-source selection under its former name, so `crate::key_source`
/// keeps resolving.
pub use keys::source as key_source;
pub use server::{fetch, harden_process, run};

/// Re-exported for binary use. The real main is here so tests can call into it.
pub fn main() -> std::process::ExitCode {
    harden_process();
    let result = match parse_args() {
        Ok(Invocation::Serve(args)) => run(&args),
        Ok(Invocation::Fetch(path)) => fetch(&path),
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
        }) => launcher::exec(&config, &argv, verify_keys),
        Ok(Invocation::Setup {
            config,
            recheck,
            unattended,
            force,
            keys_dir,
        }) => setup(&config, recheck, unattended, force, keys_dir),
        Ok(Invocation::Cleanup { config }) => cleanup(&config),
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
