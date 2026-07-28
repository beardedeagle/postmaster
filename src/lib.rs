//! postmaster library.
//!
//! The bulk of the logic lives in the submodules so that unit tests can
//! exercise key loading, resolution, argument parsing, and serving logic
//! without going through main().
//!
//! Security and fail-closed semantics are preserved exactly.

#![allow(missing_docs, missing_debug_implementations)]

pub mod adapter;
pub mod bundle;
pub mod config;
pub mod keys;
pub mod launcher;
pub mod server;

pub use config::{Invocation, parse_args, parse_args_from};
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
        }) => launcher::setup(&config, recheck, unattended, force, keys_dir),
        Ok(Invocation::Cleanup { config }) => launcher::cleanup(&config),
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
