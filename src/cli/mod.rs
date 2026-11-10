//! CLI parsing (`Invocation`, `parse_args`, help text) and the
//! configuration data structures for postmaster's daemon and exec modes.
//!
//! Deployment tools provide JSON configuration containing public paths,
//! key-source names, and projection settings.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

mod help;

/// CLI help text, also available through the `crate::config` alias.
pub use help::{HELP_CLEANUP, HELP_EXEC, HELP_FETCH, HELP_SETUP, HELP_TOP};

/// Daemon configuration loaded from JSON. Unknown fields are rejected.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the .env.keys material comes from.
    pub keys: KeysSource,
    /// Absolute socket path → what to serve on it.
    pub credentials: HashMap<PathBuf, Entry>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
/// Where postmaster should obtain its own private keys.
pub enum KeysSource {
    /// Name under $CREDENTIALS_DIRECTORY (the daemon's own LoadCredential).
    Credential(String),
    /// Absolute filesystem path (must not live in the Nix store).
    File(PathBuf),
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
/// A single credential mapping served by postmaster. Unknown fields are
/// rejected — same strictness as `Config`.
pub struct Entry {
    /// Dotenv input containing encrypted values, plaintext entries, or both.
    pub env_file: PathBuf,
    /// Which key inside it to serve.
    pub key: String,
    /// Trusted SHA-256 hashes of the exact dotenv file bytes, as 64-digit hex strings.
    /// A hash must match before parsing, interpolation or decryption.
    #[serde(deserialize_with = "deserialize_env_file_hashes")]
    pub env_file_sha256: Vec<[u8; 32]>,
    /// Allow this user as well as root to fetch the credential.
    /// Enforced even when `--allow-nonroot` is set.
    #[serde(default)]
    pub peer_user: Option<String>,
}

fn deserialize_env_file_hashes<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer)?
        .into_iter()
        .map(|value| {
            let mut hash = [0; 32];
            hex::decode_to_slice(value, &mut hash).map_err(|_| {
                serde::de::Error::custom("env_file_sha256 requires 64-digit hex hashes")
            })?;
            Ok(hash)
        })
        .collect()
}

/// Parsed command-line arguments for the `serve` invocation.
#[derive(Debug)]
pub struct Args {
    /// Path to the daemon config JSON file.
    pub config: PathBuf,
    /// Bind listener sockets even when not socket-activated.
    pub bind: bool,
    /// Allow non-root peers to connect (dev escape hatch; never overrides
    /// a configured `peer_user` ACL).
    pub allow_nonroot: bool,
}

/// The parsed top-level invocation selected from CLI arguments.
#[derive(Debug)]
pub enum Invocation {
    /// `postmaster --config <file.json> [--bind] [--allow-nonroot]`:
    /// run the credential daemon (socket-activated on Linux, bind on macOS).
    Serve(Args),
    /// `postmaster fetch <socket-path>`: connect to a running daemon
    /// socket and write the decrypted bytes to stdout.
    Fetch(PathBuf),
    /// `postmaster exec --config <exec.json> [--check] [--verify-keys]`
    /// `-- <argv…>`: decrypt + inject per the launcher contract, then
    /// execvp argv. See launcher.rs.
    Exec {
        /// Path to the exec config JSON.
        config: PathBuf,
        /// Validate config shape only — no decryption, no exec.
        check: bool,
        /// Preflight: fail unless EVERY value in every env file
        /// decrypts. Catches stale keys from a previous rotation cycle
        /// that are valid hex but no longer match the ciphertext; under
        /// `strict: false` any skipped/undecryptable value also aborts
        /// the launch (fail-closed).
        verify_keys: bool,
        /// Child argv — everything after `--` on the command line.
        argv: Vec<String>,
    },
    /// `postmaster setup --config <exec.json> [--recheck] [--unattended]
    /// [--force] [--keys-dir <path>]`: verify platform prerequisites,
    /// create keys directory with correct permissions, optionally seed
    /// keychain items, and validate the environment. Idempotent — skips
    /// steps that are already correct. `--recheck` re-verifies without
    /// creating or modifying anything.
    Setup {
        /// Path to the exec config JSON.
        config: PathBuf,
        /// Verification only — no creation or modification.
        recheck: bool,
        /// Non-interactive mode for automation (fail closed, no prompts).
        unattended: bool,
        /// Re-create or re-seed even if already correct.
        force: bool,
        /// Override the default keys directory path.
        keys_dir: Option<PathBuf>,
    },
    /// `postmaster cleanup --config <exec.json>`: remove all secret files
    /// from the secrets_dir configured in the exec config. Intended for
    /// `ExecStopPost` in systemd or equivalent lifecycle hooks in other
    /// service managers. Does not decrypt — only removes files that
    /// postmaster would have written. Bulk removal is refused for a
    /// non-empty directory lacking the `.postmaster-managed` sentinel.
    Cleanup {
        /// Path to the exec config JSON.
        config: PathBuf,
    },
    /// Print help text and exit successfully.
    Help(Option<String>),
    /// Print version and exit successfully.
    Version,
}

/// Crate version, resolved at compile time from `CARGO_PKG_VERSION`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Consume the value of a value-taking option, rejecting another flag as
/// the value: `--config --check` must not parse `"--check"` as the
/// config path.
fn option_value(
    it: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<String, String> {
    match it.next() {
        None => Err(format!("error: {flag} requires a path")),
        Some(v) if v.starts_with('-') => Err(format!(
            "error: {flag} requires a path, got flag `{v}` (missing value?)"
        )),
        Some(v) => Ok(v),
    }
}

/// Parse command-line arguments from `std::env::args()`.
pub fn parse_args() -> Result<Invocation, String> {
    parse_args_from(std::env::args().skip(1))
}

/// Parse command-line arguments from a provided iterator. Kept simple
/// with no external dependencies (no clap).
pub fn parse_args_from(args: impl IntoIterator<Item = String>) -> Result<Invocation, String> {
    let mut it = args.into_iter().peekable();

    // No args: print help and fail
    if it.peek().is_none() {
        return Err(format!(
            "{HELP_TOP}\n\nerror: no subcommand or --config provided"
        ));
    }

    match it.peek().map(String::as_str) {
        // Global flags that work before any subcommand
        Some("--help") | Some("-h") => {
            it.next();
            if it.next().is_some() {
                return Err("error: --help does not take arguments".into());
            }
            Ok(Invocation::Help(None))
        }
        Some("--version") | Some("-V") => {
            it.next();
            if it.next().is_some() {
                return Err("error: --version does not take arguments".into());
            }
            Ok(Invocation::Version)
        }
        Some("help") => {
            it.next();
            let sub = it.next();
            if it.next().is_some() {
                return Err(
                    "error: `help` takes at most one argument (the subcommand name)".into(),
                );
            }
            Ok(Invocation::Help(sub))
        }
        Some("fetch") => {
            it.next();
            match it.next() {
                // Every subcommand takes --help/-h.
                Some(a) if a == "--help" || a == "-h" => Ok(Invocation::Help(Some("fetch".into()))),
                Some(path) => {
                    if it.next().is_some() {
                        return Err(
                            "error: fetch takes exactly one argument (the socket path)".into()
                        );
                    }
                    Ok(Invocation::Fetch(PathBuf::from(path)))
                }
                None => Err("error: fetch requires a socket path".into()),
            }
        }
        Some("exec") => {
            it.next();
            let mut config = None;
            let mut check = false;
            let mut verify_keys = false;
            let mut argv: Vec<String> = Vec::new();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--config" => {
                        config = Some(PathBuf::from(option_value(&mut it, "--config")?));
                    }
                    "--check" => check = true,
                    "--verify-keys" => verify_keys = true,
                    "--help" | "-h" => return Ok(Invocation::Help(Some("exec".into()))),
                    "--" => {
                        argv = it.collect();
                        break;
                    }
                    other => {
                        return Err(format!(
                            "error: exec: unknown option `{other}`\n\n{HELP_EXEC}"
                        ));
                    }
                }
            }
            if check {
                if !argv.is_empty() {
                    return Err("error: exec --check does not accept a command after `--`".into());
                }
            } else if argv.is_empty() {
                return Err(format!(
                    "error: exec: missing command after `--`\n\n{HELP_EXEC}"
                ));
            }
            Ok(Invocation::Exec {
                config: config.ok_or("error: exec: missing required --config <exec.json>")?,
                check,
                verify_keys,
                argv,
            })
        }
        Some("setup") => {
            it.next();
            let mut config = None;
            let mut recheck = false;
            let mut unattended = false;
            let mut force = false;
            let mut keys_dir = None;
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--config" => {
                        config = Some(PathBuf::from(option_value(&mut it, "--config")?));
                    }
                    "--recheck" => recheck = true,
                    "--unattended" | "--non-interactive" => unattended = true,
                    "--force" => force = true,
                    "--keys-dir" => {
                        keys_dir = Some(PathBuf::from(option_value(&mut it, "--keys-dir")?));
                    }
                    "--help" | "-h" => return Ok(Invocation::Help(Some("setup".into()))),
                    other => {
                        return Err(format!(
                            "error: setup: unknown option `{other}`\n\n{HELP_SETUP}"
                        ));
                    }
                }
            }
            let config = config.ok_or("error: setup: missing required --config <exec.json>")?;
            Ok(Invocation::Setup {
                config,
                recheck,
                unattended,
                force,
                keys_dir,
            })
        }
        Some("cleanup") => {
            it.next();
            let mut config = None;
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--config" => {
                        config = Some(PathBuf::from(option_value(&mut it, "--config")?));
                    }
                    "--help" | "-h" => return Ok(Invocation::Help(Some("cleanup".into()))),
                    other => {
                        return Err(format!(
                            "error: cleanup: unknown option `{other}`\n\n{HELP_CLEANUP}"
                        ));
                    }
                }
            }
            Ok(Invocation::Cleanup {
                config: config.ok_or("error: cleanup: missing required --config <exec.json>")?,
            })
        }
        // Serve mode (default, no subcommand keyword)
        Some("--config") | Some("--bind") | Some("--allow-nonroot") => {
            let mut config = None;
            let mut bind = false;
            let mut allow_nonroot = false;
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--config" => {
                        config = Some(PathBuf::from(option_value(&mut it, "--config")?));
                    }
                    "--bind" => bind = true,
                    "--allow-nonroot" => allow_nonroot = true,
                    "--help" | "-h" => return Ok(Invocation::Help(None)),
                    other => {
                        return Err(format!("error: unknown option `{other}`\n\n{HELP_TOP}"));
                    }
                }
            }
            Ok(Invocation::Serve(Args {
                config: config.ok_or("error: missing required --config <file.json>")?,
                bind,
                allow_nonroot,
            }))
        }
        Some(other) => Err(format!(
            "error: unknown subcommand `{other}`\n\nTry `postmaster help` for usage.\n"
        )),
        None => unreachable!("empty args handled above"),
    }
}

#[cfg(test)]
#[allow(unused_qualifications, clippy::panic, clippy::unwrap_used)]
/// Tests for CLI argument parsing.
mod tests {
    use super::*;

    fn parse(v: &[&str]) -> Result<Invocation, String> {
        parse_args_from(v.iter().map(ToString::to_string))
    }

    #[test]
    fn parse_exec() {
        match parse(&[
            "exec", "--config", "/e.json", "--", "/bin/app", "--flag", "x",
        ]) {
            Ok(Invocation::Exec {
                config,
                check,
                verify_keys,
                argv,
            }) => {
                assert_eq!(config, PathBuf::from("/e.json"));
                assert!(!check);
                assert!(!verify_keys);
                assert_eq!(argv, vec!["/bin/app", "--flag", "x"]);
            }
            other => panic!("expected Exec, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_check() {
        match parse(&["exec", "--config", "/e.json", "--check"]) {
            Ok(Invocation::Exec {
                config,
                check,
                argv,
                ..
            }) => {
                assert_eq!(config, PathBuf::from("/e.json"));
                assert!(check);
                assert!(argv.is_empty());
            }
            other => panic!("expected Exec check, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_verify_keys() {
        match parse(&[
            "exec",
            "--config",
            "/e.json",
            "--verify-keys",
            "--",
            "/bin/app",
        ]) {
            Ok(Invocation::Exec {
                config,
                check,
                verify_keys,
                argv,
            }) => {
                assert_eq!(config, PathBuf::from("/e.json"));
                assert!(!check);
                assert!(verify_keys);
                assert_eq!(argv, vec!["/bin/app"]);
            }
            other => panic!("expected Exec with --verify-keys, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_requires_command() {
        assert!(parse(&["exec", "--config", "/e.json"]).is_err());
        assert!(parse(&["exec", "--config", "/e.json", "--"]).is_err());
        assert!(parse(&["exec", "--config", "/e.json", "--check", "--", "/bin/app"]).is_err());
    }

    #[test]
    fn parse_fetch_and_serve_still_work() {
        assert!(matches!(
            parse(&["fetch", "/s.sock"]),
            Ok(Invocation::Fetch(_))
        ));
        assert!(matches!(
            parse(&["--config", "/c.json", "--bind"]),
            Ok(Invocation::Serve(Args { bind: true, .. }))
        ));
    }

    #[test]
    fn parse_help_top_level() {
        assert!(matches!(parse(&["--help"]), Ok(Invocation::Help(None))));
        assert!(matches!(parse(&["-h"]), Ok(Invocation::Help(None))));
    }

    #[test]
    fn parse_help_subcommand() {
        assert!(matches!(parse(&["help"]), Ok(Invocation::Help(None))));
        assert!(matches!(
            parse(&["help", "exec"]),
            Ok(Invocation::Help(Some(s))) if s == "exec"
        ));
        assert!(matches!(
            parse(&["help", "setup"]),
            Ok(Invocation::Help(Some(s))) if s == "setup"
        ));
    }

    #[test]
    fn parse_version() {
        assert!(matches!(parse(&["--version"]), Ok(Invocation::Version)));
        assert!(matches!(parse(&["-V"]), Ok(Invocation::Version)));
    }

    #[test]
    fn parse_no_args_fails() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn config_rejects_unknown_fields_in_nested_entry() {
        // The nested credential Entry is as strict as the top-level Config — an unknown
        // field is a binding bug, not something to silently ignore.
        let raw = serde_json::json!({
            "keys": {"file": "/run/postmaster/.env.keys"},
            "credentials": {
                "/run/cred.sock": {"env_file": "/nix/store/x/.env", "key": "DB_URL", "bogus": 1}
            }
        });
        let err = serde_json::from_value::<Config>(raw).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");

        // A well-formed config still parses.
        let raw = serde_json::json!({
            "keys": {"credential": "postmaster-keys"},
            "credentials": {
                "/run/cred.sock": {"env_file": "/nix/store/x/.env", "key": "DB_URL", "env_file_sha256": ["0000000000000000000000000000000000000000000000000000000000000000"], "peer_user": "_www"}
            }
        });
        serde_json::from_value::<Config>(raw).unwrap();
    }

    #[test]
    fn parse_unknown_subcommand_fails() {
        let err = parse(&["bogus"]).unwrap_err();
        assert!(err.contains("unknown subcommand"), "{err}");
        assert!(err.contains("Try `postmaster help`"), "{err}");
    }

    #[test]
    fn parse_help_in_exec_subcommand() {
        assert!(matches!(
            parse(&["exec", "--help"]),
            Ok(Invocation::Help(Some(s))) if s == "exec"
        ));
    }

    #[test]
    fn parse_help_in_setup_subcommand() {
        assert!(matches!(
            parse(&["setup", "--help"]),
            Ok(Invocation::Help(Some(s))) if s == "setup"
        ));
    }

    #[test]
    fn parse_setup_flags() {
        assert!(matches!(
            parse(&["setup", "--config", "/e.json", "--recheck"]),
            Ok(Invocation::Setup { recheck: true, .. })
        ));
        assert!(matches!(
            parse(&["setup", "--config", "/e.json", "--unattended"]),
            Ok(Invocation::Setup {
                unattended: true,
                ..
            })
        ));
        assert!(matches!(
            parse(&["setup", "--config", "/e.json", "--force"]),
            Ok(Invocation::Setup { force: true, .. })
        ));
        assert!(matches!(
            parse(&["setup", "--config", "/e.json", "--keys-dir", "/custom"]),
            Ok(Invocation::Setup { keys_dir: Some(p), .. }) if &*p == std::path::Path::new("/custom")
        ));
    }

    #[test]
    fn parse_cleanup() {
        assert!(matches!(
            parse(&["cleanup", "--config", "/e.json"]),
            Ok(Invocation::Cleanup { config }) if &*config == std::path::Path::new("/e.json")
        ));
        assert!(parse(&["cleanup"]).is_err());
        assert!(parse(&["cleanup", "--config"]).is_err());
    }

    #[test]
    fn parse_help_in_cleanup_subcommand() {
        assert!(matches!(
            parse(&["cleanup", "--help"]),
            Ok(Invocation::Help(Some(s))) if s == "cleanup"
        ));
    }

    #[test]
    fn parse_help_in_fetch_subcommand() {
        // Fetch accepts --help/-h without treating either flag as a socket path.
        assert!(matches!(
            parse(&["fetch", "--help"]),
            Ok(Invocation::Help(Some(s))) if s == "fetch"
        ));
        assert!(matches!(
            parse(&["fetch", "-h"]),
            Ok(Invocation::Help(Some(s))) if s == "fetch"
        ));
        // The real path still parses.
        assert!(matches!(
            parse(&["fetch", "/run/pm/s.sock"]),
            Ok(Invocation::Fetch(p)) if &*p == std::path::Path::new("/run/pm/s.sock")
        ));
    }

    #[test]
    fn parse_rejects_flag_as_option_value() {
        // A value-taking option must not swallow the following flag as its value.
        let err = parse(&["exec", "--config", "--check"]).unwrap_err();
        assert!(err.contains("--config"), "{err}");
        assert!(err.contains("--check"), "{err}");
        let err = parse(&["setup", "--keys-dir", "--force", "--config", "/e.json"]).unwrap_err();
        assert!(err.contains("--keys-dir"), "{err}");
        assert!(parse(&["exec", "--config"]).is_err());
    }
}
