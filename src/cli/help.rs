//! Help text constants for the postmaster CLI.

/// Top-level help text shown by `postmaster --help` or `postmaster help`.
pub const HELP_TOP: &str = "postmaster — standalone secret materialization engine\n\n\
USAGE:\n  \
postmaster --config <file.json> [--bind] [--allow-nonroot]\n  \
postmaster fetch <socket-path>\n  \
postmaster exec --config <exec.json> [--check] [--verify-keys] -- <command> [args…]\n  \
postmaster setup --config <exec.json> [--recheck] [--unattended] [--force] [--keys-dir <path>]\n  \
postmaster help [subcommand]\n  \
postmaster --version\n\n\
SUBCOMMANDS:\n  \
exec     Decrypt secrets and exec a child process with them injected\n  \
fetch    Fetch a single secret from a postmaster daemon socket\n  \
setup    Verify environment, create keys directory, seed keychain (idempotent)\n  \
help     Show help for a subcommand or this message\n\n\
OPTIONS:\n  \
--config <path>  Configuration file (required for serve, exec, setup)\n  \
--bind           (serve) Bind listener sockets even if not socket-activated\n  \
--allow-nonroot  (serve) Allow non-root connections (dangerous)\n  \
--check          (exec) Validate config shape only, no decryption or exec\n  \
--verify-keys    (exec) Preflight key freshness check before exec\n  \
--recheck        (setup) Verification only, no creation or modification\n  \
--unattended     (setup) Non-interactive mode for automation (fail closed)\n  \
--force          (setup) Re-create or re-seed even if already correct\n  \
--keys-dir <p>   (setup) Override default keys directory path\n  \
--version, -V    Print version and exit\n  \
--help, -h       Show this help message\n";

/// Help text for the `exec` subcommand.
pub const HELP_EXEC: &str = "postmaster exec — decrypt secrets and exec a child process\n\n\
USAGE:\n  \
postmaster exec --config <exec.json> [--check] [--verify-keys] -- <command> [args…]\n\n\
Decrypts the configured env files and/or bundle files using the loaded key\n\
ring, injects the resolved values into the child environment (or writes them\n\
as files / credential pointers depending on mode), and execs the command.\n\n\
OPTIONS:\n  \
--config <path>  Exec config JSON (required)\n  \
--check          Validate config shape only, no decryption, no exec\n  \
--verify-keys    Preflight: fail unless EVERY value in every env file decrypts;\n                  \
under `strict:false` any skipped/undecryptable value also aborts\n                  \
the launch (fail-closed)\n  \
-- <command>     Everything after `--` is the child argv (required unless --check)\n\n\
The config must specify mode (env/files/credentials), key sources, and\n\
artifact paths. See docs/src/reference/launcher-contract.md for the full contract.\n";

/// Help text for the `fetch` subcommand.
pub const HELP_FETCH: &str = "postmaster fetch — fetch a secret from a daemon socket\n\n\
USAGE:\n  \
postmaster fetch <socket-path>\n\n\
Connects to a running postmaster daemon's AF_UNIX socket, requests the\n\
default secret, and writes the decrypted bytes to stdout. Used internally\n\
by the credentials-mode launcher on macOS (launchd) to pull secrets from\n\
the daemon into the RAM disk.\n\n\
The socket path must be a single relative or absolute path to the AF_UNIX\n\
socket created by `postmaster --config <file.json>`.\n";

/// Help text for the `setup` subcommand.
pub const HELP_SETUP: &str = "postmaster setup — verify environment and create key material\n\n\
USAGE:\n  \
postmaster setup --config <exec.json> [--recheck] [--unattended] [--force] [--keys-dir <path>]\n\n\
Verifies platform prerequisites, creates the keys directory with 0700\n\
permissions, verifies or creates keys files with 0600, optionally seeds\n\
keychain items (macOS, interactive), and validates the environment.\n\n\
Idempotent — each step checks whether the target state is already present\n\
and correct, and skips if it is. Safe to run on every converge cycle.\n\n\
OPTIONS:\n  \
--config <path>   Exec config JSON (required)\n  \
--recheck          Verification only — no creation or modification\n  \
--unattended       Non-interactive mode for automation (fail closed, no prompts)\n  \
--force            Re-create or re-seed even if already correct\n  \
--keys-dir <path>  Override the default keys directory\n\n\
Default keys directory: /var/lib/postmaster (Linux),\n\
~/Library/Application Support/postmaster (macOS).\n";

/// Help text for the `cleanup` subcommand.
pub const HELP_CLEANUP: &str = "postmaster cleanup — remove secret files from secrets_dir\n\n\
USAGE:\n  \
postmaster cleanup --config <exec.json>\n\n\
Reads the exec config, extracts secrets_dir, and removes all regular files\n\
in that directory. Intended for ExecStopPost in systemd or equivalent\n\
lifecycle hooks in other service managers.\n\n\
Does not decrypt — only removes files that postmaster would have written.\n\
Safety guard: a NON-EMPTY directory without a .postmaster-managed sentinel\n\
file is left untouched (postmaster only bulk-deletes directories it manages).\n\
Safe to run even if the directory is already empty or does not exist.\n\n\
OPTIONS:\n  \
--config <path>  Exec config JSON (required)\n";
