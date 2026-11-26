//! Help text constants for the postmaster CLI.

/// Top-level help text shown by `postmaster --help` or `postmaster help`.
pub const HELP_TOP: &str = "postmaster — standalone secret materialization engine\n\n\
USAGE:\n  \
postmaster --config <file.json> [--bind] [--allow-nonroot]\n  \
postmaster fetch [--protocol raw|framed] [--server-uid <uid>] <socket-path>\n  \
postmaster exec --config <exec.json> [--check] [--verify-keys] -- <command> [args…]\n  \
postmaster setup --config <exec.json> [--recheck] [--unattended] [--force] [--keys-dir <path>]\n  \
postmaster cleanup --config <exec.json>\n  \
postmaster help [subcommand]\n  \
postmaster --version\n\n\
SUBCOMMANDS:\n  \
exec     Decrypt secrets and exec a child process with them injected\n  \
fetch    Fetch a single secret from a postmaster daemon socket\n  \
setup    Provision local key sources and check access (idempotent)\n  \
cleanup  Remove plaintext secret files from secrets_dir (ExecStopPost)\n  \
help     Show help for a subcommand or this message\n\n\
OPTIONS:\n  \
--config <path>  Configuration file (required for serve, exec, setup, cleanup)\n  \
--bind           (serve) Bind listener sockets even if not socket-activated\n  \
--allow-nonroot  (serve) Allow any UID when peer_user is unset\n  \
--check          (exec) Validate config shape only, no decryption or exec\n  \
--verify-keys    (exec) Preflight key freshness check before exec\n  \
--recheck        (setup) Check key source access and custody only\n  \
--unattended     (setup) Non-interactive mode for automation (fail closed)\n  \
--force          (setup) Prompt to replace key files or re-seed Keychain items\n  \
--keys-dir <p>   (setup) Override default keys directory path\n  \
--version, -V    Print version and exit\n  \
--help, -h       Show this help message\n";

/// Help text for the `exec` subcommand.
pub const HELP_EXEC: &str = "postmaster exec — decrypt secrets and exec a child process\n\n\
USAGE:\n  \
postmaster exec --config <exec.json> [--check] [--verify-keys] -- <command> [args…]\n\n\
Resolves configured inputs, projects values through environment variables,\n\
files, or credential pointers, and replaces the launcher with the command.\n\n\
OPTIONS:\n  \
--config <path>  Exec config JSON (required)\n  \
--check          Validate config shape only, no decryption, no exec\n  \
--verify-keys    Preflight: fail unless EVERY value in every env file decrypts;\n                  \
under `strict:false` any skipped/undecryptable value also aborts\n                  \
the launch (fail-closed); cannot be combined with --check\n  \
-- <command>     Everything after `--` is the child argv (required unless --check)\n\n\
The config selects mode (env/files/credentials) and its required fields.\n\
Env and files modes need key sources and artifact paths. Credentials mode\n\
uses existing credential files or configured local sockets. See\n\
docs/src/reference/launcher-contract.md for the full contract.\n";

/// Help text for the `fetch` subcommand.
pub const HELP_FETCH: &str = "postmaster fetch — fetch a secret from a daemon socket\n\n\
USAGE:\n  \
postmaster fetch [--protocol raw|framed] [--server-uid <uid>] <socket-path>\n\n\
Connects to a local Unix socket and writes only the credential bytes to\n\
stdout. The credentials-mode launcher uses the same client path.\n\
The socket path may be relative or absolute. Available on Linux and macOS.\n\n\
OPTIONS:\n  \
--protocol raw|framed  Match the listener's configured protocol (default: raw)\n  \
--server-uid <uid>    Require this numeric peer UID before reading bytes\n\n\
Raw mode preserves systemd's bytes-to-EOF contract. Framed mode requires\n\
--server-uid and rejects incomplete or trailing data before writing stdout.\n\
For socket activation, the peer UID can identify the socket's creator or\n\
service manager rather than the daemon accepting the connection.\n";

/// Help text for the `setup` subcommand.
pub const HELP_SETUP: &str = "postmaster setup — provision local key sources and check access\n\n\
USAGE:\n  \
postmaster setup --config <exec.json> [--recheck] [--unattended] [--force] [--keys-dir <path>]\n\n\
Creates the keys directory with 0700 permissions if missing, checks custody\n\
of configured key files or creates them with 0600 permissions, and optionally\n\
seeds configured Keychain items (macOS, interactive).\n\n\
Steps already satisfied are skipped. Use --unattended for automated runs;\n\
it fails if operator input is required. Required Keychain accounts are\n\
deduplicated before prompting, preserving first-seen input order.\n\
The access check follows runtime source selection and file custody rules.\n\
Execution parses the key material when it loads the selected source.\n\
Credentials mode validates configuration without provisioning private keys.\n\n\
OPTIONS:\n  \
--config <path>   Exec config JSON (required)\n  \
--recheck          Check access and custody without provisioning or parsing keys\n  \
--unattended       Non-interactive mode for automation (fail closed, no prompts)\n  \
--non-interactive  Alias for --unattended\n  \
--force            Prompt to replace key files or re-seed Keychain items\n                    \
                   Conflicts with --recheck\n  \
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
Does not decrypt. A non-empty directory without a .postmaster-managed\n\
sentinel is left untouched. The marker identifies the managed directory,\n\
not individual files. Keep one secrets_dir per service. Empty or missing\n\
directories need no cleanup. Secret-file removal failures retain the marker\n\
and return an error so cleanup can be retried.\n\n\
OPTIONS:\n  \
--config <path>  Exec config JSON (required)\n";
