//! Adapter enum for key-naming conventions.
//!
//! Dotenv and bundle inputs have different key names, metadata filters, and
//! filename mappings. `KeyNaming` keeps those rules together for loading and
//! resolution.
//!
//! Exhaustive matches make new adapter variants a compile-time obligation
//! for each dispatch site.

pub mod bundle;

use std::path::Path;

/// The key-naming convention for a secret input adapter.
///
/// Each dispatch match must handle every adapter variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyNaming {
    /// The `.env` file adapter. Uses `DOTENV_PRIVATE_KEY[_<ENV>]` as its
    /// key variable naming, `DOTENV_` as its metadata prefix, and maps
    /// `.env.production` → `DOTENV_PRIVATE_KEY_PRODUCTION`.
    Env,
    /// The `postmaster_bundle` adapter. Uses `POSTMASTER_KEY` as its
    /// key variable naming, regardless of filename or `profile`. No metadata
    /// prefix (the bundle format is structured JSON, not flat key-value).
    Bundle,
}

impl KeyNaming {
    /// The prefix that identifies private key variable names.
    /// `from_pairs` and `from_env` filter by this prefix.
    pub fn key_prefix(self) -> &'static str {
        match self {
            KeyNaming::Env => "DOTENV_PRIVATE_KEY",
            KeyNaming::Bundle => "POSTMASTER_KEY",
        }
    }

    /// The prefix that identifies metadata keys to be filtered out during
    /// resolution. Keys starting with this prefix are dropped before
    /// injection. Returns `None` if the adapter has no metadata prefix.
    pub fn metadata_prefix(self) -> Option<&'static str> {
        match self {
            KeyNaming::Env => Some("DOTENV_"),
            KeyNaming::Bundle => None,
        }
    }

    /// Map an artifact filename to the key variable name it needs.
    /// `.env` → `DOTENV_PRIVATE_KEY`, `.env.production` →
    /// `DOTENV_PRIVATE_KEY_PRODUCTION`. Bundle files map to a single
    /// key variable regardless of filename. `profile` does not select a key.
    pub fn key_var_for(self, artifact_path: &Path) -> Result<String, String> {
        match self {
            KeyNaming::Env => {
                let base = artifact_path
                    .file_name()
                    .and_then(|b| b.to_str())
                    .ok_or_else(|| format!("{}: unreadable file name", artifact_path.display()))?;
                let rest = base.strip_prefix(".env").ok_or_else(|| {
                    format!("{base}: env files must follow the `.env[.<environment>]` convention")
                })?;
                if rest.is_empty() {
                    return Ok(self.key_prefix().into());
                }
                let env = rest.strip_prefix('.').ok_or_else(|| {
                    format!("{base}: env files must follow the `.env[.<environment>]` convention")
                })?;
                // Reject anything outside [A-Za-z0-9_]: such characters would sanitize
                // to '_', making distinct filenames collide on the same key variable
                // (`.env..x` ≡ `.env._x`). Letters fold to upper case, the dotenvx
                // convention.
                if env.is_empty() || !env.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return Err(format!(
                        "{base}: environment name must be non-empty [A-Za-z0-9_] only"
                    ));
                }
                let suffix: String = env.chars().map(|c| c.to_ascii_uppercase()).collect();
                Ok(format!("{}_{}", self.key_prefix(), suffix))
            }
            KeyNaming::Bundle => Ok(self.key_prefix().into()),
        }
    }

    /// Human-readable error when no keys are found.
    pub fn empty_error(self) -> String {
        match self {
            KeyNaming::Env => format!("no {}* entries", self.key_prefix()),
            KeyNaming::Bundle => format!("no {} entries", self.key_prefix()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn key_var_for_env_mapping() {
        assert_eq!(
            KeyNaming::Env.key_var_for(Path::new("/x/.env")).unwrap(),
            "DOTENV_PRIVATE_KEY"
        );
        assert_eq!(
            KeyNaming::Env
                .key_var_for(Path::new("/x/.env.production"))
                .unwrap(),
            "DOTENV_PRIVATE_KEY_PRODUCTION"
        );
        assert_eq!(
            KeyNaming::Env
                .key_var_for(Path::new("/x/.env.staging_v2"))
                .unwrap(),
            "DOTENV_PRIVATE_KEY_STAGING_V2"
        );
    }

    #[test]
    fn key_var_for_requires_the_dot_env_convention() {
        // Dotenv inputs must follow the .env[.<environment>] naming convention.
        assert!(KeyNaming::Env.key_var_for(Path::new("no-dot-env")).is_err());
    }

    #[test]
    fn key_var_for_rejects_aliasing_names() {
        // Reject lossy names that could alias another file's key variable.
        assert!(KeyNaming::Env.key_var_for(Path::new("/x/.env..x")).is_err());
        assert!(KeyNaming::Env.key_var_for(Path::new("/x/.env.-x")).is_err());
        assert!(KeyNaming::Env.key_var_for(Path::new("/x/.env.")).is_err());
        assert_eq!(
            KeyNaming::Env.key_var_for(Path::new("/x/.env._x")).unwrap(),
            "DOTENV_PRIVATE_KEY__X"
        );
    }

    #[test]
    fn key_var_for_bundle_is_constant() {
        assert_eq!(
            KeyNaming::Bundle
                .key_var_for(Path::new("/x/anything.json"))
                .unwrap(),
            "POSTMASTER_KEY"
        );
    }
}
