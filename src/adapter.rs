//! Adapter enum for key-naming conventions.
//!
//! Different input adapters (`.env` files, `postmaster_bundle`, etc.) have
//! different conventions for how private keys are named, how metadata keys
//! are filtered, and how artifact filenames map to key variable names. This
//! enum encapsulates those conventions so the core key-loading and
//! resolution logic is adapter-neutral.
//!
//! An enum (not a trait) is used deliberately: the set of adapters is small
//! and security-critical. Exhaustive match ensures every call site handles
//! every adapter at compile time — adding a variant is a deliberate act
//! that forces all code paths to acknowledge it.

#![allow(missing_docs, missing_debug_implementations)]

use std::path::Path;

/// The key-naming convention for a secret input adapter.
///
/// Adding a variant is a deliberate act: every match on this enum must
/// handle the new variant or the code will not compile. This is the
/// security boundary — no adapter can silently slip through unhandled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyNaming {
    /// The `.env` file adapter. Uses `DOTENV_PRIVATE_KEY[_<ENV>]` as its
    /// key variable naming, `DOTENV_` as its metadata prefix, and maps
    /// `.env.production` → `DOTENV_PRIVATE_KEY_PRODUCTION`.
    Env,
    /// The `postmaster_bundle` adapter. Uses `POSTMASTER_KEY` as its
    /// key variable naming (no per-environment suffix — the bundle's
    /// `profile` field handles environment selection). No metadata
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
    /// key variable regardless of filename (the `profile` field inside
    /// the bundle handles environment selection).
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
                let suffix: String = env
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() {
                            c.to_ascii_uppercase()
                        } else {
                            '_'
                        }
                    })
                    .collect();
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
