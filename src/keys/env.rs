//! Process-environment key source (external provisioning).

use zeroize::Zeroizing;

use super::KeyRing;
use crate::adapter::KeyNaming;

/// True for exactly `PREFIX` or `PREFIX_<nonempty suffix>`. A bare
/// prefix match would slurp unrelated variables like
/// `DOTENV_PRIVATE_KEYFOO` as key material (audit 2026-08-02 A16).
pub(crate) fn is_key_var_name(prefix: &str, name: &str) -> bool {
    name == prefix
        || name
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.len() > 1 && rest.starts_with('_'))
}

/// Implementation of [`KeyRing::from_env`]; the contract is documented on
/// the method.
pub(super) fn from_env(naming: KeyNaming) -> Result<KeyRing, String> {
    let prefix = naming.key_prefix();
    KeyRing::from_pairs(
        std::env::vars()
            .filter(|(k, _)| is_key_var_name(prefix, k))
            .map(|(k, v)| (k, Zeroizing::new(v))),
        naming,
    )
    .map_err(|e| format!("environment: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, unused_qualifications)]
mod tests {
    use super::*;
    use crate::test_util::ENV_LOCK;

    #[test]
    fn is_key_var_name_rules() {
        // audit 2026-08-02 A16: only `PREFIX` or `PREFIX_<suffix>` match;
        // prefix-substring collisions are rejected.
        let p = "DOTENV_PRIVATE_KEY";
        assert!(is_key_var_name(p, "DOTENV_PRIVATE_KEY"));
        assert!(is_key_var_name(p, "DOTENV_PRIVATE_KEY_PRODUCTION"));
        assert!(!is_key_var_name(p, "DOTENV_PRIVATE_KEYFOO"));
        assert!(!is_key_var_name(p, "DOTENV_PRIVATE_KEY_")); // empty suffix
        assert!(!is_key_var_name(p, "DOTENV_PRIVATE_KE"));
        assert!(!is_key_var_name(p, "XDOTENV_PRIVATE_KEY"));
    }

    #[test]
    fn from_env_loads_and_fails_closed() {
        // from_env reads ALL DOTENV_PRIVATE_KEY* vars from the process
        // environment and delegates to from_pairs. This is a single test
        // (not two) because env mutation is global; the shared ENV_LOCK
        // serializes it against every other env-mutating test. Using a
        // unique suffix to avoid collision with any ambient vars in the
        // test runner.
        //
        // SAFETY: set_var/remove_var are unsafe on edition 2024 (not
        // thread-safe). Serialized via the process-wide ENV_LOCK
        // (crate::test_util) shared by every env-mutating test.
        let _guard = ENV_LOCK.lock().unwrap();
        let var_name = "DOTENV_PRIVATE_KEY_TESTFROMENV";
        let key_hex = "aa".repeat(32);

        // Positive path: set a valid key, from_env succeeds.
        unsafe {
            std::env::set_var(var_name, &key_hex);
        }
        let ring = KeyRing::from_env(KeyNaming::Env);
        unsafe {
            std::env::remove_var(var_name);
        }
        let ring = ring.expect("from_env should succeed with a valid key set");
        let candidates = ring
            .0
            .get(var_name)
            .expect("ring should contain the key we set");
        assert_eq!(candidates.len(), 1, "exactly one candidate expected");
        assert_eq!(&candidates[0][..], &[0xaa; 32]);

        // Negative path: set an invalid hex value, from_env fails closed
        // with an "environment:" prefixed error.
        unsafe {
            std::env::set_var(var_name, "not-valid-hex-at-all");
        }
        let err = KeyRing::from_env(KeyNaming::Env);
        unsafe {
            std::env::remove_var(var_name);
        }
        let err = err.expect_err("from_env should fail on invalid hex");
        assert!(
            err.starts_with("environment:"),
            "expected 'environment:' prefix, got: {err}"
        );

        // Also verify the from_pairs empty-error path directly: no
        // DOTENV_PRIVATE_KEY* entries at all should be an error.
        assert!(
            KeyRing::from_pairs(
                [(
                    "NOT_A_DOTENV_KEY".to_string(),
                    Zeroizing::new("x".to_string())
                )],
                KeyNaming::Env,
            )
            .is_err()
        );
    }
}
