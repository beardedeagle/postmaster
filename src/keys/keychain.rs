//! macOS System keychain key source.

use zeroize::Zeroizing;

use super::KeyRing;
use crate::adapter::KeyNaming;

/// Implementation of [`KeyRing::from_keychain`]; the contract is
/// documented on the method.
#[cfg(target_os = "macos")]
pub(super) fn from_keychain(
    service: &str,
    vars: &[String],
    namings: &[KeyNaming],
) -> Result<KeyRing, String> {
    // Reads go through the Security.framework API, not the
    // /usr/bin/security CLI (F1 direction): no subprocess, no argv,
    // and no stdout buffer holding key material — the UTF-8-failure
    // path validates from a borrow so the error never carries the
    // bytes (audit 2026-08-02 A17).
    let mut pairs = Vec::new();
    for var in vars {
        let bytes = Zeroizing::new(
            security_framework::passwords::get_generic_password(service, var).map_err(|_| {
                format!("keychain {service}: no item for account {var} (fail closed)")
            })?,
        );
        let s = std::str::from_utf8(&bytes[..])
            .map_err(|_| format!("keychain {service}/{var}: not UTF-8"))?;
        // from_pairs trims each comma-separated candidate itself, so
        // no separate trim is needed here.
        pairs.push((var.clone(), Zeroizing::new(s.to_string())));
    }
    KeyRing::from_pairs(pairs, namings).map_err(|e| format!("keychain {service}: {e}"))
}
