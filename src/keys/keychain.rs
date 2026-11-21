//! macOS Keychain source using the default keychain search list.

use std::collections::HashSet;

use zeroize::Zeroizing;

use super::KeyRing;
use crate::adapter::KeyNaming;

/// Yield each requested Keychain account once, preserving first-request order.
fn unique_accounts(vars: &[String]) -> impl Iterator<Item = &String> {
    let mut seen = HashSet::new();
    vars.iter().filter(move |var| seen.insert(*var))
}

/// Implementation of [`KeyRing::from_keychain`]; the contract is
/// documented on the method.
#[cfg(target_os = "macos")]
pub(super) fn from_keychain(
    service: &str,
    vars: &[String],
    namings: &[KeyNaming],
) -> Result<KeyRing, String> {
    // Reads go through the Security.framework API, not the /usr/bin/security CLI: no
    // subprocess, no argv, and no stdout buffer holding key material — the
    // UTF-8-failure path validates from a borrow so the error never carries the bytes.
    let mut pairs = Vec::new();
    for var in unique_accounts(vars) {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn repeated_accounts_preserve_rotation_and_request_order() {
        let vars = [
            KeyNaming::Bundle
                .key_var_for(Path::new("/x/first.json"))
                .unwrap(),
            KeyNaming::Env
                .key_var_for(Path::new("/x/.env.production"))
                .unwrap(),
            KeyNaming::Bundle
                .key_var_for(Path::new("/x/second.json"))
                .unwrap(),
            KeyNaming::Env
                .key_var_for(Path::new("/y/.env.production"))
                .unwrap(),
        ];
        let accounts = unique_accounts(&vars).collect::<Vec<_>>();
        assert_eq!(accounts, [&vars[0], &vars[1]]);
        let ring = KeyRing::from_pairs(
            accounts.into_iter().map(|name| {
                (
                    name.clone(),
                    Zeroizing::new(format!("{},{}", "11".repeat(32), "22".repeat(32))),
                )
            }),
            &[KeyNaming::Env, KeyNaming::Bundle],
        )
        .unwrap();
        for name in [&vars[0], &vars[1]] {
            let keys = ring.candidates(name).unwrap();
            assert_eq!(keys.len(), 2);
            assert_eq!(&*keys[0], &[0x11; 32]);
            assert_eq!(&*keys[1], &[0x22; 32]);
        }
    }
}
