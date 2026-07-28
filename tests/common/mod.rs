//! Shared test support: builds dotenvx-compatible fixtures OFFLINE using
//! the same `ecies` crate postmaster decrypts with. Wire compatibility
//! with the published dotenvx CLI is pinned separately by the repo's
//! fixture verification (README); these helpers guard OUR semantics.
#![allow(dead_code, clippy::unwrap_used, clippy::panic, missing_docs)]

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

/// Fixed, committed TEST key — never use outside tests.
pub const TEST_SK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

pub fn test_pk_hex() -> String {
    let sk_bytes = hex::decode(TEST_SK_HEX).unwrap();
    let sk = ecies::SecretKey::parse_slice(&sk_bytes).unwrap();
    let pk = ecies::PublicKey::from_secret_key(&sk);
    hex::encode(pk.serialize_compressed())
}

/// Encrypt a value exactly as `dotenvx set` does: ECIES to the public key,
/// base64, `encrypted:` prefix.
pub fn enc(value: &str) -> String {
    let pk = hex::decode(test_pk_hex()).unwrap();
    let ct = ecies::encrypt(&pk, value.as_bytes()).unwrap();
    format!("encrypted:{}", BASE64.encode(ct))
}

pub fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "postmaster-exec-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

pub fn write_env_file(dir: &Path, name: &str, lines: &[String]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, format!("{}\n", lines.join("\n"))).unwrap();
    p
}

/// `.env.keys`-shaped file: env_suffix "" ⇒ DOTENV_PRIVATE_KEY,
/// "PRODUCTION" ⇒ DOTENV_PRIVATE_KEY_PRODUCTION. Values comma-joined
/// (rotation convention).
pub fn write_keys_file(dir: &Path, env_suffix: &str, sk_hexes: &[&str]) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let var = if env_suffix.is_empty() {
        "DOTENV_PRIVATE_KEY".to_string()
    } else {
        format!("DOTENV_PRIVATE_KEY_{env_suffix}")
    };
    let p = dir.join(".env.keys");
    fs::write(&p, format!("{var}=\"{}\"\n", sk_hexes.join(","))).unwrap();
    // KeyRing::load now enforces 0600-or-stricter permissions and euid
    // ownership (audit finding #1). The temp file must pass that check.
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    p
}
