#![allow(clippy::unwrap_used, clippy::panic, missing_docs)]

mod bundle;
#[path = "../common/mod.rs"]
mod common;
mod env_mode;
mod files_mode;
mod keys_verify;

use postmaster::adapter::KeyNaming;

use std::path::Path;
use std::process::Command;

#[test]
fn helper_ciphertext_decrypts_with_test_key() {
    let v = common::enc("hello $(rm -rf /) `x` \"q\" \nline2");
    let b64 = v.strip_prefix("encrypted:").unwrap();
    let ct = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap()
    };
    let sk = hex::decode(common::TEST_SK_HEX).unwrap();
    let pt = ecies::decrypt(&sk, &ct).unwrap();
    assert_eq!(pt, b"hello $(rm -rf /) `x` \"q\" \nline2");
}

#[test]
fn wrapped_base64_ciphertext_decrypts() {
    // Test that decrypt_value tolerates ASCII whitespace in base64 payloads,
    // matching dotenvx-rs's lenient decoding behavior.
    let plaintext = "wrapped-value";
    let v = common::enc(plaintext);
    let b64 = v.strip_prefix("encrypted:").unwrap();

    // Wrap the base64 by inserting newlines every 20 chars
    let mut wrapped = String::from("encrypted:");
    for (i, c) in b64.chars().enumerate() {
        if i > 0 && i % 20 == 0 {
            wrapped.push('\n');
        }
        wrapped.push(c);
    }
    wrapped.push('\n');

    // Create a temporary keys file with TEST_SK_HEX
    let d = common::tmpdir("wrapped-base64");
    common::write_keys_file(&d, "", &[common::TEST_SK_HEX]);
    let keys_path = d.join(".env.keys");

    // Load the key ring
    let ring = postmaster::keys::KeyRing::load(&keys_path, KeyNaming::Env).unwrap();

    // Create a dummy env file path for error messages
    let dummy_env = d.join(".env");

    // decrypt_value should handle the wrapped (whitespace-containing) payload
    let result =
        postmaster::keys::decrypt_value(&dummy_env, "TEST_VAR", &wrapped, &ring, KeyNaming::Env);

    assert!(result.is_ok(), "wrapped base64 should decrypt successfully");
    let decrypted = result.unwrap();
    assert_eq!(decrypted.as_slice(), plaintext.as_bytes());
}

fn run_exec(config: &Path, sh: &str, envs: &[(&str, &str)]) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_postmaster"));
    c.args(["exec", "--config"])
        .arg(config)
        .args(["--", "/bin/sh", "-c", sh])
        // Hermeticity: an ambient SECRET/PLAIN/A in the test runner's own
        // environment would flip the precedence-test outcomes below, since
        // these are exactly the value-variable names the suite asserts on.
        .env_remove("SECRET")
        .env_remove("PLAIN")
        .env_remove("A");
    for (k, v) in envs {
        c.env(k, v);
    }
    c.output().unwrap()
}

fn write_config(dir: &Path, json: &str) -> std::path::PathBuf {
    let p = dir.join("exec.json");
    std::fs::write(&p, json).unwrap();
    p
}
