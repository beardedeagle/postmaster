use std::process::Command;

use crate::common;
use crate::{run_exec, write_config};

#[test]
fn rotation_second_key_decrypts() {
    let d = common::tmpdir("rotation");
    let val = "rotated-secret";
    let env = common::write_env_file(
        &d,
        ".env.production",
        &[
            format!("DOTENV_PUBLIC_KEY_PRODUCTION=\"{}\"", common::test_pk_hex()),
            format!("SECRET=\"{}\"", common::enc(val)),
        ],
    );
    let bogus = "22".repeat(32);
    let keys = common::write_keys_file(&d, "PRODUCTION", &[&bogus, common::TEST_SK_HEX]);
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"]}}"#,
            keys.display(),
            env.display()
        ),
    );
    let sh = format!("printf %s \"$SECRET\" > '{d}'/out", d = d.display());
    let out = run_exec(&cfg, &sh, &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(d.join("out")).unwrap(), val.as_bytes());
}

#[test]
fn strict_failure_refuses_exec() {
    let d = common::tmpdir("strictfail");
    // Encrypt with a DIFFERENT key than the one in our keyring, so
    // decryption must fail even though the ciphertext is well-formed.
    let other_sk_hex = "22".repeat(32);
    let other_sk_bytes = hex::decode(&other_sk_hex).unwrap();
    let other_sk = ecies::SecretKey::parse_slice(&other_sk_bytes).unwrap();
    let other_pk = ecies::PublicKey::from_secret_key(&other_sk);
    let ct = ecies::encrypt(&other_pk.serialize_compressed(), b"unreachable").unwrap();
    let b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(ct)
    };
    let env = common::write_env_file(
        &d,
        ".env.production",
        &[
            format!(
                "DOTENV_PUBLIC_KEY_PRODUCTION=\"{}\"",
                hex::encode(other_pk.serialize_compressed())
            ),
            format!("SECRET=\"encrypted:{b64}\""),
        ],
    );
    let keys = common::write_keys_file(&d, "PRODUCTION", &[common::TEST_SK_HEX]);
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"],"strict":true}}"#,
            keys.display(),
            env.display()
        ),
    );
    let sh = format!("printf %s \"$SECRET\" > '{d}'/out", d = d.display());
    let out = run_exec(&cfg, &sh, &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no key under"), "stderr: {stderr}");
    assert!(!d.join("out").exists());
}

#[test]
fn strict_false_skips_undecryptable_and_continues() {
    let d = common::tmpdir("laxskip");
    // GOOD decrypts with TEST_SK_HEX; BAD uses a different key so it fails.
    let other_sk_hex = "33".repeat(32);
    let other_sk_bytes = hex::decode(&other_sk_hex).unwrap();
    let other_sk = ecies::SecretKey::parse_slice(&other_sk_bytes).unwrap();
    let other_pk = ecies::PublicKey::from_secret_key(&other_sk);
    let bad_ct = ecies::encrypt(&other_pk.serialize_compressed(), b"unreachable").unwrap();
    let bad_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bad_ct)
    };

    let env = common::write_env_file(
        &d,
        ".env.production",
        &[
            format!("DOTENV_PUBLIC_KEY_PRODUCTION=\"{}\"", common::test_pk_hex()),
            format!("GOOD=\"{}\"", common::enc("lax-ok")),
            format!("BAD=\"encrypted:{bad_b64}\""),
        ],
    );
    let keys = common::write_keys_file(&d, "PRODUCTION", &[common::TEST_SK_HEX]);
    // strict:false: BAD should be skipped (logged), GOOD should still reach the child.
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"],"strict":false}}"#,
            keys.display(),
            env.display()
        ),
    );
    let sh = format!(
        "printf %s \"${{GOOD:-UNSET}}\" > '{d}'/good.out && printf %s \"${{BAD:-UNSET}}\" > '{d}'/bad.out",
        d = d.display()
    );
    let out = run_exec(&cfg, &sh, &[]);
    assert!(
        out.status.success(),
        "strict:false should continue past undecryptable value and launch the child\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(d.join("good.out")).unwrap(), b"lax-ok");
    // BAD was skipped: the child sees no BAD env var.
    assert_eq!(std::fs::read(d.join("bad.out")).unwrap(), b"UNSET");
    // The stderr should mention the skip.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("non-strict: skipping BAD"),
        "expected skip log in stderr, got: {stderr}"
    );
}

#[test]
fn verify_keys_aborts_on_stale_keys_with_strict_false() {
    // Audit finding #4: --verify-keys should catch stale keys even when
    // strict is false. Encrypt with a different key than the one in the
    // keyring, set strict:false, and pass --verify-keys. The exec must
    // abort with a --verify-keys error rather than launching the child
    // with no secrets.
    let d = common::tmpdir("verifykeys");
    let other_sk_hex = "33".repeat(32);
    let other_sk_bytes = hex::decode(&other_sk_hex).unwrap();
    let other_sk = ecies::SecretKey::parse_slice(&other_sk_bytes).unwrap();
    let other_pk = ecies::PublicKey::from_secret_key(&other_sk);
    let ct = ecies::encrypt(&other_pk.serialize_compressed(), b"stale-secret").unwrap();
    let b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(ct)
    };
    let env = common::write_env_file(
        &d,
        ".env.production",
        &[
            format!(
                "DOTENV_PUBLIC_KEY_PRODUCTION=\"{}\"",
                hex::encode(other_pk.serialize_compressed())
            ),
            format!("SECRET=\"encrypted:{b64}\""),
        ],
    );
    // Keyring has the TEST_SK_HEX key, NOT the other key — keys are stale.
    let keys = common::write_keys_file(&d, "PRODUCTION", &[common::TEST_SK_HEX]);
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"],"strict":false}}"#,
            keys.display(),
            env.display()
        ),
    );
    // Without --verify-keys, strict:false would silently skip and succeed.
    let sh = "true".to_string();
    let out_no_verify = run_exec(&cfg, &sh, &[]);
    assert!(
        out_no_verify.status.success(),
        "without --verify-keys, strict:false should silently skip: {}",
        String::from_utf8_lossy(&out_no_verify.stderr)
    );

    // With --verify-keys, the stale keys must be caught.
    let mut c = Command::new(env!("CARGO_BIN_EXE_postmaster"));
    c.args(["exec", "--config"])
        .arg(&cfg)
        .args(["--verify-keys", "--", "true"])
        .env_remove("SECRET");
    let out = c.output().unwrap();
    assert!(
        !out.status.success(),
        "--verify-keys should abort on stale keys"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--verify-keys failed"),
        "expected '--verify-keys failed' in stderr, got: {stderr}"
    );
}

#[test]
fn verify_keys_aborts_on_partial_failure_with_strict_false() {
    // Audit 2026-08-02 A3: with strict:false, resolution silently skips
    // undecryptable values. When SOME values still decrypt, the resolved
    // set is non-empty and the old freshness check passed — the child
    // launched with a partial secret set. --verify-keys must now abort
    // on any recorded skip.
    let d = common::tmpdir("verifykeys-partial");
    let other_sk_hex = "33".repeat(32);
    let other_sk_bytes = hex::decode(&other_sk_hex).unwrap();
    let other_sk = ecies::SecretKey::parse_slice(&other_sk_bytes).unwrap();
    let other_pk = ecies::PublicKey::from_secret_key(&other_sk);
    let stale_ct = ecies::encrypt(&other_pk.serialize_compressed(), b"stale-secret").unwrap();
    let stale_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(stale_ct)
    };
    let env = common::write_env_file(
        &d,
        ".env.production",
        &[
            format!("DOTENV_PUBLIC_KEY_PRODUCTION=\"{}\"", common::test_pk_hex()),
            // Decrypts with the keyring's key — the resolved set is
            // non-empty, which is what fooled the old check.
            format!("SECRET_GOOD=\"{}\"", common::enc("good-secret")),
            // Encrypted to a key NOT in the keyring — skipped under
            // strict:false. This is the partial-rotation case.
            format!("SECRET_STALE=\"encrypted:{stale_b64}\""),
        ],
    );
    let keys = common::write_keys_file(&d, "PRODUCTION", &[common::TEST_SK_HEX]);
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"],"strict":false}}"#,
            keys.display(),
            env.display()
        ),
    );
    // Without --verify-keys the partial set launches silently:
    // SECRET_GOOD is served, SECRET_STALE is dropped.
    let out_no_verify = run_exec(&cfg, "test \"$SECRET_GOOD\" = good-secret", &[]);
    assert!(
        out_no_verify.status.success(),
        "without --verify-keys, strict:false should silently serve the partial set: {}",
        String::from_utf8_lossy(&out_no_verify.stderr)
    );

    // With --verify-keys, the recorded skip must abort the launch.
    let mut c = Command::new(env!("CARGO_BIN_EXE_postmaster"));
    c.args(["exec", "--config"])
        .arg(&cfg)
        .args(["--verify-keys", "--", "true"])
        .env_remove("SECRET_GOOD")
        .env_remove("SECRET_STALE");
    let out = c.output().unwrap();
    assert!(
        !out.status.success(),
        "--verify-keys should abort on a partial decryption failure"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--verify-keys failed"),
        "expected '--verify-keys failed' in stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("SECRET_STALE"),
        "expected the skipped key name in stderr, got: {stderr}"
    );
}
