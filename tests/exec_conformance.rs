#![allow(clippy::unwrap_used, clippy::panic, missing_docs)]

mod common;

use postmaster::adapter::KeyNaming;

use std::os::unix::fs::PermissionsExt;
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

#[test]
fn env_mode_injects_decrypted_metacharacter_values_inert() {
    let d = common::tmpdir("envmode");
    let val = "p@ss;|&`$(boom)\"'\nline2";
    let env = common::write_env_file(
        &d,
        ".env.production",
        &[
            format!("DOTENV_PUBLIC_KEY_PRODUCTION=\"{}\"", common::test_pk_hex()),
            format!("SECRET=\"{}\"", common::enc(val)),
            "PLAIN=just-plain".to_string(),
        ],
    );
    let keys = common::write_keys_file(&d, "PRODUCTION", &[common::TEST_SK_HEX]);
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"]}}"#,
            keys.display(),
            env.display()
        ),
    );
    let sh = format!(
        "printf %s \"$SECRET\" > '{d}'/secret.out && printf %s \"$PLAIN\" > '{d}'/plain.out && [ -z \"${{DOTENV_PUBLIC_KEY_PRODUCTION:-}}\" ]",
        d = d.display()
    );
    let out = run_exec(&cfg, &sh, &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(d.join("secret.out")).unwrap(), val.as_bytes());
    assert_eq!(std::fs::read(d.join("plain.out")).unwrap(), b"just-plain");
}

#[test]
fn env_mode_process_env_wins_without_overload() {
    let d = common::tmpdir("envwins");
    let val = "decrypted-value";
    let env = common::write_env_file(
        &d,
        ".env.production",
        &[
            format!("DOTENV_PUBLIC_KEY_PRODUCTION=\"{}\"", common::test_pk_hex()),
            format!("SECRET=\"{}\"", common::enc(val)),
        ],
    );
    let keys = common::write_keys_file(&d, "PRODUCTION", &[common::TEST_SK_HEX]);

    let cfg_no_overload = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"],"overload":false}}"#,
            keys.display(),
            env.display()
        ),
    );
    let sh1 = format!("printf %s \"$SECRET\" > '{d}'/out1", d = d.display());
    let out1 = run_exec(&cfg_no_overload, &sh1, &[("SECRET", "preset")]);
    assert!(
        out1.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out1.stderr)
    );
    assert_eq!(std::fs::read(d.join("out1")).unwrap(), b"preset");

    let cfg_overload = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"],"overload":true}}"#,
            keys.display(),
            env.display()
        ),
    );
    let sh2 = format!("printf %s \"$SECRET\" > '{d}'/out2", d = d.display());
    let out2 = run_exec(&cfg_overload, &sh2, &[("SECRET", "preset")]);
    assert!(
        out2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    assert_eq!(std::fs::read(d.join("out2")).unwrap(), val.as_bytes());
}

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
fn files_mode_writes_0600_pointers_and_passthrough() {
    let d = common::tmpdir("filesmode");
    let secrets_dir = d.join("secrets");
    std::fs::create_dir_all(&secrets_dir).unwrap();
    let val = "file-secret";
    let env = common::write_env_file(
        &d,
        ".env.production",
        &[
            format!("DOTENV_PUBLIC_KEY_PRODUCTION=\"{}\"", common::test_pk_hex()),
            format!("SECRET=\"{}\"", common::enc(val)),
            "PLAIN=passthrough-val".to_string(),
        ],
    );
    let keys = common::write_keys_file(&d, "PRODUCTION", &[common::TEST_SK_HEX]);
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"files","keys":[{{"file":"{}"}}],"env_files":["{}"],"secrets_dir":"{}","passthrough":["PLAIN"]}}"#,
            keys.display(),
            env.display(),
            secrets_dir.display()
        ),
    );
    let sh = format!(
        r#"printf %s "$SECRET_FILE" > '{d}'/secret_file.out && \
         cat "$SECRET_FILE" > '{d}'/secret_contents.out && \
         printf %s "${{SECRET:-UNSET}}" > '{d}'/secret_var.out && \
         printf %s "$PLAIN" > '{d}'/plain.out && \
         printf %s "${{POSTMASTER_SECRETS_DIR:-UNSET}}" > '{d}'/secretsdir.out"#,
        d = d.display()
    );
    let out = run_exec(&cfg, &sh, &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(d.join("secret_file.out")).unwrap(),
        secrets_dir.join("SECRET").display().to_string()
    );
    assert_eq!(
        std::fs::read(d.join("secret_contents.out")).unwrap(),
        val.as_bytes()
    );
    assert_eq!(std::fs::read(d.join("secret_var.out")).unwrap(), b"UNSET");
    assert_eq!(
        std::fs::read(d.join("plain.out")).unwrap(),
        b"passthrough-val"
    );
    assert_eq!(
        std::fs::read_to_string(d.join("secretsdir.out")).unwrap(),
        "UNSET"
    );

    let md = std::fs::metadata(secrets_dir.join("SECRET")).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o600);
}

#[test]
fn credentials_mode_systemd_pointers() {
    let d = common::tmpdir("credsystemd");
    let creds_dir = d.join("creds");
    std::fs::create_dir_all(&creds_dir).unwrap();
    std::fs::write(creds_dir.join("DB_URL"), "abc").unwrap();
    let cfg = write_config(&d, r#"{"mode":"credentials","credential_keys":["DB_URL"]}"#);
    let sh = format!(
        "printf %s \"$DB_URL_FILE\" > '{d}'/dbfile.out && cat \"$DB_URL_FILE\" > '{d}'/dbcontents.out",
        d = d.display()
    );
    let out = run_exec(
        &cfg,
        &sh,
        &[("CREDENTIALS_DIRECTORY", creds_dir.to_str().unwrap())],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(d.join("dbfile.out")).unwrap(),
        creds_dir.join("DB_URL").display().to_string()
    );
    assert_eq!(std::fs::read(d.join("dbcontents.out")).unwrap(), b"abc");

    // Without CREDENTIALS_DIRECTORY, the systemd path has nothing to point
    // at: fail closed. Explicitly remove from child to ensure hermeticity.
    let mut c = Command::new(env!("CARGO_BIN_EXE_postmaster"));
    c.args(["exec", "--config"])
        .arg(&cfg)
        .args(["--", "/bin/sh", "-c", "true"])
        .env_remove("CREDENTIALS_DIRECTORY");
    let out2 = c.output().unwrap();
    assert!(!out2.status.success());
}

#[test]
fn credentials_mode_fetch_loop() {
    let d = common::tmpdir("credfetch");
    let secrets_dir = d.join("secrets");
    std::fs::create_dir_all(&secrets_dir).unwrap();
    let sock = d.join("k.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let server = std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            use std::io::Write;
            let _ = s.write_all(b"s3cret");
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    });
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"credentials","credential_keys":["K"],"sockets":{{"K":"{}"}},"secrets_dir":"{}"}}"#,
            sock.display(),
            secrets_dir.display()
        ),
    );
    let sh = format!(
        "printf %s \"$CREDENTIALS_DIRECTORY\" > '{d}'/creddir.out && cat '{sd}'/K > '{d}'/kcontents.out",
        d = d.display(),
        sd = secrets_dir.display()
    );
    let out = run_exec(&cfg, &sh, &[]);
    server.join().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(d.join("creddir.out")).unwrap(),
        secrets_dir.display().to_string()
    );
    assert_eq!(std::fs::read(d.join("kcontents.out")).unwrap(), b"s3cret");
    let md = std::fs::metadata(secrets_dir.join("K")).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o600);
}

#[test]
fn multi_file_first_wins_and_overload_reverses() {
    let d = common::tmpdir("multifile");
    let f1 = common::write_env_file(&d, ".env", &["A=first-file".to_string()]);
    let f2 = common::write_env_file(&d, ".env.local", &["A=second-file".to_string()]);
    let keys = common::write_keys_file(&d, "", &[common::TEST_SK_HEX]);

    let cfg_first = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}","{}"],"overload":false}}"#,
            keys.display(),
            f1.display(),
            f2.display()
        ),
    );
    let sh1 = format!("printf %s \"$A\" > '{d}'/out1", d = d.display());
    let out1 = run_exec(&cfg_first, &sh1, &[]);
    assert!(
        out1.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out1.stderr)
    );
    assert_eq!(std::fs::read(d.join("out1")).unwrap(), b"first-file");

    let cfg_overload = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}","{}"],"overload":true}}"#,
            keys.display(),
            f1.display(),
            f2.display()
        ),
    );
    let sh2 = format!("printf %s \"$A\" > '{d}'/out2", d = d.display());
    let out2 = run_exec(&cfg_overload, &sh2, &[]);
    assert!(
        out2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    assert_eq!(std::fs::read(d.join("out2")).unwrap(), b"second-file");
}

#[test]
fn same_file_last_assignment_wins() {
    let d = common::tmpdir("samelastwin");
    let first_val = "first-value";
    let second_val = "second-value";
    let env = common::write_env_file(
        &d,
        ".env.production",
        &[
            format!("DOTENV_PUBLIC_KEY_PRODUCTION=\"{}\"", common::test_pk_hex()),
            format!("SECRET=\"{}\"", common::enc(first_val)),
            format!("SECRET=\"{}\"", common::enc(second_val)),
        ],
    );
    let keys = common::write_keys_file(&d, "PRODUCTION", &[common::TEST_SK_HEX]);
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"]}}"#,
            keys.display(),
            env.display()
        ),
    );
    let sh = format!("printf %s \"$SECRET\" > '{d}'/secret.out", d = d.display());
    let out = run_exec(&cfg, &sh, &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(d.join("secret.out")).unwrap(),
        second_val.as_bytes()
    );
}

#[test]
fn nul_in_env_value_fails_closed() {
    let d = common::tmpdir("nulval");
    let val = "before\0after";
    let env = common::write_env_file(
        &d,
        ".env.production",
        &[
            format!("DOTENV_PUBLIC_KEY_PRODUCTION=\"{}\"", common::test_pk_hex()),
            format!("SECRET=\"{}\"", common::enc(val)),
        ],
    );
    let keys = common::write_keys_file(&d, "PRODUCTION", &[common::TEST_SK_HEX]);

    // env mode: fails closed with a message about NUL.
    let cfg_env = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"]}}"#,
            keys.display(),
            env.display()
        ),
    );
    let out = run_exec(&cfg_env, "true", &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("NUL"), "stderr: {stderr}");

    // files mode: the exact bytes (including the NUL) reach the file.
    let secrets_dir = d.join("secrets");
    std::fs::create_dir_all(&secrets_dir).unwrap();
    let cfg_files = write_config(
        &d,
        &format!(
            r#"{{"mode":"files","keys":[{{"file":"{}"}}],"env_files":["{}"],"secrets_dir":"{}"}}"#,
            keys.display(),
            env.display(),
            secrets_dir.display()
        ),
    );
    let sh = format!(
        "cat '{sd}'/SECRET > '{d}'/out",
        sd = secrets_dir.display(),
        d = d.display()
    );
    let out2 = run_exec(&cfg_files, &sh, &[]);
    assert!(
        out2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    assert_eq!(std::fs::read(d.join("out")).unwrap(), val.as_bytes());
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
fn exec_rejects_non_identifier_key_at_exec_boundary() {
    let d = common::tmpdir("badkey");
    // A dotted key like BAD.KEY parses fine as dotenv but is_ident rejects it.
    let env = common::write_env_file(&d, ".env", &["BAD.KEY=oops".to_string()]);
    let keys = common::write_keys_file(&d, "", &[common::TEST_SK_HEX]);
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"]}}"#,
            keys.display(),
            env.display()
        ),
    );
    let out = run_exec(&cfg, "true", &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("non-identifier"),
        "expected 'non-identifier' in stderr, got: {stderr}"
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
