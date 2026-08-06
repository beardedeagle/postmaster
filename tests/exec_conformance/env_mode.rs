use crate::common;
use crate::{run_exec, write_config};

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
