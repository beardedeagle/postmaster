use std::process::Command;

use crate::common;
use crate::{run_exec, write_config};

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
         printf %s "${{POSTMASTER_SECRETS_DIR:-UNSET}}" > '{d}'/secretsdir.out && \
         find "$SECRET_FILE" -perm 600 -print | grep -q ."#,
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

    // The 0600 check ran inside the service above (the file must be
    // exactly 0600 while it exists). Once the service exits, the sibling
    // monitor removes the plaintext (cleanup on every death path) —
    // run_exec returning implies the monitor has already exited: it
    // inherits postmaster's stdout/stderr pipe ends across the fork and
    // output() only sees EOF after the monitor's cleanup has run.
    assert!(
        !secrets_dir.join("SECRET").exists(),
        "the sibling monitor must remove plaintext files on service death"
    );
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
        "printf %s \"$CREDENTIALS_DIRECTORY\" > '{d}'/creddir.out && cat '{sd}'/K > '{d}'/kcontents.out && find '{sd}/K' -perm 600 -print | grep -q .",
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
    // The 0600 check ran inside the service above; after the service
    // exits the sibling monitor removes the plaintext (see the files-mode
    // test for why run_exec returning implies the monitor has exited).
    assert!(
        !secrets_dir.join("K").exists(),
        "the sibling monitor must remove plaintext files on service death"
    );
}
