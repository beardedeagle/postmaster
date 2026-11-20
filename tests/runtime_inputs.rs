//! Exercise launch input boundaries through the real CLI.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::fs;
use std::os::unix::ffi::OsStringExt as _;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn bounded_output(mut command: Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "command blocked: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn help_help_prints_top_level_help() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_postmaster"));
    command.args(["help", "help"]);
    let output = bounded_output(command);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, postmaster::config::HELP_TOP.as_bytes());
    assert!(output.stderr.is_empty());
}

#[test]
fn private_key_interpolation_fails_before_launch() {
    let dir = common::tmpdir("private-substitution");
    let keys = common::write_keys_file(&dir, "", &[common::TEST_SK_HEX]);
    let env = dir.join(".env");
    let config = dir.join("exec.json");
    fs::write(
        &config,
        serde_json::json!({"mode":"env", "keys":[{"file":keys}], "env_files":[env]}).to_string(),
    )
    .unwrap();
    for name in [
        "DOTENV_PRIVATE_KEY",
        "DOTENV_PRIVATE_KEY_PRODUCTION",
        "POSTMASTER_KEY",
        "POSTMASTER_KEY_FILE",
    ] {
        fs::write(&env, format!("LEAK=${{{name}}}\n")).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_postmaster"));
        command
            .args(["exec", "--config"])
            .arg(&config)
            .args(["--", "/bin/sh", "-c", "printf launched"])
            .env(name, "PRIVATE_SENTINEL");
        let output = bounded_output(command);
        assert!(!output.status.success(), "{name} reached the application");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("cannot be interpolated"), "{stderr}");
        assert!(!stderr.contains("PRIVATE_SENTINEL"));
    }
}

#[test]
fn dotenv_private_key_output_names_fail_explicitly() {
    let dir = common::tmpdir("reserved-dotenv-output");
    let keys = common::write_keys_file(&dir, "", &[common::TEST_SK_HEX]);
    let env = dir.join(".env");
    let config = dir.join("exec.json");
    fs::write(
        &config,
        serde_json::json!({"mode":"env", "keys":[{"file":keys}], "env_files":[env]}).to_string(),
    )
    .unwrap();
    for name in [
        "DOTENV_PRIVATE_KEY",
        "POSTMASTER_KEY",
        "POSTMASTER_KEY_PRODUCTION",
    ] {
        fs::write(&env, format!("{name}=private-output\n")).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_postmaster"));
        command
            .args(["exec", "--config"])
            .arg(&config)
            .args(["--", "/usr/bin/true"]);
        let output = bounded_output(command);
        assert!(
            !output.status.success(),
            "reserved output {name} was accepted"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("reserved"));
    }
}

#[test]
fn config_and_bundle_fifos_fail_without_waiting_for_a_writer() {
    let dir = common::tmpdir("regular-launch-inputs");
    let fifo = dir.join("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let keys = common::write_keys_file(&dir, "", &[common::TEST_SK_HEX]);
    fs::write(
        &keys,
        format!(
            "DOTENV_PRIVATE_KEY={}\nPOSTMASTER_KEY={}\n",
            common::TEST_SK_HEX,
            common::TEST_SK_HEX
        ),
    )
    .unwrap();
    let config = dir.join("exec.json");
    fs::write(
        &config,
        serde_json::json!({"mode":"env", "keys":[{"file":keys}], "bundle_files":[fifo]})
            .to_string(),
    )
    .unwrap();
    for path in [&fifo, &config] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_postmaster"));
        command
            .args(["exec", "--config"])
            .arg(path)
            .args(["--", "/usr/bin/true"]);
        let output = bounded_output(command);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("not a regular file"), "{stderr}");
    }
}

#[test]
fn unix_child_arguments_preserve_non_utf8_bytes() {
    let dir = common::tmpdir("unix-argv");
    let keys = common::write_keys_file(&dir, "", &[common::TEST_SK_HEX]);
    let env = common::write_env_file(&dir, ".env", &["A=hello".into()]);
    let config = dir.join("exec.json");
    fs::write(
        &config,
        serde_json::json!({"mode":"env", "keys":[{"file":keys}], "env_files":[env]}).to_string(),
    )
    .unwrap();
    let argument = std::ffi::OsString::from_vec(b"argument-\xff".to_vec());
    let mut command = Command::new(env!("CARGO_BIN_EXE_postmaster"));
    command
        .args(["exec", "--config"])
        .arg(config)
        .args(["--", "/bin/sh", "-c", "printf '%s' \"$1\"", "sh"])
        .arg(argument);
    let output = bounded_output(command);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"argument-\xff");
}

#[test]
fn systemd_credentials_require_regular_existing_files_without_reading_values() {
    let dir = common::tmpdir("systemd-credential-inputs");
    let config = dir.join("exec.json");
    fs::write(
        &config,
        r#"{"mode":"credentials","credential_keys":["DB"]}"#,
    )
    .unwrap();
    let credentials = dir.join("credentials");
    fs::create_dir(&credentials).unwrap();
    let credential = credentials.join("DB");
    for kind in ["missing", "directory", "empty-file"] {
        match kind {
            "directory" => fs::create_dir(&credential).unwrap(),
            "empty-file" => {
                fs::remove_dir(&credential).unwrap();
                fs::write(&credential, b"").unwrap();
            }
            _ => {}
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_postmaster"));
        command
            .args(["exec", "--config"])
            .arg(&config)
            .args(["--", "/usr/bin/true"])
            .env("CREDENTIALS_DIRECTORY", &credentials);
        let output = bounded_output(command);
        assert_eq!(
            output.status.success(),
            kind == "empty-file",
            "{kind}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
