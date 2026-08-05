#![allow(clippy::unwrap_used, clippy::panic, missing_docs)]

use std::path::{Path, PathBuf};
use std::process::Command;

use postmaster::exec_config::ExecConfig;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn fixture(path: &str) -> PathBuf {
    repo_root().join(path)
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pm-exec-check-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run_check(config: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_postmaster"))
        .args(["exec", "--config"])
        .arg(config)
        .arg("--check")
        .output()
        .unwrap()
}

#[test]
fn docs_exec_schema_is_valid_json() {
    let raw = std::fs::read(fixture("docs/schema/exec.schema.json")).unwrap();
    let schema: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        schema.get("$schema").and_then(serde_json::Value::as_str),
        Some("https://json-schema.org/draft/2020-12/schema")
    );
    assert!(schema.get("$defs").is_some());
}

#[test]
fn docs_exec_examples_parse_and_validate() {
    for rel in [
        "docs/examples/exec-env.json",
        "docs/examples/exec-files.json",
        "docs/examples/exec-credentials-systemd.json",
        "docs/examples/exec-credentials-darwin.json",
    ] {
        let raw = std::fs::read(fixture(rel)).unwrap();
        let cfg: ExecConfig = serde_json::from_slice(&raw).unwrap_or_else(|e| {
            panic!("{rel}: failed to parse as ExecConfig: {e}");
        });
        cfg.validate_shape()
            .unwrap_or_else(|e| panic!("{rel}: failed validate_shape: {e}"));
    }
}

#[test]
fn exec_check_accepts_valid_shape_without_secret_state() {
    let out = run_check(&fixture("docs/examples/exec-env.json"));
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn exec_check_rejects_unknown_future_fields() {
    let d = tmpdir("unknown");
    let cfg = d.join("exec.json");
    std::fs::write(
        &cfg,
        r#"{"mode":"credentials","credential_keys":["DB_URL"],"adapter":"env"}"#,
    )
    .unwrap();

    let out = run_check(&cfg);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown field"), "stderr: {stderr}");
}

#[test]
fn exec_check_rejects_structurally_incomplete_credentials_fetch_config() {
    let d = tmpdir("missing-socket");
    let cfg = d.join("exec.json");
    std::fs::write(
        &cfg,
        r#"{
          "mode": "credentials",
          "credential_keys": ["DB_URL", "REDIS_URL"],
          "secrets_dir": "/private/var/run/postmaster/myapp",
          "sockets": {
            "DB_URL": "/private/var/run/postmaster-credd/myapp/DB_URL.sock"
          }
        }"#,
    )
    .unwrap();

    let out = run_check(&cfg);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("REDIS_URL: no socket mapped"),
        "stderr: {stderr}"
    );
}

#[test]
fn exec_check_rejects_store_path_private_key_source_without_reading_it() {
    let d = tmpdir("store-key");
    let cfg = d.join("exec.json");
    std::fs::write(
        &cfg,
        r#"{
          "mode": "env",
          "keys": [{"file": "/nix/store/example/.env.keys"}],
          "env_files": ["/nix/store/example/.env.production"]
        }"#,
    )
    .unwrap();

    let out = run_check(&cfg);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Nix store"), "stderr: {stderr}");
}

#[test]
fn exec_check_rejects_path_like_credential_source_names() {
    let d = tmpdir("credential-source");
    let cfg = d.join("exec.json");
    std::fs::write(
        &cfg,
        r#"{
          "mode": "env",
          "keys": [{"credential": "../postmaster-myapp"}],
          "env_files": ["/nix/store/example/.env.production"]
        }"#,
    )
    .unwrap();

    let out = run_check(&cfg);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("credential source"), "stderr: {stderr}");
}
