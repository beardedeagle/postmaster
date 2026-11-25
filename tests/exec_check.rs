#![allow(clippy::unwrap_used, clippy::panic, missing_docs)]

#[path = "../src/test_util/temp_dir.rs"]
mod temp_dir;

use std::path::{Path, PathBuf};
use std::process::Command;

use postmaster::exec_config::ExecConfig;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn fixture(path: &str) -> PathBuf {
    repo_root().join(path)
}

fn tmpdir(tag: &str) -> temp_dir::TestDir {
    temp_dir::TestDir::new(tag)
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
    let mut found = false;
    for entry in std::fs::read_dir(fixture("docs/examples")).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.as_encoded_bytes();
        if !name.starts_with(b"exec-") || !name.ends_with(b".json") {
            continue;
        }
        let path = entry.path();
        let example = path.display();
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{example}: {e}"));
        let cfg: ExecConfig = serde_json::from_slice(&raw).unwrap_or_else(|e| {
            panic!("{example}: failed to parse as ExecConfig: {e}");
        });
        cfg.validate_shape()
            .unwrap_or_else(|e| panic!("{example}: failed validate_shape: {e}"));
        found = true;
    }
    assert!(found, "no docs/examples/exec-*.json fixtures found");
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
            "DB_URL": {"path":"/private/var/run/postmaster-credd/myapp/DB_URL.sock", "protocol":"raw", "server_uid":0}
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

#[test]
fn docs_exec_schema_covers_every_exec_config_field() {
    use serde::de::{self, Deserialize, Deserializer, Visitor};
    use std::collections::BTreeSet;

    // Capture the field names provided by Serde's derived struct deserializer.
    struct CaptureFields<'capture>(&'capture mut Option<&'static [&'static str]>);

    impl<'de> Deserializer<'de> for CaptureFields<'_> {
        type Error = de::value::Error;

        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _name: &'static str,
            fields: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, Self::Error> {
            *self.0 = Some(fields);
            self.deserialize_any(visitor)
        }

        fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            Err(de::Error::custom(
                "field capture does not deserialize values",
            ))
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf option
            unit unit_struct newtype_struct seq tuple tuple_struct map enum identifier ignored_any
        }
    }

    let mut fields = None;
    assert!(ExecConfig::deserialize(CaptureFields(&mut fields)).is_err());
    let fields = fields.expect("ExecConfig must deserialize as a named struct");

    let raw = std::fs::read(fixture("docs/schema/exec.schema.json")).unwrap();
    let schema: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let properties = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .unwrap();
    assert_eq!(
        properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        fields.iter().copied().collect::<BTreeSet<_>>()
    );
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&serde_json::Value::Bool(false))
    );
}
