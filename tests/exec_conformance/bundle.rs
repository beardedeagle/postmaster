//! Bundle conformance tests.
//!
//! End-to-end bundle exec coverage: the actual binary, a real bundle
//! file, and key material loaded through `load_ring` — the seam where
//! the bundle-ring gap lived (unit tests build rings directly and never
//! saw it).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::common;
use crate::{run_exec, write_config};

/// Encrypt `value` for the shared test key with AAD = the entry name,
/// exactly as the bundle adapter's suite requires.
fn enc_entry(name: &str, value: &str) -> String {
    let pk = hex::decode(common::test_pk_hex()).unwrap();
    let ct = common::aad_fixture::encrypt(&pk, value.as_bytes(), name.as_bytes());
    BASE64.encode(ct)
}

/// Write a v1 bundle file with the given (name, value) utf8 entries.
fn write_bundle(dir: &std::path::Path, entries: &[(&str, &str)]) -> std::path::PathBuf {
    let entries: serde_json::Map<String, serde_json::Value> = entries
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                serde_json::json!({
                    "encoding": "utf8",
                    "ciphertext": enc_entry(name, value),
                }),
            )
        })
        .collect();
    let bundle = serde_json::json!({
        "format": "postmaster.bundle",
        "version": 1,
        "profile": "conformance",
        "suite": "ecies-secp256k1-hkdf-sha256-aes-256-gcm-entry-aad",
        "recipients": [{ "id": "test", "public_key": common::test_pk_hex() }],
        "entries": entries,
    });
    let p = dir.join("secrets.bundle.json");
    std::fs::write(&p, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
    p
}

/// A keys file carrying `POSTMASTER_KEY` (and optionally
/// `DOTENV_PRIVATE_KEY`), with the permissions `KeyRing::load` enforces.
fn write_keys(dir: &std::path::Path, with_dotenv: bool) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let mut content = format!("POSTMASTER_KEY=\"{}\"\n", common::TEST_SK_HEX);
    if with_dotenv {
        content.push_str(&format!("DOTENV_PRIVATE_KEY=\"{}\"\n", common::TEST_SK_HEX));
    }
    let p = dir.join(".env.keys");
    std::fs::write(&p, content).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

#[test]
fn bundle_exec_loads_postmaster_key_through_load_ring() {
    // Regression for the bundle-ring gap: load_ring hardcoded
    // KeyNaming::Env at every source leg, so POSTMASTER_KEY never entered
    // the ring and EVERY bundle config failed at exec with "key ring has
    // no POSTMASTER_KEY entry". This test drives the real binary through
    // load_ring; it fails on the old code and passes on the fix.
    let d = common::tmpdir("bundlee2e");
    let bundle = write_bundle(&d, &[("SECRET", "bundle-secret-value")]);
    let keys = write_keys(&d, false);
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"bundle_files":["{}"]}}"#,
            keys.display(),
            bundle.display()
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
        b"bundle-secret-value"
    );
}

#[test]
fn exec_private_key_variables_are_not_inherited() {
    let d = common::tmpdir("private-key-env");
    let env = common::write_env_file(
        &d,
        ".env",
        &[
            format!("PLAIN=\"{}\"", common::enc("from-env")),
            format!(
                "POSTMASTER_KEY_STAGING=\"{}\"",
                common::enc("reserved-output")
            ),
        ],
    );
    let bundle = write_bundle(&d, &[("SECRET", "from-bundle")]);
    let keys = write_keys(&d, true);
    for (mode, file_source) in [
        ("env", false),
        ("env", true),
        ("files", false),
        ("files", true),
        ("credentials", false),
    ] {
        let secrets = d.join(format!("{mode}-{file_source}"));
        std::fs::create_dir(&secrets).unwrap();
        let mut config = serde_json::json!({"mode": mode});
        if mode == "credentials" {
            std::fs::write(secrets.join("SECRET"), "from-bundle").unwrap();
            config["credential_keys"] = serde_json::json!(["SECRET"]);
        } else {
            config["keys"] = if file_source {
                serde_json::json!([{"file": keys}])
            } else {
                serde_json::json!(["environment"])
            };
            config["env_files"] = serde_json::json!([env]);
            config["bundle_files"] = serde_json::json!([bundle]);
            config["overload"] = serde_json::json!(true);
            if mode == "files" {
                config["secrets_dir"] = serde_json::json!(secrets);
            }
        }
        let cfg = write_config(&d, &config.to_string());
        let sh = r#"
            [ "${DOTENV_PRIVATE_KEY+x}${DOTENV_PRIVATE_KEY_PRODUCTION+x}${POSTMASTER_KEY+x}${POSTMASTER_KEY_PRODUCTION+x}${POSTMASTER_KEY_STAGING+x}${POSTMASTER_KEY_STAGING_FILE+x}" = "" ] || {
                echo 'private key variable reached the application' >&2; exit 42;
            }
            [ "$DOTENV_PRIVATE_KEYFOO" = keep-dotenv ] &&
            [ "$POSTMASTER_KEYFOO" = keep-bundle ] &&
            [ "$HOME" = /postmaster-test-home ] && [ "$PATH" = /usr/bin:/bin ] || exit 43
            if [ -n "${SECRET_FILE:-}" ]; then
                [ "$(cat "$SECRET_FILE")" = from-bundle ] || exit 44
                if [ -n "${PLAIN_FILE:-}" ]; then
                    [ "$(cat "$PLAIN_FILE")" = from-env ] || exit 45
                fi
            else
                [ "$SECRET" = from-bundle ] && [ "$PLAIN" = from-env ] || exit 46
            fi
        "#;
        let out = run_exec(
            &cfg,
            sh,
            &[
                ("DOTENV_PRIVATE_KEY", common::TEST_SK_HEX),
                ("DOTENV_PRIVATE_KEY_PRODUCTION", common::TEST_SK_HEX),
                ("POSTMASTER_KEY", common::TEST_SK_HEX),
                ("POSTMASTER_KEY_PRODUCTION", common::TEST_SK_HEX),
                ("DOTENV_PRIVATE_KEYFOO", "keep-dotenv"),
                ("POSTMASTER_KEYFOO", "keep-bundle"),
                ("HOME", "/postmaster-test-home"),
                ("PATH", "/usr/bin:/bin"),
                ("CREDENTIALS_DIRECTORY", secrets.to_str().unwrap()),
            ],
        );
        assert!(
            out.status.success(),
            "mode:{mode}, file_source:{file_source}, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn bundle_private_key_entry_names_fail_before_launch() {
    let d = common::tmpdir("reserved-bundle-keys");
    let keys = write_keys(&d, false);
    for name in [
        "DOTENV_PRIVATE_KEY",
        "DOTENV_PRIVATE_KEY_PRODUCTION",
        "POSTMASTER_KEY",
        "POSTMASTER_KEY_PRODUCTION",
    ] {
        let bundle = write_bundle(&d, &[(name, "reserved-output")]);
        let cfg = write_config(
            &d,
            &serde_json::json!({
                "mode": "env",
                "keys": [{"file": keys}],
                "bundle_files": [bundle],
                "strict": false,
                "overload": true,
            })
            .to_string(),
        );
        let marker = d.join("started");
        let out = run_exec(&cfg, &format!("echo started > '{}'", marker.display()), &[]);
        assert!(!out.status.success(), "reserved entry {name} was accepted");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(name) && stderr.contains("reserved"),
            "{stderr}"
        );
        assert!(
            !marker.exists(),
            "reserved entry {name} started the command"
        );
    }
}

#[test]
fn mixed_env_and_bundle_exec_resolves_both_adapters() {
    // A config with both env_files and bundle_files requires BOTH
    // namings in one ring (the adapter-aware load_ring signature's
    // multi-naming path).
    let d = common::tmpdir("bundle-mixed");
    let val = "p@ss;|&`$(boom)\"'\nline2";
    let env = common::write_env_file(&d, ".env", &[format!("PLAIN=\"{}\"", common::enc(val))]);
    let bundle = write_bundle(&d, &[("SECRET", "from-bundle")]);
    let keys = write_keys(&d, true);
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"env_files":["{}"],"bundle_files":["{}"]}}"#,
            keys.display(),
            env.display(),
            bundle.display()
        ),
    );
    let sh = format!(
        "printf %s \"$SECRET\" > '{d}'/secret.out && printf %s \"$PLAIN\" > '{d}'/plain.out",
        d = d.display()
    );
    let out = run_exec(&cfg, &sh, &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(d.join("secret.out")).unwrap(), b"from-bundle");
    assert_eq!(std::fs::read(d.join("plain.out")).unwrap(), val.as_bytes());
}

#[test]
fn bundle_exec_refuses_symlinked_bundle_file() {
    // sweep 2026-08-07 T5: the O_NOFOLLOW open on bundle ciphertext
    // (audit 2026-08-02 A13) must hold end-to-end — a planted symlink at
    // a configured bundle path is a hard error, never a read-through.
    let d = common::tmpdir("bundle-symlink");
    let bundle = write_bundle(&d, &[("SECRET", "unreachable")]);
    let keys = write_keys(&d, false);
    let link = d.join("linked.bundle.json");
    std::os::unix::fs::symlink(&bundle, &link).unwrap();
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"bundle_files":["{}"]}}"#,
            keys.display(),
            link.display()
        ),
    );
    let out = run_exec(&cfg, "true", &[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
}

#[test]
fn bundle_env_precedence_matches_env_adapter() {
    // sweep 2026-08-07 T10: bundle entries follow the same precedence
    // contract as .env values — the process environment wins unless
    // overload.
    let d = common::tmpdir("bundle-prec");
    let bundle = write_bundle(&d, &[("SECRET", "from-bundle")]);
    let keys = write_keys(&d, false);
    let cfg = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"bundle_files":["{}"],"overload":false}}"#,
            keys.display(),
            bundle.display()
        ),
    );
    let sh = format!("printf %s \"$SECRET\" > '{d}'/out1", d = d.display());
    let out = run_exec(&cfg, &sh, &[("SECRET", "preset")]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(d.join("out1")).unwrap(), b"preset");

    let cfg_overload = write_config(
        &d,
        &format!(
            r#"{{"mode":"env","keys":[{{"file":"{}"}}],"bundle_files":["{}"],"overload":true}}"#,
            keys.display(),
            bundle.display()
        ),
    );
    let sh2 = format!("printf %s \"$SECRET\" > '{d}'/out2", d = d.display());
    let out2 = run_exec(&cfg_overload, &sh2, &[("SECRET", "preset")]);
    assert!(
        out2.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    assert_eq!(std::fs::read(d.join("out2")).unwrap(), b"from-bundle");
}

#[test]
fn bundle_files_follow_first_or_last_wins_precedence() {
    let d = common::tmpdir("bundle-file-precedence");
    let first_dir = d.join("first");
    let last_dir = d.join("last");
    std::fs::create_dir(&first_dir).unwrap();
    std::fs::create_dir(&last_dir).unwrap();
    let first = write_bundle(&first_dir, &[("SECRET", "first-bundle"), ("FIRST", "one")]);
    let last = write_bundle(&last_dir, &[("SECRET", "last-bundle"), ("LAST", "two")]);
    let env = common::write_env_file(&d, ".env", &[format!("SECRET={}", common::enc("from-env"))]);
    let keys = write_keys(&d, true);
    for mode in ["env", "files"] {
        for include_env in [false, true] {
            for overload in [false, true] {
                let mut config = serde_json::json!({
                    "mode": mode,
                    "keys": [{"file": keys}],
                    "bundle_files": [first, last],
                    "overload": overload,
                });
                if include_env {
                    config["env_files"] = serde_json::json!([env]);
                }
                if mode == "files" {
                    let dir = d.join(format!("files-{include_env}-{overload}"));
                    std::fs::create_dir(&dir).unwrap();
                    config["secrets_dir"] = serde_json::json!(dir);
                }
                let cfg = write_config(&d, &config.to_string());
                let sh = if mode == "files" {
                    "cat \"$SECRET_FILE\"; printf '|'; cat \"$FIRST_FILE\"; printf '|'; cat \"$LAST_FILE\""
                } else {
                    "printf '%s|%s|%s' \"$SECRET\" \"$FIRST\" \"$LAST\""
                };
                let out = run_exec(&cfg, sh, &[]);
                assert!(
                    out.status.success(),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                let expected = if overload {
                    "last-bundle|one|two"
                } else if include_env {
                    "from-env|one|two"
                } else {
                    "first-bundle|one|two"
                };
                assert_eq!(
                    out.stdout,
                    expected.as_bytes(),
                    "mode:{mode}, include_env:{include_env}, overload:{overload}"
                );
            }
        }
    }
}

#[test]
fn bundle_shadowed_nul_value_still_fails_closed() {
    let d = common::tmpdir("bundle-shadowed-nul");
    let first_dir = d.join("first");
    std::fs::create_dir(&first_dir).unwrap();
    let first = write_bundle(&first_dir, &[("SECRET", "valid")]);
    let last = write_bundle(&d, &[("SECRET", "invalid\0value")]);
    let keys = write_keys(&d, false);
    let cfg = write_config(
        &d,
        &serde_json::json!({
            "mode": "env",
            "keys": [{"file": keys}],
            "bundle_files": [first, last],
            "strict": false,
        })
        .to_string(),
    );
    let out = run_exec(&cfg, "true", &[]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("NUL byte"));
}

#[test]
fn bundle_nul_value_is_a_hard_error_under_any_strictness() {
    // sweep 2026-08-07 T10 (X6): an env-bound bundle value containing NUL
    // is a HARD error — one rule for every env-bound value. strict:false
    // must NOT skip it the way it skips undecryptable values.
    let d = common::tmpdir("bundle-nul");
    let bundle = write_bundle(&d, &[("SECRET", "before\0after")]);
    let keys = write_keys(&d, false);
    for strict in [true, false] {
        let cfg = write_config(
            &d,
            &format!(
                r#"{{"mode":"env","keys":[{{"file":"{}"}}],"bundle_files":["{}"],"strict":{strict}}}"#,
                keys.display(),
                bundle.display()
            ),
        );
        let out = run_exec(&cfg, "true", &[]);
        assert!(
            !out.status.success(),
            "strict:{strict} must still fail closed on a NUL value"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("NUL byte"),
            "strict:{strict} stderr: {stderr}"
        );
    }
}
