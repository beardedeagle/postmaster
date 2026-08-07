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
    let ct = ecies::encrypt_with_aad(&pk, value.as_bytes(), name.as_bytes()).unwrap();
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
