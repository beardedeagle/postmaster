//! Daemon end-to-end conformance (sweep 2026-08-07 T2): the real binary
//! in serve mode, a real bound socket, and the real fetch client — the
//! serve/fetch roundtrip and the startup preflight refusal, which the
//! unit tests only exercise in-process.

use sha2::Digest as _;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::common;

/// Kill the daemon on drop (panic paths included) so a failed assertion
/// can't leak a serving process.
struct KillOnDrop(Option<std::process::Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Wait for the daemon's socket to accept connections (the file existing
/// is not enough — a dead daemon leaves the socket file behind), bailing
/// early with the daemon's stderr if the process exits first.
fn wait_for_socket(
    daemon: &mut std::process::Child,
    sock: &std::path::Path,
    timeout: Duration,
) -> Result<(), String> {
    use std::io::Read as _;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        // A successful connect means a live listener. The probe is itself
        // served like a fetch (one serialized connection) and dropped.
        if std::os::unix::net::UnixStream::connect(sock).is_ok() {
            return Ok(());
        }
        if let Some(status) = daemon.try_wait().map_err(|e| e.to_string())? {
            let mut stderr = String::new();
            if let Some(mut h) = daemon.stderr.take() {
                let _ = h.read_to_string(&mut stderr);
            }
            return Err(format!("daemon exited before binding ({status}): {stderr}"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(format!(
        "daemon did not accept on {} within {timeout:?}",
        sock.display()
    ))
}

#[test]
fn daemon_serves_a_real_fetch_roundtrip() {
    for mask in ["000", "022", "077"] {
        daemon_roundtrip(mask, None);
    }
}

#[test]
fn daemon_serves_configured_peer_under_any_umask() {
    let out = Command::new("id").arg("-un").output().unwrap();
    assert!(out.status.success());
    let user = String::from_utf8(out.stdout).unwrap();
    for mask in ["000", "022", "077"] {
        daemon_roundtrip(mask, Some(user.trim()));
    }
}

fn daemon_roundtrip(mask: &str, peer_user: Option<&str>) {
    let d = common::tmpdir("daemon");
    let encrypted = common::enc("postgres://real-roundtrip");
    let env = common::write_env_file(
        &d,
        ".env.production",
        &[
            format!("DOTENV_PUBLIC_KEY_PRODUCTION=\"{}\"", common::test_pk_hex()),
            format!("DB_URL=\"{}\"", encrypted),
        ],
    );
    let hash = hex::encode(sha2::Sha256::digest(std::fs::read(&env).unwrap()));
    let keys = common::write_keys_file(&d, "PRODUCTION", &[common::TEST_SK_HEX]);
    // Bound directly under the tmpdir: unix socket paths are length-capped
    // (104 bytes on darwin), and the tmpdir path is already long.
    let sock = d.join("DB_URL.sock");
    let cfg = d.join("daemon.json");
    std::fs::write(
        &cfg,
        serde_json::json!({
            "keys": {"file": keys},
            "credentials": {sock.to_str().unwrap(): {
                "env_file": env,
                "key": "DB_URL",
                "peer_user": peer_user,
                "env_file_sha256": [hash],
            }},
        })
        .to_string(),
    )
    .unwrap();

    // The suite runs as the test user: --bind (no systemd activation
    // here) and --allow-nonroot (the peer ACL's root-only default would
    // refuse our own fetch when no peer_user is configured).
    // The shell sets the child's mask without changing the test process.
    let daemon = Command::new("/bin/sh")
        .args([
            "-c",
            "umask \"$1\"; shift; exec \"$@\"",
            "postmaster-test",
            mask,
            env!("CARGO_BIN_EXE_postmaster"),
        ])
        .args(["--config"])
        .arg(&cfg)
        .args(["--bind", "--allow-nonroot"])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut guard = KillOnDrop(Some(daemon));
    wait_for_socket(guard.0.as_mut().unwrap(), &sock, Duration::from_secs(10)).unwrap();

    // A configured peer needs write access; otherwise the socket is owner-only.
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    let expected = if peer_user.is_some() { 0o666 } else { 0o600 };
    assert_eq!(mode, expected, "socket mode under umask {mask}");

    let out = Command::new(env!("CARGO_BIN_EXE_postmaster"))
        .arg("fetch")
        .arg(&sock)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "fetch stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"postgres://real-roundtrip");

    let original = std::fs::read(&env).unwrap();
    for replacement in [
        format!("DB_URL='{}'\n", common::enc("foreign-secret")),
        "DB_URL=${PATH}\n".into(),
    ] {
        std::fs::write(&env, replacement).unwrap();
        let refused = Command::new(env!("CARGO_BIN_EXE_postmaster"))
            .arg("fetch")
            .arg(&sock)
            .output()
            .unwrap();
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
    }
    std::fs::write(&env, original).unwrap();
    let restored = Command::new(env!("CARGO_BIN_EXE_postmaster"))
        .arg("fetch")
        .arg(&sock)
        .output()
        .unwrap();
    assert!(restored.status.success());
    assert_eq!(restored.stdout, b"postgres://real-roundtrip");
}

#[test]
fn daemon_preflight_refuses_an_empty_credential_at_startup() {
    // sweep 2026-08-07 D4 end-to-end: an empty resolved value can never
    // be served (zero bytes means refusal on the wire), so the daemon
    // must fail at STARTUP naming the key, not look healthy while every
    // fetch comes back empty.
    let d = common::tmpdir("daemonpre");
    let env = common::write_env_file(&d, ".env", &["EMPTY=".to_string()]);
    let keys = common::write_keys_file(&d, "", &[common::TEST_SK_HEX]);
    let sock = d.join("EMPTY.sock");
    let cfg = d.join("daemon.json");
    std::fs::write(
        &cfg,
        format!(
            r#"{{"keys":{{"file":"{}"}},"credentials":{{"{}":{{"env_file":"{}","key":"EMPTY","env_file_sha256":["7819c04858487b8325a083235e0697f271991cb446086084807fec586dc27427"]}}}}}}"#,
            keys.display(),
            sock.display(),
            env.display()
        ),
    )
    .unwrap();

    // Startup fails before any bind, so output() returns promptly.
    let out = Command::new(env!("CARGO_BIN_EXE_postmaster"))
        .args(["--config"])
        .arg(&cfg)
        .args(["--bind", "--allow-nonroot"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("empty value"), "stderr: {stderr}");
    assert!(
        !sock.exists(),
        "a preflight refusal must happen before any socket is bound"
    );
}
