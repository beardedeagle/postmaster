//! Daemon end-to-end conformance (sweep 2026-08-07 T2): the real binary
//! in serve mode, a real bound socket, and the real fetch client — the
//! serve/fetch roundtrip and the startup preflight refusal, which the
//! unit tests only exercise in-process.

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
    let d = common::tmpdir("daemon");
    let env = common::write_env_file(
        &d,
        ".env.production",
        &[
            format!("DOTENV_PUBLIC_KEY_PRODUCTION=\"{}\"", common::test_pk_hex()),
            format!("DB_URL=\"{}\"", common::enc("postgres://real-roundtrip")),
        ],
    );
    let keys = common::write_keys_file(&d, "PRODUCTION", &[common::TEST_SK_HEX]);
    // Bound directly under the tmpdir: unix socket paths are length-capped
    // (104 bytes on darwin), and the tmpdir path is already long.
    let sock = d.join("DB_URL.sock");
    let cfg = d.join("daemon.json");
    std::fs::write(
        &cfg,
        format!(
            r#"{{"keys":{{"file":"{}"}},"credentials":{{"{}":{{"env_file":"{}","key":"DB_URL"}}}}}}"#,
            keys.display(),
            sock.display(),
            env.display()
        ),
    )
    .unwrap();

    // The suite runs as the test user: --bind (no systemd activation
    // here) and --allow-nonroot (the peer ACL's root-only default would
    // refuse our own fetch otherwise; no peer_user is configured).
    let daemon = Command::new(env!("CARGO_BIN_EXE_postmaster"))
        .args(["--config"])
        .arg(&cfg)
        .args(["--bind", "--allow-nonroot"])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut guard = KillOnDrop(Some(daemon));
    wait_for_socket(guard.0.as_mut().unwrap(), &sock, Duration::from_secs(10)).unwrap();

    // The bind-time permission contract (audit finding #7; umask-borne on
    // darwin, fchmod on Linux): no peer_user configured → owner-only.
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket must be owner-only, got {mode:o}");

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
            r#"{{"keys":{{"file":"{}"}},"credentials":{{"{}":{{"env_file":"{}","key":"EMPTY"}}}}}}"#,
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
