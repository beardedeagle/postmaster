//! Exercise real setup input and rotation, including terminal interruption.

#[path = "../../src/test_util/pty.rs"]
mod pty;

use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};

use crate::common;

fn setup_command(dir: &std::path::Path, force: bool) -> Command {
    let config = dir.join("setup.json");
    std::fs::write(&config, serde_json::json!({"mode":"env", "keys":[{"file":dir.join(".env.keys")}], "env_files":[dir.join(".env")]}).to_string()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_postmaster"));
    command
        .args(["setup", "--config"])
        .arg(config)
        .arg("--keys-dir")
        .arg(dir.join("provisioning"));
    if force {
        command.arg("--force");
    }
    command
}

#[test]
fn file_input_hides_secrets_and_restores_echo_before_termination() {
    for force in [false, true] {
        for interrupt in [false, true] {
            let dir = common::tmpdir("setup-tty");
            if force {
                common::write_keys_file(&dir, "", &[common::TEST_SK_HEX]);
            }
            let mut pty = pty::TestPty::new();
            let original = rustix::termios::tcgetattr(&pty.slave).unwrap().local_modes;
            pty.spawn(&mut setup_command(&dir, force));
            pty.expect("[y/N]");
            pty.send(b"y\n");
            pty.expect("Paste the keys file contents");
            assert!(
                !rustix::termios::tcgetattr(&pty.slave)
                    .unwrap()
                    .local_modes
                    .contains(rustix::termios::LocalModes::ECHO)
            );
            if interrupt {
                pty.send(b"PRIVATE_SENTINEL\n");
                pty.signal(rustix::process::Signal::TERM);
            } else {
                pty.send(
                    format!(
                        "# PRIVATE_SENTINEL\nDOTENV_PRIVATE_KEY={}\n",
                        common::TEST_SK_HEX
                    )
                    .as_bytes(),
                );
                pty.send(&[4]);
            }
            assert_eq!(
                pty.wait().success(),
                !interrupt,
                "{}",
                String::from_utf8_lossy(&pty.output)
            );
            assert_eq!(
                rustix::termios::tcgetattr(&pty.slave).unwrap().local_modes,
                original
            );
            assert!(!String::from_utf8_lossy(&pty.output).contains("PRIVATE_SENTINEL"));
            if interrupt && !force {
                assert!(!dir.join(".env.keys").exists());
            }
        }
    }
}

#[test]
fn rotation_rejects_inode_substitution_after_confirmation() {
    let dir = common::tmpdir("rotation-swap");
    let keys = common::write_keys_file(&dir, "", &[common::TEST_SK_HEX]);
    let target = dir.join("sentinel");
    std::fs::write(&target, b"untouched").unwrap();
    let mut pty = pty::TestPty::new();
    pty.spawn(&mut setup_command(&dir, true));
    pty.expect("[y/N]");
    pty.send(b"y\n");
    pty.expect("Paste the keys file contents");
    std::fs::rename(&keys, dir.join("original")).unwrap();
    std::os::unix::fs::symlink(&target, &keys).unwrap();
    pty.send(format!("DOTENV_PRIVATE_KEY={}\n", "22".repeat(32)).as_bytes());
    pty.send(&[4]);
    assert!(!pty.wait().success());
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
    assert!(String::from_utf8_lossy(&pty.output).contains("changed while awaiting input"));
}

#[test]
fn partial_noncanonical_input_does_not_delay_terminal_restoration() {
    use rustix::termios::{LocalModes, OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr};
    let dir = common::tmpdir("raw-input");
    let mut pty = pty::TestPty::new();
    let mut original = tcgetattr(&pty.slave).unwrap();
    original.local_modes.remove(LocalModes::ICANON);
    original.special_codes[SpecialCodeIndex::VMIN] = 1;
    original.special_codes[SpecialCodeIndex::VTIME] = 0;
    tcsetattr(&pty.slave, OptionalActions::Now, &original).unwrap();
    pty.spawn(&mut setup_command(&dir, false));
    pty.expect("[y/N]");
    pty.send(b"y\n");
    pty.expect("Paste the keys file contents");
    pty.send(b"PRIVATE_SENTINEL");
    std::thread::sleep(std::time::Duration::from_millis(100));
    pty.signal(rustix::process::Signal::TERM);
    assert!(!pty.wait().success());
    assert_eq!(
        tcgetattr(&pty.slave).unwrap().local_modes,
        original.local_modes
    );
    assert!(!String::from_utf8_lossy(&pty.output).contains("PRIVATE_SENTINEL"));
    assert!(!dir.join(".env.keys").exists());
}

#[test]
fn interrupted_canonical_input_is_discarded_before_the_next_reader() {
    let dir = common::tmpdir("canonical-interrupt");
    let mut pty = pty::TestPty::new();
    let original = rustix::termios::tcgetattr(&pty.slave).unwrap().local_modes;
    assert!(original.contains(rustix::termios::LocalModes::ICANON));
    pty.spawn(&mut setup_command(&dir, false));
    pty.expect("[y/N]");
    pty.send(b"y\n");
    pty.expect("Paste the keys file contents");
    pty.send(b"PRIVATE_SENTINEL");
    pty.signal(rustix::process::Signal::TERM);
    assert!(!pty.wait().success());
    assert_eq!(
        rustix::termios::tcgetattr(&pty.slave).unwrap().local_modes,
        original
    );
    // Complete the next canonical line; it must contain none of the interrupted secret.
    pty.send(b"\n");
    let mut next = [0; 128];
    let count = pty.slave.read(&mut next).unwrap();
    assert_eq!(&next[..count], b"\n");
    assert!(!dir.join(".env.keys").exists());
}

#[test]
fn redirected_rotation_preserves_old_handles_and_read_only_files() {
    for mode in [0o400, 0o600] {
        let dir = common::tmpdir("rotation-pipe");
        let keys = common::write_keys_file(&dir, "", &[common::TEST_SK_HEX]);
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(mode)).unwrap();
        let old = std::fs::read(&keys).unwrap();
        let mut handle = std::fs::File::open(&keys).unwrap();
        let mut child = setup_command(&dir, true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let contents = format!("DOTENV_PRIVATE_KEY={}\n", "22".repeat(32));
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("y\n{contents}").as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut retained = Vec::new();
        handle.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, old);
        assert_eq!(std::fs::read(&keys).unwrap(), contents.as_bytes());
        assert_eq!(
            std::fs::metadata(&keys).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
