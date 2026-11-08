//! Secret stdin input with terminal echo suppressed and restored before signal delivery.

use std::io::{BufRead as _, IsTerminal as _, Read as _};

use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};
use zeroize::Zeroizing;

struct EchoGuard {
    terminal: Option<Termios>,
    flags: Option<rustix::fs::OFlags>,
}

impl EchoGuard {
    fn restore(&mut self) -> Result<(), String> {
        let terminal = if let Some(original) = &self.terminal {
            tcsetattr(std::io::stdin(), OptionalActions::Now, original)
                .map_err(|e| format!("cannot restore terminal settings: {e}"))
        } else {
            Ok(())
        };
        if terminal.is_ok() {
            self.terminal = None;
        }
        let flags = if let Some(original) = self.flags {
            rustix::fs::fcntl_setfl(std::io::stdin(), original)
                .map_err(|e| format!("cannot restore stdin flags: {e}"))
        } else {
            Ok(())
        };
        if flags.is_ok() {
            self.flags = None;
        }
        terminal.and(flags)
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            crate::server::log(&e);
        }
    }
}

/// Read one line or a multiline EOF-terminated value without terminal echo.
/// Redirected input uses stdin's existing buffer. Errors never include input values.
#[allow(clippy::print_stderr)]
pub(super) fn read_secret(prompt: &str, single_line: bool) -> Result<Zeroizing<String>, String> {
    let stdin = std::io::stdin();
    let mut value = Zeroizing::new(String::new());
    if !stdin.is_terminal() {
        eprintln!("{prompt}");
        let mut input = stdin.lock();
        if single_line {
            input.read_line(&mut value)
        } else {
            input.read_to_string(&mut value)
        }
        .map_err(|_| "cannot read secret input")?;
        return Ok(value);
    }
    // Drop order matters: restore echo before unblocking a pending termination or suspend.
    let signals = crate::launcher::TerminationGuard::block_input();
    if !signals.active() {
        return Err("cannot protect terminal input from interruption".into());
    }
    let original = tcgetattr(&stdin).map_err(|e| format!("cannot read terminal settings: {e}"))?;
    let flags =
        rustix::fs::fcntl_getfl(&stdin).map_err(|e| format!("cannot read stdin flags: {e}"))?;
    let mut no_echo = original.clone();
    no_echo
        .local_modes
        .remove(LocalModes::ECHO | LocalModes::ECHONL);
    let mut echo = EchoGuard {
        terminal: Some(original),
        flags: Some(flags),
    };
    rustix::fs::fcntl_setfl(&stdin, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|e| format!("cannot make terminal input nonblocking: {e}"))?;
    tcsetattr(&stdin, OptionalActions::Now, &no_echo)
        .map_err(|e| format!("cannot suppress terminal echo: {e}"))?;
    eprintln!("{prompt}");
    let mut input = stdin.lock();
    loop {
        if signals.input_pending()? {
            return Err("secret input interrupted".into());
        }
        // Read buffered data first. NONBLOCK also protects partial noncanonical lines.
        match input.read_line(&mut value) {
            Ok(0) => break,
            Ok(_) if single_line => break,
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err("cannot read secret input".into()),
        }
        let mut fds = [rustix::event::PollFd::new(
            &stdin,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => continue,
            Ok(_) => {}
            Err(e) => return Err(format!("cannot wait for secret input: {e}")),
        }
    }
    echo.restore()?;
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn input_child() {
        let Ok(style) = std::env::var("POSTMASTER_TEST_INPUT") else {
            return;
        };
        let result = read_secret("secret-ready", style == "line");
        assert!(result.is_ok(), "input failed");
        assert_eq!(result.unwrap().trim(), "PRIVATE_SENTINEL");
    }

    #[test]
    fn terminal_echo_is_restored_after_success_and_error() {
        for style in ["line", "multiline"] {
            for outcome in ["success", "invalid-utf8"] {
                let mut pty = crate::test_util::pty::TestPty::new();
                let original = tcgetattr(&pty.slave).unwrap().local_modes;
                let flags = rustix::fs::fcntl_getfl(&pty.slave).unwrap();
                pty.spawn(
                    std::process::Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "keys::provisioning::input::tests::input_child",
                            "--nocapture",
                        ])
                        .env("POSTMASTER_TEST_INPUT", style),
                );
                pty.expect("secret-ready");
                assert!(
                    !tcgetattr(&pty.slave)
                        .unwrap()
                        .local_modes
                        .contains(LocalModes::ECHO)
                );
                match outcome {
                    "success" => {
                        pty.send(b"PRIVATE_SENTINEL\n");
                        if style == "multiline" {
                            pty.send(&[4]);
                        }
                    }
                    "invalid-utf8" => pty.send(&[0xff, b'\n']),
                    _ => pty.signal(rustix::process::Signal::TERM),
                }
                assert_eq!(pty.wait().success(), outcome == "success");
                assert_eq!(tcgetattr(&pty.slave).unwrap().local_modes, original);
                // Darwin adds an internal status bit when the slave is written to.
                assert_eq!(
                    rustix::fs::fcntl_getfl(&pty.slave)
                        .unwrap()
                        .contains(rustix::fs::OFlags::NONBLOCK),
                    flags.contains(rustix::fs::OFlags::NONBLOCK)
                );
                assert!(!String::from_utf8_lossy(&pty.output).contains("PRIVATE_SENTINEL"));
            }
        }
    }

    #[test]
    fn noncanonical_single_line_retains_partial_buffered_input() {
        let mut pty = crate::test_util::pty::TestPty::new();
        let mut mode = tcgetattr(&pty.slave).unwrap();
        mode.local_modes.remove(LocalModes::ICANON);
        mode.special_codes[rustix::termios::SpecialCodeIndex::VMIN] = 1;
        mode.special_codes[rustix::termios::SpecialCodeIndex::VTIME] = 0;
        tcsetattr(&pty.slave, OptionalActions::Now, &mode).unwrap();
        pty.spawn(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "keys::provisioning::input::tests::input_child",
                    "--nocapture",
                ])
                .env("POSTMASTER_TEST_INPUT", "line"),
        );
        pty.expect("secret-ready");
        pty.send(b"PRIVATE_");
        std::thread::sleep(std::time::Duration::from_millis(100));
        pty.send(b"SENTINEL\n");
        assert!(pty.wait().success());
        assert_eq!(tcgetattr(&pty.slave).unwrap().local_modes, mode.local_modes);
        assert!(!String::from_utf8_lossy(&pty.output).contains("PRIVATE_SENTINEL"));
    }
}
