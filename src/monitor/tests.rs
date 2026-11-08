//! Tests for the sibling monitor, extracted from monitor.rs. Same
//! module path (`monitor::tests`), same crate-internal visibility —
//! nothing here changed but location.
#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;
use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use rustix::process::{WaitOptions, waitpid};

use crate::launcher::TerminationGuard;
use crate::secret_files::open_secrets_dir;

fn tdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pm-monitor-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Fork a monitor watching `service_pid`, mirroring the production
/// launcher: the calling thread blocks the stop signals first (the
/// child is born with them blocked — no ready-race between fork and
/// the monitor's own block), the fork-child runs the REAL monitor
/// loop with test-scaled timing, the parent restores its mask and
/// returns the monitor's pid.
fn fork_monitor(
    service_pid: Pid,
    dir: Option<&Path>,
    names: Vec<String>,
    grace: Duration,
    poll_interval: Duration,
) -> Pid {
    let guard = TerminationGuard::block();
    let dir_fd = dir.map(|d| open_secrets_dir(d).unwrap());
    // SAFETY: fork(2) in the test process. The child executes only
    // run_inner — documented async-signal-safe discipline: no
    // allocation, no stdio locks, raw syscalls only — and then exits
    // via _exit/exit_group, so the multithreaded test harness's
    // malloc locks and output buffers are never touched in the child.
    match unsafe { libc::fork() } {
        -1 => panic!("fork: {}", std::io::Error::last_os_error()),
        0 => {
            // Never returns (`-> !`), so the guard is never dropped
            // and the mask stays blocked for the monitor's life
            // (run_inner re-asserts it regardless).
            run_inner(service_pid, dir_fd, names, grace, poll_interval);
        }
        child => {
            guard.restore_mask();
            Pid::from_raw(child).unwrap()
        }
    }
}

/// Reap the monitor, asserting it exits 0 within `timeout`. On
/// timeout the monitor is SIGKILLed and reaped so a regression fails
/// the test instead of hanging the suite.
fn wait_monitor_exit(pid: Pid, timeout: Duration) -> i32 {
    let deadline = Instant::now() + timeout;
    loop {
        match waitpid(Some(pid), WaitOptions::NOHANG).unwrap() {
            Some((_, status)) => {
                if let Some(sig) = status.terminating_signal() {
                    panic!("monitor died by signal {sig}");
                }
                return status.exit_status().unwrap_or(-1);
            }
            None => {
                if Instant::now() >= deadline {
                    let _ = kill_process(pid, Signal::KILL);
                    let _ = waitpid(Some(pid), WaitOptions::empty());
                    panic!("monitor did not exit within {timeout:?}");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

fn write_dummies(dir: &Path) -> Vec<String> {
    fs::write(dir.join("A"), b"secret-a").unwrap();
    fs::write(dir.join("B"), b"secret-b").unwrap();
    vec!["A".to_string(), "B".to_string()]
}

/// Reaps a forked/spawned pid on drop (SIGKILL first) so a failed
/// assertion can't leak a stray service process — important for the
/// TERM-ignoring service, which would otherwise outlive the test
/// binary indefinitely.
struct ReapOnDrop(Pid);

impl Drop for ReapOnDrop {
    fn drop(&mut self) {
        let _ = kill_process(self.0, Signal::KILL);
        let _ = waitpid(Some(self.0), WaitOptions::empty());
    }
}

/// Fork a "service" that ignores SIGTERM until SIGKILLed: a
/// fork-child that sets TERM to SIG_IGN and pause()s forever. This
/// exercises the grace → SIGKILL escalation deterministically, unlike
/// a shell `trap` — macOS /bin/sh resets TERM for exec'd commands,
/// so the disposition doesn't survive into `sleep` there. The child
/// acknowledges readiness after installing SIG_IGN, before its pid returns.
fn fork_term_ignoring_service() -> Pid {
    let (mut ready_read, ready_write) = std::io::pipe().unwrap();
    // SAFETY: fork(2) in the test process; the child executes only
    // async-signal-safe calls (close, signal, write, pause, _exit) and
    // never returns into the test harness — no allocation, stdio, or locks.
    match unsafe { libc::fork() } {
        -1 => panic!("fork: {}", std::io::Error::last_os_error()),
        0 => unsafe {
            libc::close(ready_read.as_raw_fd());
            // SAFETY: plain single-threaded signal op on this
            // process; SIG_IGN is the documented ignore-disposition
            // constant. pause(2) suspends until a caught signal
            // arrives; TERM is ignored, so only SIGKILL ends the loop.
            if libc::signal(libc::SIGTERM, libc::SIG_IGN) == libc::SIG_ERR
                || libc::write(ready_write.as_raw_fd(), b"R".as_ptr().cast(), 1) != 1
            {
                libc::_exit(1);
            }
            libc::close(ready_write.as_raw_fd());
            loop {
                libc::pause();
            }
        },
        child => {
            let pid = Pid::from_raw(child).unwrap();
            drop(ready_write);
            if let Err(error) = ready_read.read_exact(&mut [0]) {
                drop(ReapOnDrop(pid));
                panic!("service readiness: {error}");
            }
            pid
        }
    }
}

/// Service death NOT mediated by the monitor (kill -9 / crash
/// stand-in) must still trigger cleanup and monitor exit.
#[test]
fn natural_service_death_triggers_cleanup_and_monitor_exit() {
    let dir = tdir("natural");
    let names = write_dummies(&dir);
    let mut service = Command::new("sleep").arg("30").spawn().unwrap();
    let service_pid = Pid::from_child(&service);
    let _reap = ReapOnDrop(service_pid);
    let monitor = fork_monitor(
        service_pid,
        Some(&dir),
        names,
        Duration::from_millis(50),
        Duration::from_millis(10),
    );

    assert!(dir.join("A").exists());
    kill_process(service_pid, Signal::KILL).unwrap();
    let status = service.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));

    assert_eq!(wait_monitor_exit(monitor, Duration::from_secs(5)), 0);
    assert!(
        !dir.join("A").exists() && !dir.join("B").exists(),
        "monitor must remove the plaintext files on service death"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A stop signal to the monitor is forwarded to the service; death
/// follows within the grace (no SIGKILL escalation needed), then
/// cleanup runs and the monitor exits 0. The monitor is born with
/// the signal blocked, so the TERM pends until its first tick —
/// no settle sleep is needed.
#[test]
fn stop_signal_is_forwarded_then_grace_then_cleanup() {
    let dir = tdir("forward");
    let names = write_dummies(&dir);
    let mut service = Command::new("sleep").arg("30").spawn().unwrap();
    let service_pid = Pid::from_child(&service);
    let _reap = ReapOnDrop(service_pid);
    let monitor = fork_monitor(
        service_pid,
        Some(&dir),
        names,
        Duration::from_millis(500),
        Duration::from_millis(10),
    );

    kill_process(monitor, Signal::TERM).unwrap();

    assert_eq!(wait_monitor_exit(monitor, Duration::from_secs(5)), 0);
    let status = service.wait().unwrap();
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "the service must die by the forwarded TERM, not by an escalated SIGKILL"
    );
    assert!(
        !dir.join("A").exists() && !dir.join("B").exists(),
        "cleanup must run before the monitor exits"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A service that ignores SIGTERM is SIGKILLed only after the grace
/// elapses; cleanup still runs and the monitor exits 0.
#[test]
fn term_ignoring_service_is_sigkilled_after_grace() {
    let dir = tdir("grace");
    let names = write_dummies(&dir);
    let service_pid = fork_term_ignoring_service();
    let _reap = ReapOnDrop(service_pid);
    let grace = Duration::from_millis(50);
    let monitor = fork_monitor(
        service_pid,
        Some(&dir),
        names,
        grace,
        Duration::from_millis(10),
    );

    let start = Instant::now();
    kill_process(monitor, Signal::TERM).unwrap();

    assert_eq!(wait_monitor_exit(monitor, Duration::from_secs(5)), 0);
    let Some((_, status)) = waitpid(Some(service_pid), WaitOptions::empty()).unwrap() else {
        panic!("blocking waitpid returned no status");
    };
    assert_eq!(
        status.terminating_signal(),
        Some(libc::SIGKILL),
        "a TERM-ignoring service must be SIGKILLed"
    );
    assert!(
        start.elapsed() >= grace,
        "SIGKILL must not come before the grace elapses"
    );
    assert!(
        !dir.join("A").exists() && !dir.join("B").exists(),
        "cleanup must run after the SIGKILL path"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The inherited-heap scrub (threat model): both buffers of an env
/// pair must come back fully wiped.
#[test]
fn wipe_pair_scrubs_both_buffers() {
    let (k, v) = wipe_pair(
        std::ffi::OsString::from("SECRET_NAME"),
        std::ffi::OsString::from("s3cr3t-value"),
    );
    assert!(k.iter().all(|b| *b == 0), "name buffer not wiped");
    assert!(v.iter().all(|b| *b == 0), "value buffer not wiped");
}

/// Uniform semantics (design decision 4): the monitor runs even in
/// env mode — no dir fd, an empty name list, cleanup a no-op — and
/// still exits when the service dies.
#[test]
fn env_mode_monitor_with_no_files_exits_on_service_death() {
    let mut service = Command::new("sleep").arg("30").spawn().unwrap();
    let service_pid = Pid::from_child(&service);
    let _reap = ReapOnDrop(service_pid);
    let monitor = fork_monitor(
        service_pid,
        None,
        Vec::new(),
        Duration::from_millis(50),
        Duration::from_millis(10),
    );

    kill_process(service_pid, Signal::TERM).unwrap();
    let status = service.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGTERM));

    assert_eq!(wait_monitor_exit(monitor, Duration::from_secs(5)), 0);
}

/// A service that is ALREADY dead when the monitor starts (death
/// observed on the first tick) must still trigger cleanup and an
/// immediate monitor exit — the monitor must never hang waiting on a
/// process that died before it began watching.
#[test]
fn pre_dead_service_triggers_immediate_cleanup_and_exit() {
    let dir = tdir("predead");
    let names = write_dummies(&dir);
    let mut service = Command::new("sleep").arg("30").spawn().unwrap();
    let service_pid = Pid::from_child(&service);
    // Kill AND reap before the monitor starts: a zombie still answers
    // kill(pid, 0), so the monitor would correctly see "alive". After
    // the reap the pid is gone (ESRCH); reuse inside the test window
    // is negligible.
    kill_process(service_pid, Signal::KILL).unwrap();
    let status = service.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));

    let monitor = fork_monitor(
        service_pid,
        Some(&dir),
        names,
        Duration::from_millis(50),
        Duration::from_millis(10),
    );

    assert_eq!(wait_monitor_exit(monitor, Duration::from_secs(5)), 0);
    assert!(
        !dir.join("A").exists() && !dir.join("B").exists(),
        "cleanup must run even when the service died before the monitor started"
    );
    let _ = fs::remove_dir_all(&dir);
}
