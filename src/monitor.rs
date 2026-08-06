//! Sibling launch monitor — a per-service fork-child that owns stop
//! semantics and plaintext cleanup on every service-death path
//! (sibling-monitor launch supervision design, 2026-08-05).
//!
//! The launcher forks the monitor after validation, plaintext writes, and
//! zeroization, and immediately before `execvp`: the parent restores its
//! pre-guard signal mask and execs the service (MainPID unchanged), and
//! the fork-child becomes the monitor. The monitor carries only the
//! pinned secrets-dir fd (inherited across fork; `CLOEXEC` does not fire
//! because the monitor never execs) and the list of written entry names
//! — in env mode both are empty and cleanup is a no-op, but the monitor
//! still runs (uniform semantics: it forwards stops regardless).
//!
//! Signal discipline: the four termination signals ({TERM, INT, HUP,
//! QUIT}) stay *blocked for the monitor's whole life* — the mask is
//! inherited from the launcher's `TerminationGuard` across fork and
//! re-asserted at monitor start — and are consumed synchronously via the
//! `sigpending`/`sigwait` family. No signal handlers exist anywhere in
//! the process (the sigaction flag-handler was retired with this design).
//! SIGPIPE is additionally blocked so a stderr write to a closed pipe
//! cannot kill the monitor mid-supervision.
//!
//! Loop semantics (one tick = `POLL_INTERVAL`):
//! 1. A pending stop signal is dequeued → forward it to the service →
//!    wait up to `GRACE` (250 ms constant — a single global security
//!    policy, deliberately not configurable) for the service to die →
//!    if still alive, `SIGKILL` → wait for death (unbounded: `SIGKILL`
//!    cannot be blocked or ignored; only a D-state hang can delay it, and
//!    abandoning cleanup is worse) → `cleanup_written` → exit.
//! 2. Otherwise, if the service is dead (liveness watch: pidfd + `poll`
//!    on Linux, kqueue `EVFILT_PROC`/`NOTE_EXIT` on macOS, `kill(pid, 0)`
//!    only as fallback) → `cleanup_written` → exit. This covers natural
//!    exit, `kill -9`, and crashes — the net-new cleanup coverage.
//! 3. Otherwise, sleep one tick. Liveness/stop latency adds to cleanup
//!    latency, never to the grace cap.
//!
//! Fork-child discipline (the soundness contract for `launcher.rs`'s
//! `fork`): the fork parent may be multithreaded (it is under
//! `cargo test`), so between fork and exit the monitor performs no
//! allocation and takes no stdio locks — only the async-signal-safe
//! syscall set: signal mask/wait ops, `pidfd_open`/`poll`/`kevent`,
//! `kill`/`pidfd_send_signal`, `unlinkat`, `nanosleep`, raw `write(2)`
//! for diagnostics, and `_exit`/`exit_group`. All inputs (`names`, the
//! dir fd) are allocated pre-fork and moved in. Exit never runs
//! destructors, atexit handlers, or stdio flushes (inherited buffers
//! must not flush twice).

use std::os::fd::{AsFd, OwnedFd};
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::process::{Pid, Signal, kill_process, test_kill_process};
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
use rustix::event::{PollFd, PollFlags, poll};
#[cfg(target_os = "linux")]
use rustix::process::{PidfdFlags, pidfd_open, pidfd_send_signal};
#[cfg(target_os = "linux")]
use rustix::runtime::{self, KernelSigSet};
#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd};

use crate::secret_files::cleanup_written;

/// Scrub one inherited env pair in place and return the wiped buffers
/// (threat model: monitor inherited heap). The fork-child monitor
/// inherits the launcher's `extra` env array — plaintext values in env
/// mode and in files-mode passthrough — and `free()` alone would leave
/// those bytes in the monitor's mapped pages for its whole life (the
/// monitor never allocates again, so they would never even be reused).
/// `into_vec` takes ownership of the existing `OsString` buffer with no
/// copy, and `zeroize` wipes it in place before the buffers are freed.
pub(crate) fn wipe_pair(k: std::ffi::OsString, v: std::ffi::OsString) -> (Vec<u8>, Vec<u8>) {
    use std::os::unix::ffi::OsStringExt;
    let mut kb = k.into_vec();
    let mut vb = v.into_vec();
    kb.zeroize();
    vb.zeroize();
    (kb, vb)
}

/// The termination signals the monitor consumes synchronously and
/// forwards to the service. Also blocked across the launcher's
/// plaintext-write window (`TerminationGuard`) and inherited by the
/// monitor across fork.
pub(crate) const STOP_SIGNALS: [Signal; 4] = [Signal::TERM, Signal::INT, Signal::HUP, Signal::QUIT];

/// Grace between forwarding a stop signal and `SIGKILL` escalation:
/// 250 ms, a single global security policy (author ruling 2026-08-05 —
/// per-service erosion is unacceptable; the per-unit knob is the service
/// manager's own stop timeout). Injectable in tests via `run_inner`.
pub(crate) const GRACE: Duration = Duration::from_millis(250);

/// Liveness/poll tick. Short is fine: this latency adds to cleanup
/// latency, not to the grace cap.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Zero timeout for non-blocking `poll(2)` liveness checks on the pidfd.
#[cfg(target_os = "linux")]
const ZERO_TIMESPEC: rustix::event::Timespec = rustix::event::Timespec {
    tv_sec: 0,
    tv_nsec: 0,
};

/// Monitor entry point with production timing. Never returns: the
/// monitor exits the process (via `_exit`/`exit_group`) once the service
/// is dead and the plaintext is cleaned. `dir_fd`/`names` are the pinned
/// secrets-dir fd and written entry names from the launcher; both are
/// absent in env mode (cleanup is then a no-op, but the monitor still
/// runs — uniform stop semantics).
pub(crate) fn run<Fd: AsFd>(service_pid: Pid, dir_fd: Option<Fd>, names: Vec<String>) -> ! {
    run_inner(service_pid, dir_fd, names, GRACE, POLL_INTERVAL)
}

/// The monitor loop, parameterized for deterministic tests.
fn run_inner<Fd: AsFd>(
    service_pid: Pid,
    dir_fd: Option<Fd>,
    names: Vec<String>,
    grace: Duration,
    poll_interval: Duration,
) -> ! {
    block_monitor_signals();
    let set = stop_sigset();
    let watch = Watch::new(service_pid);
    loop {
        if let Some(sig) = take_pending_stop(&set) {
            // Stop semantics (diverges): forward, bounded grace, SIGKILL
            // escalation, then clean and exit.
            signal_service(&watch, service_pid, sig);
            if !wait_for_death(&watch, service_pid, grace, poll_interval) {
                monitor_log("postmaster monitor: grace expired; escalating to SIGKILL");
                signal_service(&watch, service_pid, Signal::KILL);
                while !watch.dead(service_pid) {
                    std::thread::sleep(poll_interval);
                }
            }
            cleanup_and_exit(dir_fd.as_ref(), &names);
        }
        if watch.dead(service_pid) {
            // Service death from any cause: natural exit, kill -9, crash.
            cleanup_and_exit(dir_fd.as_ref(), &names);
        }
        std::thread::sleep(poll_interval);
    }
}

/// Wait up to `grace` for the service to die. Returns true when death is
/// confirmed within the grace window.
fn wait_for_death(watch: &Watch, pid: Pid, grace: Duration, poll_interval: Duration) -> bool {
    let deadline = Instant::now() + grace;
    loop {
        if watch.dead(pid) {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        std::thread::sleep(poll_interval.min(deadline - now));
    }
}

/// Unlink the written plaintext files (fd-relative, best-effort — an
/// already-vanished entry is ignored) and exit the monitor. Never
/// returns.
fn cleanup_and_exit<Fd: AsFd>(dir_fd: Option<&Fd>, names: &[String]) -> ! {
    if let Some(fd) = dir_fd {
        cleanup_written(fd, names);
    } else if !names.is_empty() {
        // Unreachable from the launcher (names are only tracked in fd
        // modes); logged so a future caller regression is visible.
        monitor_log("postmaster monitor: entry names without a directory fd; cannot clean");
    }
    exit_process(0)
}

/// Send `sig` to the service. Delivery errors (e.g. `ESRCH` because the
/// service died first) are ignored — the subsequent death wait settles
/// the outcome either way.
#[cfg(target_os = "linux")]
fn signal_service(watch: &Watch, pid: Pid, sig: Signal) {
    // With a pidfd, signal through it: pidfd_send_signal(2) pins the
    // process and cannot hit a recycled PID — the same PID-reuse
    // rationale that makes pidfd the liveness choice.
    if let Watch::Pidfd(fd) = watch {
        let _ = pidfd_send_signal(fd, sig);
    } else {
        let _ = kill_process(pid, sig);
    }
}

/// Send `sig` to the service (see the Linux leg). Darwin has no pidfd,
/// so forwarding is plain kill(2); the bounded PID-reuse exposure on the
/// macOS stop path is documented in the threat model.
#[cfg(target_os = "macos")]
fn signal_service(_watch: &Watch, pid: Pid, sig: Signal) {
    let _ = kill_process(pid, sig);
}

/// Exit the monitor without running destructors, atexit handlers, or
/// stdio flushes — mandatory in a fork-child (inherited buffers and
/// handlers must not run twice; see module docs).
#[cfg(target_os = "linux")]
fn exit_process(code: i32) -> ! {
    // exit_group(2) ≡ _exit(2): a safe rustix wrapper, no libc FFI.
    runtime::exit_group(code)
}

/// Exit the monitor (see the Linux leg).
#[cfg(target_os = "macos")]
fn exit_process(code: i32) -> ! {
    // SAFETY: _exit(2) is async-signal-safe and callable from any
    // context; it runs no handlers and flushes nothing — exactly the
    // fork-child exit semantics required here.
    unsafe { libc::_exit(code) }
}

/// Best-effort diagnostic to stderr that stays inside the fork-child
/// discipline: a raw write(2) — no allocation, no stdio locks (the fork
/// parent may be multithreaded, e.g. under `cargo test`). SIGPIPE is
/// blocked for the monitor's life, so a closed pipe cannot kill us here.
fn monitor_log(msg: &str) {
    // SAFETY: fd 2 is the process's stderr; if it has been closed the
    // write simply fails with EBADF. The borrowed fd is not stored and
    // does not outlive the call; nothing is closed.
    let stderr = unsafe { std::os::fd::BorrowedFd::borrow_raw(2) };
    let _ = rustix::io::write(stderr, msg.as_bytes());
    let _ = rustix::io::write(stderr, b"\n");
}

/// The service liveness watch. Event sources (pidfd `POLLIN`, kqueue
/// `NOTE_EXIT`) fire at process exit — zombie- and PID-reuse-proof,
/// which is why they are the choice and `kill(pid, 0)` polling is only
/// the fallback (zombie-blind, PID-reuse-prone).
#[cfg(target_os = "linux")]
enum Watch {
    /// pidfd(2) opened at monitor start; the fd pins the process.
    Pidfd(OwnedFd),
    /// kill(pid, 0) fallback for kernels without pidfd_open (< 5.3).
    Poll,
    /// The service was already dead when the monitor started.
    Dead,
}

#[cfg(target_os = "linux")]
impl Watch {
    fn new(pid: Pid) -> Self {
        match pidfd_open(pid, PidfdFlags::empty()) {
            Ok(fd) => Self::Pidfd(fd),
            // ESRCH is race-free "definitely gone" — clean up at once.
            Err(Errno::SRCH) => Self::Dead,
            // ENOSYS (old kernel), EMFILE, …: degrade to polling.
            Err(_) => {
                monitor_log(
                    "postmaster monitor: pidfd_open failed; falling back to kill(pid, 0) polling",
                );
                Self::Poll
            }
        }
    }

    fn dead(&self, pid: Pid) -> bool {
        match self {
            Self::Dead => true,
            Self::Poll => matches!(test_kill_process(pid), Err(Errno::SRCH)),
            Self::Pidfd(fd) => {
                let mut fds = [PollFd::new(fd, PollFlags::IN)];
                match poll(&mut fds, Some(&ZERO_TIMESPEC)) {
                    // POLLIN: the process has terminated (fires at exit,
                    // not at reap — zombie-proof). POLLERR is treated as
                    // dead too: a pidfd that errors cannot supervise.
                    Ok(_) => fds[0].revents().intersects(PollFlags::IN | PollFlags::ERR),
                    // A failed poll means "unknown", not "dead": keep
                    // watching rather than abandon supervision.
                    Err(_) => false,
                }
            }
        }
    }
}

/// The service liveness watch (see the Linux leg).
#[cfg(target_os = "macos")]
enum Watch {
    /// kqueue with `EVFILT_PROC`/`NOTE_EXIT` registered for the service.
    Kqueue(OwnedFd),
    /// kill(pid, 0) fallback (kqueue creation failed — fd exhaustion).
    Poll,
    /// The service was already dead when the monitor started.
    Dead,
}

#[cfg(target_os = "macos")]
impl Watch {
    fn new(pid: Pid) -> Self {
        // ESRCH is race-free "definitely gone" — clean up at once.
        if matches!(test_kill_process(pid), Err(Errno::SRCH)) {
            return Self::Dead;
        }
        // SAFETY: kqueue(2) has no preconditions and returns a fresh
        // queue fd on success. The kevent registration passes valid
        // stack pointers and a well-formed changelist built from
        // constants; a NULL timeout with an empty eventlist cannot block.
        unsafe {
            let kq = libc::kqueue();
            if kq == -1 {
                monitor_log(
                    "postmaster monitor: kqueue failed; falling back to kill(pid, 0) polling",
                );
                return Self::Poll;
            }
            let change = libc::kevent {
                ident: pid.as_raw_pid() as usize,
                filter: libc::EVFILT_PROC,
                flags: libc::EV_ADD,
                fflags: libc::NOTE_EXIT,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            if libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) == -1 {
                // With a changelist-only call, a knote error comes back
                // as the kevent errno. ESRCH means the pid lookup failed
                // because the service already exited (xnu drops exited
                // procs from the pid table before they are reaped) —
                // race-free "definitely gone", same as pidfd_open's ESRCH
                // on Linux, so clean up at once rather than degrading to
                // zombie-blind polling.
                let dead = std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
                libc::close(kq);
                if dead {
                    return Self::Dead;
                }
                monitor_log(
                    "postmaster monitor: kevent registration failed; falling back to kill(pid, 0) polling",
                );
                return Self::Poll;
            }
            // SAFETY: kq is a fresh, valid fd owned by this process;
            // wrapping it in OwnedFd closes it exactly once at drop.
            Self::Kqueue(OwnedFd::from_raw_fd(kq))
        }
    }

    fn dead(&self, pid: Pid) -> bool {
        match self {
            Self::Dead => true,
            Self::Poll => matches!(test_kill_process(pid), Err(Errno::SRCH)),
            Self::Kqueue(kq) => {
                // SAFETY: `ev`/`ts` are valid stack locals that outlive
                // the call; a zero timeout makes kevent(2) a non-blocking
                // queue drain; the queue fd is valid (owned).
                unsafe {
                    let mut ev: libc::kevent = std::mem::zeroed();
                    let ts = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    };
                    if libc::kevent(kq.as_raw_fd(), std::ptr::null(), 0, &mut ev, 1, &ts) > 0 {
                        // The queue holds only the one NOTE_EXIT knote.
                        return true;
                    }
                }
                // Defense-in-depth net for any exit the knote misses
                // (xnu attach subtleties): ESRCH is race-free "definitely
                // gone". The registration-time case of this race returns
                // Watch::Dead above instead.
                matches!(test_kill_process(pid), Err(Errno::SRCH))
            }
        }
    }
}

/// Block the stop signals plus `SIGPIPE` for the monitor's lifetime.
/// The four stop signals are normally already blocked by the launcher's
/// `TerminationGuard` and inherited across fork (blocking again is a
/// no-op); re-asserting keeps the monitor correct when the caller did
/// not pre-block (unit tests). `SIGPIPE` is monitor-local so the raw
/// stderr write in `monitor_log` cannot kill the monitor via a closed
/// pipe. A failure is logged and supervision continues: the inherited
/// mask is the common case, and failing to block cannot strand
/// plaintext by itself.
#[cfg(target_os = "linux")]
fn block_monitor_signals() {
    let mut set = KernelSigSet::empty();
    for sig in STOP_SIGNALS {
        set.insert(sig);
    }
    set.insert(Signal::PIPE);
    // SAFETY: single-threaded fork-child; the set holds only standard
    // signals — none reserved by a libc in the process (glibc reserves
    // 32/33, untouched). Blocking these signals for life breaks no other
    // code's assumptions: the monitor consumes the stop set synchronously
    // and never installs handlers.
    if unsafe { runtime::kernel_sigprocmask(runtime::How::BLOCK, Some(&set)) }.is_err() {
        monitor_log("postmaster monitor: failed to block termination signals");
    }
}

/// Block the stop signals plus `SIGPIPE` (see the Linux leg).
#[cfg(target_os = "macos")]
fn block_monitor_signals() {
    // SAFETY: zeroed sigset_t is a valid empty set representation; all
    // pointers are valid stack locals that outlive the calls; the pthread
    // form is correct in single- and multi-threaded processes.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in STOP_SIGNALS {
            libc::sigaddset(&mut set, sig.as_raw());
        }
        libc::sigaddset(&mut set, libc::SIGPIPE);
        if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            monitor_log("postmaster monitor: failed to block termination signals");
        }
    }
}

/// The set of signals consumed synchronously by the loop.
#[cfg(target_os = "linux")]
fn stop_sigset() -> KernelSigSet {
    let mut set = KernelSigSet::empty();
    for sig in STOP_SIGNALS {
        set.insert(sig);
    }
    set
}

/// The set of signals consumed synchronously by the loop.
#[cfg(target_os = "macos")]
fn stop_sigset() -> libc::sigset_t {
    // SAFETY: zeroed sigset_t is a valid empty set representation;
    // sigemptyset/sigaddset operate on a valid stack local.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in STOP_SIGNALS {
            libc::sigaddset(&mut set, sig.as_raw());
        }
        set
    }
}

/// Dequeue a pending stop signal without blocking, if one is pending.
/// The signals are blocked for life, so they pend until consumed here —
/// synchronous consumption, no handlers anywhere. (Darwin has no
/// `sigtimedwait`, so both platforms use the portable
/// sigpending-then-sigwait form on the poll tick; the bounded stop
/// latency — one tick — is the latency the design explicitly budgets.)
#[cfg(target_os = "linux")]
fn take_pending_stop(set: &KernelSigSet) -> Option<Signal> {
    if !STOP_SIGNALS
        .iter()
        .any(|s| runtime::kernel_sigpending().contains(*s))
    {
        return None;
    }
    // SAFETY: a signal from the set IS pending (checked above), so
    // sigwait dequeues and returns immediately; the set holds only
    // standard non-reserved signals; single-threaded here.
    unsafe { runtime::kernel_sigwait(set) }.ok()
}

/// Dequeue a pending stop signal without blocking (see the Linux leg).
#[cfg(target_os = "macos")]
fn take_pending_stop(set: &libc::sigset_t) -> Option<Signal> {
    // SAFETY: zeroed sigset_t is valid and sigpending fills it; sigwait
    // is called only when a set member is pending, so it returns
    // immediately; all pointers are valid stack locals.
    unsafe {
        let mut pending: libc::sigset_t = std::mem::zeroed();
        if libc::sigpending(&mut pending) != 0 {
            return None;
        }
        if !STOP_SIGNALS
            .iter()
            .any(|s| libc::sigismember(&pending, s.as_raw()) == 1)
        {
            return None;
        }
        let mut got: libc::c_int = 0;
        if libc::sigwait(set, &mut got) != 0 {
            return None;
        }
        Signal::from_named_raw(got)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("postmaster's sibling monitor supports Linux and macOS only");

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
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
    /// so the disposition doesn't survive into `sleep` there.
    fn fork_term_ignoring_service() -> Pid {
        // SAFETY: fork(2) in the test process; the child executes only
        // async-signal-safe calls (signal(2), pause(2)) and never returns
        // into the test harness — no allocation, no stdio, no locks.
        match unsafe { libc::fork() } {
            -1 => panic!("fork: {}", std::io::Error::last_os_error()),
            0 => unsafe {
                // SAFETY: plain single-threaded signal op on this
                // process; SIG_IGN is the documented ignore-disposition
                // constant. pause(2) suspends until a caught signal
                // arrives; TERM is ignored, so only SIGKILL ends the loop.
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
                loop {
                    libc::pause();
                }
            },
            child => Pid::from_raw(child).unwrap(),
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
}
