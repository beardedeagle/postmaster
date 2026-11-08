//! A bounded pseudo-terminal harness for secret-input regression tests.

#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::FromRawFd as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub struct TestPty {
    master: File,
    pub slave: File,
    pub output: Vec<u8>,
    child: Option<Child>,
}

impl TestPty {
    pub fn new() -> Self {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: valid output pointers; null optional arguments request default settings.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        // SAFETY: openpty returned two new descriptors, each transferred once to File.
        let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        Self {
            master,
            slave,
            output: Vec::new(),
            child: None,
        }
    }

    pub fn spawn(&mut self, command: &mut Command) {
        self.spawn_with_stderr(command, Stdio::from(self.slave.try_clone().unwrap()));
    }

    pub fn spawn_with_stderr(&mut self, command: &mut Command, stderr: Stdio) {
        self.child = Some(
            command
                .stdin(Stdio::from(self.slave.try_clone().unwrap()))
                .stdout(Stdio::from(self.slave.try_clone().unwrap()))
                .stderr(stderr)
                .spawn()
                .unwrap(),
        );
    }

    pub fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
    }

    fn receive(&mut self) {
        let mut fds = [rustix::event::PollFd::new(
            &self.master,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 20_000_000,
        };
        if rustix::event::poll(&mut fds, Some(&timeout)).unwrap() != 0 {
            let mut bytes = [0; 4096];
            if let Ok(count) = self.master.read(&mut bytes) {
                self.output.extend_from_slice(&bytes[..count]);
            }
        }
    }

    pub fn expect(&mut self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !String::from_utf8_lossy(&self.output).contains(needle) {
            assert!(
                Instant::now() < deadline,
                "missing {needle:?}: {}",
                String::from_utf8_lossy(&self.output)
            );
            self.receive();
        }
    }

    pub fn signal(&self, signal: rustix::process::Signal) {
        let pid = rustix::process::Pid::from_raw(self.child.as_ref().unwrap().id() as i32).unwrap();
        rustix::process::kill_process(pid, signal).unwrap();
    }

    pub fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.receive();
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                self.receive();
                return status;
            }
            assert!(Instant::now() < deadline, "child did not exit");
        }
    }
}

impl Drop for TestPty {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
