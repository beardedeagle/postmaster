//! Serving logic, platform hardening, listener acquisition, and the fetch client.
//!
//! This module contains the bulk of the runtime behavior while keeping
//! main.rs thin.

#![allow(missing_docs, missing_debug_implementations)]

use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
use libc;

use crate::adapter::KeyNaming;
use crate::config::{Args, Config, Entry, KeysSource};
use crate::keys::{KeyRing, resolve};

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const SD_LISTEN_FDS_START: RawFd = 3;

// stderr IS the daemon's log transport (journald on Linux, launchd
// StandardErrorPath on darwin) — this is the one sanctioned print site.
#[allow(clippy::print_stderr)]
pub fn log(msg: &str) {
    eprintln!("postmaster: {msg}");
}

pub fn serve(
    listener: UnixListener,
    path: PathBuf,
    entry: Entry,
    peer_uid: Option<u32>,
    ring: Arc<KeyRing>,
    allow_nonroot: bool,
) {
    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(e) => {
                log(&format!("{}: accept: {e}", path.display()));
                continue;
            }
        };
        if !allow_nonroot {
            match peer_euid(&stream) {
                Ok(0) => {}
                Ok(uid) if peer_uid == Some(uid) => {}
                Ok(uid) => {
                    log(&format!("{}: denied peer uid {uid}", path.display()));
                    continue;
                }
                Err(e) => {
                    log(&format!("{}: peer credentials: {e}", path.display()));
                    continue;
                }
            }
        }
        let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
        // Fresh resolution per request: rotation-friendly, nothing cached.
        match resolve(&entry, &ring, KeyNaming::Env) {
            Ok(value) => {
                if let Err(e) = stream.write_all(&value) {
                    log(&format!("{}: write: {e}", path.display()));
                }
                let _ = stream.shutdown(Shutdown::Both);
            }
            Err(e) => {
                // Preflight makes this near-unreachable (store paths are
                // immutable). Write nothing: the consumer sees an empty
                // credential and must treat that as fatal; we log loudly.
                log(&format!("{}: REFUSING TO SERVE: {e}", path.display()));
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }
}

/// Connect, read one credential to EOF. Zero bytes means the server
/// refused to serve — fail closed, exactly like LoadCredential failing.
pub fn fetch_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut stream =
        UnixStream::connect(path).map_err(|e| format!("{}: connect: {e}", path.display()))?;
    let _ = stream.set_read_timeout(Some(WRITE_TIMEOUT));
    let mut buf = Zeroizing::new(Vec::new());
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("{}: read: {e}", path.display()))?;
    if buf.is_empty() {
        return Err(format!(
            "{}: server sent zero bytes (refused to serve); failing closed",
            path.display()
        ));
    }
    Ok(buf)
}

/// Client half for platforms without LoadCredential (darwin wrappers):
/// connect, read one credential to EOF, emit on stdout. Zero bytes means
/// the server refused to serve — fail closed, exactly like LoadCredential
/// failing the unit.
pub fn fetch(path: &Path) -> Result<(), String> {
    let buf = fetch_bytes(path)?;
    let mut out = std::io::stdout().lock();
    out.write_all(&buf)
        .and_then(|()| out.flush())
        .map_err(|e| format!("stdout: {e}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn sd_listen_fds() -> Vec<RawFd> {
    let pid_ok = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .and_then(rustix::process::Pid::from_raw)
        .map(|p| p == rustix::process::getpid())
        .unwrap_or(false);
    let n: RawFd = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if !pid_ok || n <= 0 {
        return Vec::new();
    }
    (SD_LISTEN_FDS_START..SD_LISTEN_FDS_START + n).collect()
}

#[cfg(target_os = "linux")]
fn peer_euid(stream: &UnixStream) -> std::io::Result<u32> {
    let cred = rustix::net::sockopt::socket_peercred(stream)?;
    Ok(cred.uid.as_raw())
}

#[cfg(target_os = "macos")]
fn peer_euid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;
    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;
    // SAFETY: getpeereid only writes the two out-params, which are exactly
    // the types it declares; the fd stays valid for the borrow of `stream`.
    // Darwin's stable kernel ABI is libc — there is no raw-syscall route.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(euid)
}

#[cfg(target_os = "linux")]
pub fn harden_process() {
    // No core dumps, no ptrace from non-privileged peers.
    let _ = rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);
    // Best effort: keep key material off swap even without the unit-level
    // MemorySwapMax=0 belt (may fail under RLIMIT_MEMLOCK; that's fine).
    let _ = rustix::mm::mlockall(
        rustix::mm::MlockAllFlags::CURRENT | rustix::mm::MlockAllFlags::FUTURE,
    );
}

#[cfg(target_os = "macos")]
pub fn harden_process() {
    // Closest analog to PR_SET_DUMPABLE for dumps: no core files, ever.
    let _ = rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    );
    // macOS has no mlockall(2); its swap is encrypted by default, so pages
    // that do swap out are ciphertext at rest. Deny debugger attach in
    // release builds (the ptrace-from-peers half of PR_SET_DUMPABLE).
    #[cfg(not(debug_assertions))]
    // SAFETY: PT_DENY_ATTACH takes no pointer arguments; null addr and zero
    // data are the documented invocation.
    unsafe {
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
}

/// Resolve a user name to a uid without getpwnam FFI.
pub fn uid_of(name: &str) -> Result<u32, String> {
    #[cfg(target_os = "macos")]
    const ID: &str = "/usr/bin/id";
    #[cfg(not(target_os = "macos"))]
    const ID: &str = "id";
    let out = std::process::Command::new(ID)
        .args(["-u", name])
        .output()
        .map_err(|e| format!("{ID}: {e}"))?;
    if !out.status.success() {
        return Err(format!("peer_user {name:?}: no such user"));
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("peer_user {name:?}: `id -u` output not a uid"))
}

pub fn keys_path(source: &KeysSource) -> Result<PathBuf, String> {
    match source {
        KeysSource::Credential(name) => {
            let dir = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(
                "keys.credential configured but $CREDENTIALS_DIRECTORY is unset \
                 (is LoadCredential wired on the postmaster unit?)",
            )?;
            Ok(Path::new(&dir).join(name))
        }
        KeysSource::File(p) => {
            if p.starts_with("/nix/store") {
                return Err(format!(
                    "{}: refusing plaintext private keys from the world-readable Nix store",
                    p.display()
                ));
            }
            Ok(p.clone())
        }
    }
}

pub fn acquire_listeners(
    cfg: &Config,
    bind: bool,
    peer_uids: &std::collections::HashMap<PathBuf, Option<u32>>,
) -> Result<Vec<(UnixListener, PathBuf)>, String> {
    use std::os::fd::AsFd;
    if bind {
        let am_root = rustix::process::geteuid().is_root();
        let mut out = Vec::new();
        for path in cfg.credentials.keys() {
            let expected = peer_uids.get(path).copied().flatten();
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
                // The parent directory is the filesystem half of the ACL:
                // owned by the consumer's user, execute-only-for-owner, so
                // only that user (and root) can even reach the socket. Only
                // meaningful when we run privileged; dev runs skip it.
                if am_root && let Some(uid) = expected {
                    rustix::fs::chown(parent, Some(rustix::fs::Uid::from_raw(uid)), None)
                        .map_err(|e| format!("{}: chown: {e}", parent.display()))?;
                    // Audit finding #6: use fchmod on the directory fd
                    // instead of set_permissions on the path to eliminate a
                    // TOCTOU between chown and chmod. Open the directory
                    // read-only with O_DIRECTORY, fchmod the fd, close.
                    let dir_fd = rustix::fs::open(
                        parent,
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(|e| format!("{}: open dir: {e}", parent.display()))?;
                    rustix::fs::fchmod(&dir_fd, rustix::fs::Mode::from_bits_truncate(0o500))
                        .map_err(|e| format!("{}: fchmod: {e}", parent.display()))?;
                }
            }
            let _ = fs::remove_file(path);
            let l =
                UnixListener::bind(path).map_err(|e| format!("{}: bind: {e}", path.display()))?;
            // connect(2) needs write on the socket inode; the reachability
            // gate is the 0500 parent dir plus the peer-credential check.
            let mode = if expected.is_some() { 0o666 } else { 0o600 };
            // Audit finding #7: use fchmod on the socket fd instead of
            // set_permissions on the path to eliminate a TOCTOU between
            // bind and chmod. Between those two path operations an attacker
            // with directory write access could unlink the socket and
            // create a symlink. fchmod operates on the already-bound fd,
            // which is the socket inode we just created.
            rustix::fs::fchmod(l.as_fd(), rustix::fs::Mode::from_bits_truncate(mode))
                .map_err(|e| format!("{}: fchmod: {e}", path.display()))?;
            out.push((l, path.clone()));
        }
        return Ok(out);
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(
            "socket activation is a systemd contract; on this platform postmaster \
             requires --bind (launchd mode)"
                .into(),
        )
    }

    #[cfg(target_os = "linux")]
    {
        let fds = sd_listen_fds();
        if fds.is_empty() {
            return Err("no sockets inherited from systemd (and --bind not given); \
             start via postmaster-credd.socket"
                .into());
        }
        let mut seen: Vec<PathBuf> = Vec::new();
        let mut out = Vec::new();
        for fd in fds {
            // SAFETY: the sole unsafe in the program. sd_listen_fds() proved
            // LISTEN_PID names this process, so fds [3, 3+n) are listening
            // sockets systemd created for us and nothing else owns them; taking
            // ownership here is exactly the sd_listen_fds(3) contract.
            let l = unsafe { UnixListener::from_raw_fd(fd) };
            rustix::io::fcntl_setfd(&l, rustix::io::FdFlags::CLOEXEC)
                .map_err(|e| format!("fd {fd}: FD_CLOEXEC: {e}"))?;
            let path = l
                .local_addr()
                .ok()
                .and_then(|a| a.as_pathname().map(Path::to_path_buf))
                .ok_or_else(|| format!("fd {fd}: inherited socket has no filesystem path"))?;
            if !cfg.credentials.contains_key(&path) {
                // Fail closed: an unmapped socket means config and socket unit
                // have diverged; serving nothing on it would strand a consumer.
                return Err(format!(
                    "{}: inherited socket not present in --config; refusing to start",
                    path.display()
                ));
            }
            seen.push(path.clone());
            out.push((l, path));
        }
        for configured in cfg.credentials.keys() {
            if !seen.contains(configured) {
                return Err(format!(
                    "{}: configured credential has no inherited socket; refusing to start",
                    configured.display()
                ));
            }
        }
        Ok(out)
    }
}

pub fn run(args: &Args) -> Result<(), String> {
    let raw = fs::read(&args.config).map_err(|e| format!("{}: {e}", args.config.display()))?;
    let cfg: Config =
        serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", args.config.display()))?;
    if cfg.credentials.is_empty() {
        return Err("config maps no credentials; nothing to do".into());
    }

    let ring = Arc::new(KeyRing::load(&keys_path(&cfg.keys)?, KeyNaming::Env)?);

    // Preflight: prove every credential is servable — and every peer_user
    // resolvable — before accepting anyone.
    let mut peer_uids: std::collections::HashMap<PathBuf, Option<u32>> =
        std::collections::HashMap::new();
    for (path, entry) in &cfg.credentials {
        resolve(entry, &ring, KeyNaming::Env)
            .map_err(|e| format!("preflight {}: {e}", path.display()))?;
        let uid = entry
            .peer_user
            .as_deref()
            .map(uid_of)
            .transpose()
            .map_err(|e| format!("preflight {}: {e}", path.display()))?;
        peer_uids.insert(path.clone(), uid);
    }
    log(&format!(
        "preflight ok: {} credential(s) decryptable",
        cfg.credentials.len()
    ));

    let listeners = acquire_listeners(&cfg, args.bind, &peer_uids)?;
    let mut handles = Vec::new();
    for (listener, path) in listeners {
        let entry = cfg.credentials.get(&path).expect("validated above").clone();
        let peer_uid = peer_uids.get(&path).copied().flatten();
        let ring = Arc::clone(&ring);
        let allow = args.allow_nonroot;
        let label = path.clone();
        handles.push(
            thread::Builder::new()
                .name(format!("serve:{}", label.display()))
                .spawn(move || serve(listener, path, entry, peer_uid, ring, allow))
                .map_err(|e| format!("spawn: {e}"))?,
        );
    }
    log(&format!("serving {} socket(s)", handles.len()));
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn fetch_bytes_roundtrip_and_empty_fails_closed() {
        let dir = std::env::temp_dir().join(format!("pm-fetch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("t.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let t = thread::spawn(move || {
            for (i, conn) in listener.incoming().take(2).enumerate() {
                let mut s = conn.unwrap();
                if i == 0 {
                    s.write_all(b"sekrit").unwrap();
                }
                let _ = s.shutdown(Shutdown::Both);
            }
        });
        assert_eq!(&*fetch_bytes(&sock).unwrap(), b"sekrit");
        assert!(fetch_bytes(&sock).unwrap_err().contains("zero bytes"));
        t.join().unwrap();
    }
}
