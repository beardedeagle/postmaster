//! Serving logic, platform hardening, listener acquisition, and the fetch client.
//!
//! This module contains the bulk of the runtime behavior while keeping
//! main.rs thin.

use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
use libc;

use crate::adapter::KeyNaming;
use crate::config::{Args, Config, Entry, KeysSource, SocketProtocol};
use crate::keys::{KeyRing, resolve};

/// Shared I/O deadline for socket reads and writes (one constant, so
/// the two directions can't silently diverge).
const IO_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const SD_LISTEN_FDS_START: RawFd = 3;

// stderr IS the daemon's log transport (journald on Linux, launchd
// StandardErrorPath on darwin) — this is the one sanctioned print site.
/// Log a message to stderr (journald on Linux, launchd on macOS).
#[allow(clippy::print_stderr)]
pub fn log(msg: &str) {
    eprintln!("postmaster: {msg}");
}

/// Serve a single credential entry on a Unix socket. Handles one peer
/// at a time (thread-per-socket); each peer must be uid 0 (root) or the
/// configured peer_user.
///
/// Connection limiting (documented decision): the
/// loop is serialized — one connection at a time, each accepted stream
/// closed at the end of its iteration, writes bounded by IO_TIMEOUT —
/// so per-connection FDs/threads never accumulate and pending connects
/// are bounded by the kernel backlog. A trusted peer (root or the
/// configured peer_user) can starve the listener with slow connections;
/// that is the authorized consumer of this socket, so no rate limiting
/// is implemented.
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
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        // Peer ACL: a configured peer_user is ALWAYS enforced — --allow-nonroot widens
        // root→configured-user, never root→anyone. The flag skips verification only
        // when no peer_user is configured (the dev loop it exists for).
        if !allow_nonroot || peer_uid.is_some() {
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
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        // Fresh resolution per request: rotation-friendly, nothing cached.
        match resolve(&entry, &ring, KeyNaming::Env) {
            Ok(value) => {
                if let Err(e) = write_credential(&mut stream, &value, entry.protocol) {
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

/// Maximum bytes accepted for a credential fetch payload, bundle JSON, or config
/// read. These payloads are small; the cap keeps a hostile or broken
/// peer from forcing unbounded heap allocation. Oversized payloads fail.
const MAX_READ_BYTES: u64 = 16 * 1024 * 1024;
const FRAME_MAGIC: [u8; 8] = *b"PMCR\0\0\0\x01";
const FRAME_HEADER_BYTES: usize = FRAME_MAGIC.len() + size_of::<u32>();

fn write_credential(
    stream: &mut impl Write,
    value: &[u8],
    protocol: SocketProtocol,
) -> std::io::Result<()> {
    if protocol == SocketProtocol::Framed {
        if value.is_empty() || value.len() as u64 > MAX_READ_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "credential frame payload must contain 1..=16 MiB bytes",
            ));
        }
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        header[..FRAME_MAGIC.len()].copy_from_slice(&FRAME_MAGIC);
        header[FRAME_MAGIC.len()..].copy_from_slice(&(value.len() as u32).to_be_bytes());
        stream.write_all(&header)?;
    }
    stream.write_all(value)
}

/// Read `reader` to EOF with a hard size cap.
/// Fails rather than truncates when the stream exceeds the cap — a
/// truncated secret must never be served as if complete.
pub(crate) fn read_capped<R: Read>(reader: R, path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut limited = reader.take(MAX_READ_BYTES + 1);
    let mut buf = Zeroizing::new(Vec::new());
    limited
        .read_to_end(&mut buf)
        .map_err(|e| format!("{}: read: {e}", path.display()))?;
    if buf.len() as u64 > MAX_READ_BYTES {
        return Err(format!(
            "{}: exceeds the {}-byte size cap",
            path.display(),
            MAX_READ_BYTES
        ));
    }
    Ok(buf)
}

/// Open a regular file without blocking on special files, then read within the byte cap.
pub(crate) fn read_regular_capped(
    path: &Path,
    extra_flags: rustix::fs::OFlags,
) -> Result<Zeroizing<Vec<u8>>, String> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | extra_flags,
        Mode::empty(),
    )
    .map_err(|e| {
        if extra_flags.contains(OFlags::NOFOLLOW) && e == rustix::io::Errno::LOOP {
            format!(
                "{}: open: {e} (refusing to follow a symlink)",
                path.display()
            )
        } else {
            format!("{}: open: {e}", path.display())
        }
    })?;
    let stat = fstat(&fd).map_err(|e| format!("{}: stat: {e}", path.display()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(format!("{}: not a regular file", path.display()));
    }
    read_capped(fs::File::from(fd), path)
}

/// Connect, read one credential to EOF (hard-capped by `read_capped`).
/// Zero bytes means the server refused to serve — fail closed, exactly
/// like LoadCredential failing.
pub fn fetch_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    fetch_bytes_with_options(path, SocketProtocol::Raw, None)
}

/// Fetch a complete credential, optionally checking the listener's kernel peer uid.
/// Framed endpoints require an explicit expected uid and reject incomplete responses.
/// All connection and read operations share one deadline.
pub fn fetch_bytes_with_options(
    path: &Path,
    protocol: SocketProtocol,
    expected_uid: Option<u32>,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if protocol == SocketProtocol::Framed && expected_uid.is_none() {
        return Err("framed fetch requires an expected server uid".into());
    }
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut stream = connect_fetch(path, deadline)?;
    if let Some(expected) = expected_uid {
        let actual = peer_euid(&stream)
            .map_err(|e| format!("{}: server peer credentials: {e}", path.display()))?;
        if actual != expected {
            return Err(format!(
                "{}: server uid {actual} does not match expected uid {expected}",
                path.display()
            ));
        }
    }
    let buf = read_fetch(&mut stream, path, deadline, protocol)?;
    if buf.is_empty() {
        return Err(format!(
            "{}: server sent zero bytes (refused to serve); failing closed",
            path.display()
        ));
    }
    Ok(buf)
}

fn connect_fetch(path: &Path, deadline: Instant) -> Result<UnixStream, String> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketType};
    let socket = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)
        .map_err(|e| format!("{}: socket: {e}", path.display()))?;
    rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC)
        .map_err(|e| format!("{}: FD_CLOEXEC: {e}", path.display()))?;
    rustix::fs::fcntl_setfl(&socket, rustix::fs::OFlags::NONBLOCK)
        .map_err(|e| format!("{}: nonblocking socket: {e}", path.display()))?;
    let address = SocketAddrUnix::new(path)
        .map_err(|e| format!("{}: socket address: {e}", path.display()))?;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| format!("{}: credential fetch timed out", path.display()))?;
        match rustix::net::connect(&socket, &address) {
            Ok(()) | Err(rustix::io::Errno::ISCONN) => break,
            Err(
                rustix::io::Errno::AGAIN
                | rustix::io::Errno::INPROGRESS
                | rustix::io::Errno::ALREADY,
            ) => {
                thread::sleep(remaining.min(Duration::from_millis(10)));
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(format!("{}: connect: {e}", path.display())),
        }
    }
    Ok(UnixStream::from(socket))
}

fn read_fetch(
    stream: &mut UnixStream,
    path: &Path,
    deadline: Instant,
    protocol: SocketProtocol,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let expected = if protocol == SocketProtocol::Framed {
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        let mut filled = 0;
        while filled < header.len() {
            let n = read_fetch_chunk(stream, &mut header[filled..], path, deadline)?;
            if n == 0 {
                return Err(format!(
                    "{}: truncated credential frame header",
                    path.display()
                ));
            }
            filled += n;
        }
        if header[..FRAME_MAGIC.len()] != FRAME_MAGIC {
            return Err(format!(
                "{}: invalid credential frame magic/version",
                path.display()
            ));
        }
        let mut encoded_length = [0_u8; size_of::<u32>()];
        encoded_length.copy_from_slice(&header[FRAME_MAGIC.len()..]);
        let length = u32::from_be_bytes(encoded_length) as usize;
        if length == 0 || length as u64 > MAX_READ_BYTES {
            return Err(format!(
                "{}: credential frame payload must contain 1..=16 MiB bytes",
                path.display()
            ));
        }
        Some(length)
    } else {
        None
    };
    let mut buf = Zeroizing::new(Vec::with_capacity(expected.unwrap_or(0)));
    let mut chunk = Zeroizing::new([0_u8; 8192]);
    loop {
        let remaining = expected
            .unwrap_or(MAX_READ_BYTES as usize)
            .saturating_sub(buf.len());
        let n = read_fetch_chunk(
            stream,
            &mut chunk[..(remaining + 1).min(8192)],
            path,
            deadline,
        )?;
        if n == 0 {
            if expected.is_some_and(|length| buf.len() != length) {
                return Err(format!(
                    "{}: truncated credential frame payload",
                    path.display()
                ));
            }
            return Ok(buf);
        }
        if n > remaining {
            let reason = if expected.is_some() {
                "credential frame contains extra bytes".to_string()
            } else {
                format!("exceeds the {MAX_READ_BYTES}-byte size cap")
            };
            return Err(format!("{}: {reason}", path.display()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn read_fetch_chunk(
    stream: &mut UnixStream,
    output: &mut [u8],
    path: &Path,
    deadline: Instant,
) -> Result<usize, String> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| format!("{}: credential fetch timed out", path.display()))?;
        let mut ready = [rustix::event::PollFd::new(
            &*stream,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec::try_from(remaining)
            .map_err(|e| format!("{}: read deadline: {e}", path.display()))?;
        match rustix::event::poll(&mut ready, Some(&timeout)) {
            Ok(0) => return Err(format!("{}: credential fetch timed out", path.display())),
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(format!("{}: read readiness: {e}", path.display())),
        }
        match stream.read(output) {
            Ok(n) => return Ok(n),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(e) => return Err(format!("{}: read: {e}", path.display())),
        }
    }
}

/// Connect to a local credential socket, read to EOF, and write to stdout.
/// Available on Linux and macOS. Zero bytes means
/// the server refused to serve — fail closed, exactly like LoadCredential
/// failing the unit.
pub fn fetch(path: &Path) -> Result<(), String> {
    fetch_with_options(path, SocketProtocol::Raw, None)
}

/// Fetch using the selected protocol and peer uid, writing only a complete response.
pub fn fetch_with_options(
    path: &Path,
    protocol: SocketProtocol,
    expected_uid: Option<u32>,
) -> Result<(), String> {
    let buf = fetch_bytes_with_options(path, protocol, expected_uid)?;
    let mut out = std::io::stdout().lock();
    out.write_all(&buf)
        .and_then(|()| out.flush())
        .map_err(|e| format!("stdout: {e}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn sd_listen_fds() -> Result<std::ops::Range<RawFd>, String> {
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
        return Ok(SD_LISTEN_FDS_START..SD_LISTEN_FDS_START);
    }
    let end = SD_LISTEN_FDS_START
        .checked_add(n)
        .ok_or("LISTEN_FDS count overflows")?;
    Ok(SD_LISTEN_FDS_START..end)
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

/// Attempt to disable dumps and peer tracing and lock memory on Linux.
/// Failures are logged. Dumpability and memory locks reset across exec.
#[cfg(target_os = "linux")]
pub fn harden_process() {
    // No core dumps, no ptrace from non-privileged peers. Best-effort by policy, but a
    // failure is security-relevant — log it.
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        log(&format!(
            "hardening: set_dumpable(NotDumpable) failed: {e} — core dumps/ptrace not disabled"
        ));
    }
    // Best effort: keep key material off swap even without the unit-level
    // MemorySwapMax=0 belt (may fail under RLIMIT_MEMLOCK; that's fine —
    // but say so).
    if let Err(e) =
        rustix::mm::mlockall(rustix::mm::MlockAllFlags::CURRENT | rustix::mm::MlockAllFlags::FUTURE)
    {
        log(&format!(
            "hardening: mlockall failed: {e} — decrypted secrets may swap to disk (check RLIMIT_MEMLOCK)"
        ));
    }
}

/// Attempt to disable core dumps and, in release builds, peer tracing on macOS.
/// Failures are logged.
#[cfg(target_os = "macos")]
pub fn harden_process() {
    // Closest analog to PR_SET_DUMPABLE for dumps: no core files, ever. Best-effort by
    // policy, but failures are security-relevant — log them.
    if let Err(e) = rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    ) {
        log(&format!(
            "hardening: setrlimit(Core, 0) failed: {e} — core dumps not disabled"
        ));
    }
    // macOS has no mlockall(2); its swap is encrypted by default, so pages
    // that do swap out are ciphertext at rest. Deny debugger attach in
    // release builds (the ptrace-from-peers half of PR_SET_DUMPABLE).
    #[cfg(not(debug_assertions))]
    {
        // SAFETY: PT_DENY_ATTACH takes no pointer arguments; null addr and
        // zero data are the documented invocation.
        let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            log(&format!(
                "hardening: PT_DENY_ATTACH failed: {err} — debugger attach not denied"
            ));
        }
    }
}

/// Resolve a user name to a uid without getpwnam FFI.
pub fn uid_of(name: &str) -> Result<u32, String> {
    if name.is_empty() || name.starts_with('-') {
        return Err(format!("peer_user {name:?}: expected a user name"));
    }
    // Trust boundary: a compromised `id` returning a wrong uid would defeat the socket
    // peer-uid ACL. macOS invokes /usr/bin/id by absolute path under SIP, verified via
    // codesign. Linux never uses PATH resolution — a PATH-resolved `id` would inherit a
    // potentially attacker-controlled PATH; instead the first candidate absolute path
    // that verifies (regular file, root-owned, no group/other write bits — checked by
    // fstat on an O_NOFOLLOW|CLOEXEC fd) is invoked, and if none verifies the lookup
    // fails closed.
    #[cfg(target_os = "macos")]
    let id = {
        crate::keys::verify_external_binary(Path::new("/usr/bin/id"))?;
        PathBuf::from("/usr/bin/id")
    };
    #[cfg(not(target_os = "macos"))]
    let id = verified_id_binary()?;
    let out = std::process::Command::new(&id)
        .args(["-u", "--", name])
        .output()
        .map_err(|e| format!("{}: {e}", id.display()))?;
    if !out.status.success() {
        return Err(format!("peer_user {name:?}: no such user"));
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("peer_user {name:?}: `id -u` output not a uid"))
}

/// First `id(1)` candidate that exists and verifies, or a fail-closed
/// error listing why each was rejected (Linux only — see `uid_of`).
/// Candidates are well-known absolute paths in preference order; the
/// NixOS path covers systems without /usr/bin or /bin.
#[cfg(not(target_os = "macos"))]
fn verified_id_binary() -> Result<PathBuf, String> {
    const CANDIDATES: [&str; 3] = ["/usr/bin/id", "/bin/id", "/run/current-system/sw/bin/id"];
    let mut failures: Vec<String> = Vec::new();
    for path in CANDIDATES {
        match verify_id_candidate(path) {
            Ok(target) => return Ok(target),
            Err(e) => failures.push(e),
        }
    }
    Err(format!(
        "no trustworthy `id` binary found (refusing PATH resolution; tried {}): {}",
        CANDIDATES.join(", "),
        failures.join("; ")
    ))
}

/// Resolve a system alias, verify its protected target by opened fd, and return
/// that target for invocation. The final open uses O_NOFOLLOW|CLOEXEC.
/// The target must be a regular file owned by root with no group/other write
/// bits. Type, owner and mode are checked on the same opened inode.
#[cfg(not(target_os = "macos"))]
fn verify_id_candidate(path: &str) -> Result<PathBuf, String> {
    let target = fs::canonicalize(path).map_err(|e| format!("{path}: resolve: {e}"))?;
    crate::secret_files::validate_directory_path(
        target.parent().ok_or("id requires a parent directory")?,
    )?;
    let fd = rustix::fs::open(
        &target,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| format!("{path}: {e}"))?;
    let stat = rustix::fs::fstat(&fd).map_err(|e| format!("{path}: fstat: {e}"))?;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(format!("{path}: not a regular file"));
    }
    if stat.st_uid != 0 {
        return Err(format!(
            "{path}: owned by uid {} (expected root/0); refusing to trust",
            stat.st_uid
        ));
    }
    if rustix::fs::Mode::from_bits_truncate(stat.st_mode)
        .intersects(rustix::fs::Mode::WGRP | rustix::fs::Mode::WOTH)
    {
        return Err(format!("{path}: group/other writable; refusing to trust"));
    }
    Ok(target)
}

/// Resolve the keys file path from a `KeysSource` configuration.
pub fn keys_path(source: &KeysSource) -> Result<PathBuf, String> {
    match source {
        KeysSource::Credential(name) => {
            // Same discipline as the exec-config credential source: the name must be a
            // single relative path component — otherwise "../../…" would escape
            // $CREDENTIALS_DIRECTORY and read an arbitrary root-readable file as key
            // material.
            crate::exec_config::validate_credential_source_name(name)?;
            let dir = crate::key_source::credential_directory()?.ok_or(
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

/// RAII guard that sets the process umask so a bound unix socket is born
/// with `mode` (sockets are created `0777 & ~umask`) and restores the
/// prior mask on drop. Used only during single-threaded socket setup.
#[derive(Debug)]
struct UmaskGuard(rustix::fs::Mode);

impl UmaskGuard {
    fn around_bind(mode: rustix::fs::Mode) -> Self {
        let mask = !mode & rustix::fs::Mode::from_bits_truncate(0o777);
        Self(rustix::process::umask(mask))
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        rustix::process::umask(self.0);
    }
}

struct SocketDomain {
    parent: PathBuf,
    traversed: std::collections::HashSet<PathBuf>,
    uid: u32,
}

/// Resolve aliases while retaining each directory traversed by the consumer's pathname.
fn socket_domain(path: &Path, uid: u32) -> Result<SocketDomain, String> {
    let mut resolved = PathBuf::new();
    let mut traversed = std::collections::HashSet::new();
    for part in path
        .parent()
        .ok_or("socket requires a parent directory")?
        .components()
    {
        if part == std::path::Component::ParentDir {
            resolved.pop();
            continue;
        }
        resolved.push(part);
        match fs::canonicalize(&resolved) {
            Ok(path) => resolved = path,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: socket parent: {e}", path.display())),
        }
        traversed.extend(resolved.ancestors().map(Path::to_path_buf));
    }
    Ok(SocketDomain {
        parent: resolved,
        traversed,
        uid,
    })
}

/// Reject ownership domains where one consumer could replace another's sockets.
fn validate_socket_domains(
    cfg: &Config,
    peer_uids: &std::collections::HashMap<PathBuf, Option<u32>>,
    euid: u32,
) -> Result<(), String> {
    let mut domains: Vec<SocketDomain> = Vec::new();
    for path in cfg.credentials.keys() {
        let uid = if euid == 0 {
            peer_uids.get(path).copied().flatten().unwrap_or(0)
        } else {
            euid
        };
        let domain = socket_domain(path, uid)?;
        for other in &domains {
            let same = domain.parent == other.parent;
            let controlled = other.uid != 0 && domain.traversed.contains(&other.parent)
                || uid != 0 && other.traversed.contains(&domain.parent);
            if uid != other.uid && (same || controlled) {
                return Err(format!(
                    "{} and {}: socket parents have conflicting ownership domains",
                    domain.parent.display(),
                    other.parent.display()
                ));
            }
        }
        domains.push(domain);
    }
    Ok(())
}

fn open_socket_parent(parent: &Path, peer_uid: Option<u32>) -> Result<OwnedFd, String> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use std::collections::VecDeque;
    use std::os::unix::ffi::OsStringExt as _;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if !parent.is_absolute() {
        return Err(format!(
            "{}: socket parent must be absolute",
            parent.display()
        ));
    }
    let euid = rustix::process::geteuid().as_raw();
    let mut dir = rustix::fs::open("/", flags, Mode::empty())
        .map_err(|e| format!("/: socket parent: {e}"))?;
    let mut parts: VecDeque<_> = parent
        .components()
        .map(|part| part.as_os_str().to_owned())
        .collect();
    let mut links = 0;
    while let Some(part) = parts.pop_front() {
        let stat = rustix::fs::fstat(&dir).map_err(|e| format!("socket parent: {e}"))?;
        if stat.st_uid != 0 && stat.st_uid != euid && Some(stat.st_uid) != peer_uid {
            return Err(format!(
                "{}: socket ancestor is owned by an untrusted user",
                parent.display()
            ));
        }
        if stat.st_mode & 0o022 != 0 && stat.st_mode & 0o1000 == 0 {
            return Err(format!(
                "{}: socket ancestor permits untrusted replacement",
                parent.display()
            ));
        }
        crate::secret_files::validate_directory_acl(&dir)?;
        if part == "/" {
            dir = rustix::fs::open("/", flags, Mode::empty())
                .map_err(|e| format!("/: socket parent: {e}"))?;
            continue;
        }
        let opened = match rustix::fs::openat(&dir, &part, flags, Mode::empty()) {
            Err(rustix::io::Errno::NOENT) => {
                match rustix::fs::mkdirat(&dir, &part, Mode::from_bits_truncate(0o700)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => {
                        return Err(format!("{}: create socket parent: {e}", parent.display()));
                    }
                }
                rustix::fs::openat(&dir, &part, flags, Mode::empty())
            }
            result => result,
        };
        match opened {
            Ok(next) => dir = next,
            Err(error) => {
                let link = rustix::fs::statat(&dir, &part, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|e| format!("{}: socket parent: {e}", parent.display()))?;
                if FileType::from_raw_mode(link.st_mode) != FileType::Symlink
                    || parts.is_empty()
                    || (stat.st_uid != 0 && stat.st_uid != euid)
                    || (link.st_uid != 0 && link.st_uid != euid)
                {
                    return Err(format!(
                        "{}: socket parent: {error} (refusing an untrusted symlink)",
                        parent.display()
                    ));
                }
                links += 1;
                if links > 40 {
                    return Err(format!(
                        "{}: too many socket-parent symlinks",
                        parent.display()
                    ));
                }
                let target = rustix::fs::readlinkat(&dir, &part, Vec::new())
                    .map_err(|e| format!("{}: socket parent link: {e}", parent.display()))?;
                let target = PathBuf::from(std::ffi::OsString::from_vec(target.into_bytes()));
                for component in target.components().rev() {
                    parts.push_front(component.as_os_str().to_owned());
                }
            }
        }
    }
    let stat = rustix::fs::fstat(&dir).map_err(|e| format!("socket parent: {e}"))?;
    if stat.st_uid != 0 && stat.st_uid != euid && Some(stat.st_uid) != peer_uid {
        return Err(format!(
            "{}: socket parent is owned by an untrusted user",
            parent.display()
        ));
    }
    if stat.st_mode & 0o022 != 0 && stat.st_mode & 0o1000 == 0 {
        return Err(format!(
            "{}: socket parent permits untrusted replacement",
            parent.display()
        ));
    }
    crate::secret_files::validate_directory_acl(&dir)?;
    Ok(dir)
}

fn bind_in_directory(dir: &OwnedFd, name: &std::ffi::OsStr) -> Result<UnixListener, String> {
    let cwd = crate::secret_files::open_secrets_dir(Path::new("."))
        .map_err(|e| format!("pin current directory: {e}"))?;
    rustix::process::fchdir(dir).map_err(|e| format!("enter socket parent: {e}"))?;
    let listener = UnixListener::bind(Path::new(name));
    let restored = rustix::process::fchdir(&cwd);
    restored.map_err(|e| format!("restore current directory after bind: {e}"))?;
    listener.map_err(|e| format!("bind: {e}"))
}

/// Bind and listen on all configured credential sockets. Returns
/// a vector of `(UnixListener, path)` pairs ready for serving (the entry
/// is re-looked-up by the caller).
/// Call during single-threaded startup: bind mode temporarily changes umask and cwd.
pub fn acquire_listeners(
    cfg: &Config,
    bind: bool,
    peer_uids: &std::collections::HashMap<PathBuf, Option<u32>>,
) -> Result<Vec<(UnixListener, PathBuf)>, String> {
    if bind {
        validate_socket_domains(cfg, peer_uids, rustix::process::geteuid().as_raw())?;
        let am_root = rustix::process::geteuid().is_root();
        let mut out = Vec::new();
        for path in cfg.credentials.keys() {
            let expected = peer_uids.get(path).copied().flatten();
            let parent = path.parent().ok_or("socket requires a parent directory")?;
            let name = path.file_name().ok_or("socket requires a file name")?;
            let dir_fd = open_socket_parent(parent, expected)?;
            // The parent directory is the filesystem half of the ACL:
            // owned by the consumer's user, execute-only-for-owner, so
            // only that user (and root) can even reach the socket. Only
            // meaningful when we run privileged; dev runs skip it.
            if am_root && let Some(uid) = expected {
                rustix::fs::fchown(&dir_fd, Some(rustix::fs::Uid::from_raw(uid)), None)
                    .map_err(|e| format!("{}: fchown: {e}", parent.display()))?;
                rustix::fs::fchmod(&dir_fd, rustix::fs::Mode::from_bits_truncate(0o500))
                    .map_err(|e| format!("{}: fchmod: {e}", parent.display()))?;
            }
            let _ = rustix::fs::unlinkat(&dir_fd, name, rustix::fs::AtFlags::empty());
            // connect(2) needs write on the socket inode; the reachability
            // gate is the 0500 parent dir plus the peer-credential check.
            let mode = if expected.is_some() { 0o666 } else { 0o600 };
            // fchmod on Linux changes the sockfs inode, not the pathname;
            // Darwin rejects it. Bind with the final mode to avoid a chmod race.
            let l = {
                let _umask_guard =
                    UmaskGuard::around_bind(rustix::fs::Mode::from_bits_truncate(mode));
                bind_in_directory(&dir_fd, name).map_err(|e| format!("{}: {e}", path.display()))?
            };
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
        let fds = sd_listen_fds()?;
        if fds.is_empty() {
            return Err("no sockets inherited from systemd (and --bind not given); \
             start via postmaster-credd.socket"
                .into());
        }
        let mut seen: Vec<PathBuf> = Vec::new();
        let mut out = Vec::new();
        for fd in fds {
            validate_inherited_socket(fd)?;
            // SAFETY: the raw getsockopt checks proved fd is an open listening
            // stream socket. Startup is single-threaded, so it cannot close
            // between validation and adoption; systemd transferred its ownership.
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

#[cfg(target_os = "linux")]
fn validate_inherited_socket(fd: RawFd) -> Result<(), String> {
    for (option, expected) in [
        (libc::SO_DOMAIN, libc::AF_UNIX),
        (libc::SO_TYPE, libc::SOCK_STREAM),
        (libc::SO_ACCEPTCONN, 1),
    ] {
        let mut value: libc::c_int = 0;
        let mut len = size_of_val(&value) as libc::socklen_t;
        // SAFETY: getsockopt accepts an arbitrary raw descriptor and validates it
        // in the kernel; both output pointers reference initialized live storage.
        // No Rust fd owner or borrow is constructed before validity is established.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                std::ptr::from_mut(&mut value).cast(),
                &raw mut len,
            )
        };
        if result != 0 {
            return Err(format!(
                "fd {fd}: inherited socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        if len as usize != size_of_val(&value) || value != expected {
            return Err(format!("fd {fd}: expected a listening Unix stream socket"));
        }
    }
    Ok(())
}

/// Enforce the absoluteness the config type docs promise: a CWD-relative
/// socket or keys path would resolve against whatever directory the
/// daemon happened to start in.
fn validate_absolute_paths(cfg: &Config) -> Result<(), String> {
    for path in cfg.credentials.keys() {
        if !path.is_absolute() {
            return Err(format!(
                "{}: socket path must be absolute (fail closed)",
                path.display()
            ));
        }
    }
    if let KeysSource::File(p) = &cfg.keys
        && !p.is_absolute()
    {
        return Err(format!(
            "{}: keys file path must be absolute (fail closed)",
            p.display()
        ));
    }
    Ok(())
}

/// Preflight: prove every credential is servable — and every peer_user
/// resolvable — before accepting anyone. An empty resolved value is
/// unservable (zero bytes means refusal on the wire), so it fails here
/// at startup naming the key rather than leaving
/// the daemon looking healthy while the credential permanently fails
/// with a misdiagnosing message.
fn preflight_credentials(
    cfg: &Config,
    ring: &KeyRing,
) -> Result<std::collections::HashMap<PathBuf, Option<u32>>, String> {
    let mut peer_uids: std::collections::HashMap<PathBuf, Option<u32>> =
        std::collections::HashMap::new();
    for (path, entry) in &cfg.credentials {
        let value = resolve(entry, ring, KeyNaming::Env)
            .map_err(|e| format!("preflight {}: {e}", path.display()))?;
        if value.is_empty() {
            return Err(format!(
                "preflight {}: {} resolved to an empty value, which can never be served (zero bytes means refusal on the wire)",
                path.display(),
                entry.key
            ));
        }
        let uid = entry
            .peer_user
            .as_deref()
            .map(uid_of)
            .transpose()
            .map_err(|e| format!("preflight {}: {e}", path.display()))?;
        peer_uids.insert(path.clone(), uid);
    }
    Ok(peer_uids)
}

/// Load keys, bind sockets, and serve credential requests.
/// The caller applies process hardening before calling. Runs until the process is
/// terminated; returns only on startup-path failure.
pub fn run(args: &Args) -> Result<(), String> {
    let raw = read_regular_capped(&args.config, rustix::fs::OFlags::empty())?;
    let cfg: Config =
        serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", args.config.display()))?;
    if cfg.credentials.is_empty() {
        return Err("config maps no credentials; nothing to do".into());
    }
    validate_absolute_paths(&cfg)?;

    // The daemon's fetch contract is dotenvx-style env entries only; the
    // bundle adapter is an exec-mode surface, so the ring requires Env
    // naming alone here.
    let ring = Arc::new(KeyRing::load(&keys_path(&cfg.keys)?, &[KeyNaming::Env])?);

    let peer_uids = preflight_credentials(&cfg, &ring)?;
    log(&format!(
        "preflight ok: {} credential(s) decryptable",
        cfg.credentials.len()
    ));
    // --allow-nonroot never overrides a configured peer_user; say so once at startup
    // when both are present.
    if args.allow_nonroot && peer_uids.values().any(Option::is_some) {
        log(
            "note: --allow-nonroot does not override configured peer_user ACLs — peer_user sockets still verify the connecting uid",
        );
    }

    let listeners = acquire_listeners(&cfg, args.bind, &peer_uids)?;
    let mut handles = Vec::new();
    for (listener, path) in listeners {
        let entry = match cfg.credentials.get(&path) {
            Some(e) => e.clone(),
            // Unreachable (listeners derive from cfg.credentials), but a clear error
            // beats an abort under panic=abort.
            None => {
                return Err(format!(
                    "{}: internal: listener path missing from config",
                    path.display()
                ));
            }
        };
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
        h.join().map_err(|_| "credential server thread panicked")?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn fetch_bytes_roundtrip_and_empty_fails_closed() {
        let dir = crate::test_util::temp_dir::TestDir::new("server");
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

    fn fetch_wire(bytes: &[u8], protocol: SocketProtocol) -> Result<Zeroizing<Vec<u8>>, String> {
        let dir = crate::test_util::temp_dir::TestDir::new("frame");
        let sock = dir.join("credential.sock");
        let listener = UnixListener::bind(&sock).map_err(|e| e.to_string())?;
        let bytes = bytes.to_vec();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.write_all(&bytes);
        });
        let response =
            fetch_bytes_with_options(&sock, protocol, Some(rustix::process::geteuid().as_raw()));
        server
            .join()
            .map_err(|_| "mock credential server panicked")?;
        response
    }

    #[test]
    fn framed_fetch_is_binary_exact_and_raw_remains_unframed() {
        let payload = b"a\0b\xff";
        let mut framed = Vec::new();
        write_credential(&mut framed, payload, SocketProtocol::Framed).unwrap();
        assert_eq!(&framed[..FRAME_HEADER_BYTES], b"PMCR\0\0\0\x01\0\0\0\x04");
        assert_eq!(
            &*fetch_wire(&framed, SocketProtocol::Framed).unwrap(),
            payload
        );
        let mut raw = Vec::new();
        write_credential(&mut raw, payload, SocketProtocol::Raw).unwrap();
        assert_eq!(raw, payload);
        assert_eq!(&*fetch_wire(&raw, SocketProtocol::Raw).unwrap(), payload);
    }

    #[test]
    fn framed_payload_cap_does_not_include_its_header() {
        let payload = vec![0x5a; MAX_READ_BYTES as usize];
        let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
        write_credential(&mut frame, &payload, SocketProtocol::Framed).unwrap();
        let received = fetch_wire(&frame, SocketProtocol::Framed).unwrap();
        assert_eq!(&*received, &payload);
    }

    #[test]
    fn framed_fetch_rejects_incomplete_invalid_and_extra_data() {
        let frame = b"PMCR\0\0\0\x01\0\0\0\x03a\0b";
        for length in 0..FRAME_HEADER_BYTES {
            assert!(
                fetch_wire(&frame[..length], SocketProtocol::Framed)
                    .unwrap_err()
                    .contains("truncated credential frame header")
            );
        }
        for length in FRAME_HEADER_BYTES..frame.len() {
            assert!(
                fetch_wire(&frame[..length], SocketProtocol::Framed)
                    .unwrap_err()
                    .contains("truncated credential frame payload")
            );
        }
        let mut invalid = frame.to_vec();
        invalid[7] = 2;
        assert!(
            fetch_wire(&invalid, SocketProtocol::Framed)
                .unwrap_err()
                .contains("magic/version")
        );
        invalid = frame.to_vec();
        invalid.push(0);
        assert!(
            fetch_wire(&invalid, SocketProtocol::Framed)
                .unwrap_err()
                .contains("extra bytes")
        );
        for length in [0, MAX_READ_BYTES as u32 + 1, u32::MAX] {
            let mut header = frame[..FRAME_HEADER_BYTES].to_vec();
            header[FRAME_MAGIC.len()..].copy_from_slice(&length.to_be_bytes());
            assert!(
                fetch_wire(&header, SocketProtocol::Framed)
                    .unwrap_err()
                    .contains("1..=16 MiB")
            );
        }
    }

    #[test]
    fn framed_fetch_checks_server_uid_before_reading() {
        let dir = crate::test_util::temp_dir::TestDir::new("frame-uid");
        let sock = dir.join("credential.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = [0_u8; 1];
            assert_eq!(stream.read(&mut bytes).unwrap(), 0);
        });
        let start = Instant::now();
        let wrong_uid = rustix::process::geteuid().as_raw() ^ 1;
        let error =
            fetch_bytes_with_options(&sock, SocketProtocol::Framed, Some(wrong_uid)).unwrap_err();
        assert!(error.contains("does not match expected uid"), "{error}");
        assert!(start.elapsed() < IO_TIMEOUT);
        server.join().unwrap();
        assert!(
            fetch_bytes_with_options(&sock, SocketProtocol::Framed, None)
                .unwrap_err()
                .contains("requires an expected server uid")
        );
    }

    #[test]
    fn framed_fetch_uses_one_deadline_for_header_and_payload() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let writer = thread::spawn(move || {
            server.write_all(b"PMCR\0\0\0\x01\0\0\x01\0").unwrap();
            while server.write_all(b"x").is_ok() {
                thread::sleep(Duration::from_millis(10));
            }
        });
        let start = Instant::now();
        let error = read_fetch(
            &mut client,
            Path::new("/test.sock"),
            start + Duration::from_millis(100),
            SocketProtocol::Framed,
        )
        .unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        assert!(start.elapsed() < Duration::from_secs(2));
        drop(client);
        writer.join().unwrap();
    }

    #[test]
    fn fetch_deadline_rejects_a_slow_partial_response() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let writer = thread::spawn(move || {
            while server.write_all(b"x").is_ok() {
                thread::sleep(Duration::from_millis(10));
            }
        });
        let start = Instant::now();
        assert!(
            read_fetch(
                &mut client,
                Path::new("/test.sock"),
                start + Duration::from_millis(100),
                SocketProtocol::Raw,
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        drop(client);
        writer.join().unwrap();
    }

    #[test]
    fn regular_reads_reject_special_files_and_preserve_config_aliases() {
        let dir = crate::test_util::temp_dir::TestDir::new("regular-read");
        let fifo = dir.join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            read_regular_capped(&fifo, rustix::fs::OFlags::empty())
                .unwrap_err()
                .contains("not a regular file")
        );
        assert!(read_regular_capped(&dir, rustix::fs::OFlags::empty()).is_err());
        fs::write(dir.join("config"), b"{}").unwrap();
        std::os::unix::fs::symlink("config", dir.join("alias")).unwrap();
        assert_eq!(
            &*read_regular_capped(&dir.join("alias"), rustix::fs::OFlags::empty()).unwrap(),
            b"{}"
        );
        assert!(read_regular_capped(&dir.join("alias"), rustix::fs::OFlags::NOFOLLOW).is_err());
    }

    #[test]
    fn peer_user_is_never_an_id_option() {
        for name in ["", "-r", "--help"] {
            assert!(uid_of(name).unwrap_err().contains("expected a user name"));
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn inherited_fds_must_be_open_listening_stream_sockets() {
        use std::os::fd::AsRawFd as _;
        assert!(validate_inherited_socket(-1).is_err());
        let dir = crate::test_util::temp_dir::TestDir::new("inherited-socket");
        let file = fs::File::create(dir.join("regular")).unwrap();
        assert!(validate_inherited_socket(file.as_raw_fd()).is_err());
        let (stream, _peer) = UnixStream::pair().unwrap();
        assert!(validate_inherited_socket(stream.as_raw_fd()).is_err());
        let tcp = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        assert!(validate_inherited_socket(tcp.as_raw_fd()).is_err());
        let listener = UnixListener::bind(dir.join("listener.sock")).unwrap();
        validate_inherited_socket(listener.as_raw_fd()).unwrap();
    }

    #[test]
    fn socket_parent_walk_preserves_aliases_and_checks_ancestors() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = crate::test_util::temp_dir::TestDir::new("socket-walk");
        let parent = dir.join("parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&parent, dir.join("alias")).unwrap();
        let opened = open_socket_parent(&dir.join("alias/new/../nested"), None).unwrap();
        assert_eq!(
            rustix::fs::fstat(&opened).unwrap().st_ino,
            fs::metadata(parent.join("nested")).unwrap().ino()
        );
        assert!(open_socket_parent(&dir.join("alias"), None).is_err());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            open_socket_parent(&parent, None)
                .unwrap_err()
                .contains("untrusted replacement")
        );
        assert!(
            open_socket_parent(&parent.join("nested"), None)
                .unwrap_err()
                .contains("untrusted replacement")
        );
    }

    #[test]
    fn socket_bind_stays_in_its_pinned_directory_and_restores_cwd() {
        const CHILD: &str = "POSTMASTER_TEST_PINNED_SOCKET";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "server::tests::socket_bind_stays_in_its_pinned_directory_and_restores_cwd",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let dir = crate::test_util::temp_dir::TestDir::new("socket-pin");
        let parent = dir.join("parent");
        fs::create_dir(&parent).unwrap();
        let fd = open_socket_parent(&parent, None).unwrap();
        fs::rename(&parent, dir.join("pinned")).unwrap();
        fs::create_dir(dir.join("unrelated")).unwrap();
        std::os::unix::fs::symlink(dir.join("unrelated"), &parent).unwrap();
        let cwd = std::env::current_dir().unwrap();
        let listener = bind_in_directory(&fd, std::ffi::OsStr::new("cred.sock")).unwrap();
        assert_eq!(std::env::current_dir().unwrap(), cwd);
        assert!(dir.join("pinned/cred.sock").exists());
        assert!(!dir.join("unrelated/cred.sock").exists());
        assert!(bind_in_directory(&fd, std::ffi::OsStr::new("cred.sock")).is_err());
        assert_eq!(std::env::current_dir().unwrap(), cwd);
        drop(listener);
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn verify_id_candidate_rejects_untrusted_file() {
        // A user-owned, group/other-writable file must fail: non-root
        // runs trip the root-ownership check, root runs trip the
        // write-bits check — either way the file is refused.
        use std::os::unix::fs::PermissionsExt;
        let fixture = crate::test_util::temp_dir::TestDir::new("server");
        let path = fixture.join("fixture");
        fs::write(&path, b"fake id").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let p = path.to_str().unwrap().to_string();

        let err = verify_id_candidate(&p).unwrap_err();

        let _ = fs::remove_file(&path);
        if crate::test_util::root_has_trusted_owner() {
            assert!(
                err.contains("owned by uid") || err.contains("writable"),
                "{err}"
            );
        } else {
            assert_eq!(err, "/: directory path is owned by an untrusted user");
        }
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn verified_id_binary_uses_system_paths_or_fails_closed() {
        let paths = ["/usr/bin/id", "/bin/id", "/run/current-system/sw/bin/id"];
        let available = paths.iter().any(|p| Path::new(p).try_exists().unwrap());
        let result = verified_id_binary();
        if available && crate::test_util::root_has_trusted_owner() {
            assert!(result.unwrap().is_absolute());
        } else {
            let err = result.unwrap_err();
            assert!(err.starts_with("no trustworthy `id` binary found"), "{err}");
            assert!(err.contains("refusing PATH resolution"), "{err}");
            for path in paths {
                assert!(err.contains(path), "{err}");
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn id_lookup_accepts_trusted_nix_style_aliases() {
        use std::os::unix::fs::PermissionsExt as _;
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let dir = crate::test_util::temp_dir::TestDir::new("id-alias");
        let target = dir.join("store/bin");
        fs::create_dir_all(&target).unwrap();
        fs::copy(verified_id_binary().unwrap(), target.join("id")).unwrap();
        fs::set_permissions(target.join("id"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(dir.join("current-system")).unwrap();
        std::os::unix::fs::symlink(dir.join("store"), dir.join("current-system/sw")).unwrap();
        std::os::unix::fs::symlink("id", target.join("id-link")).unwrap();
        let alias = dir.join("current-system/sw/bin/id-link");
        let verified = verify_id_candidate(alias.to_str().unwrap()).unwrap();
        assert_eq!(verified, target.join("id"));
        fs::remove_file(target.join("id-link")).unwrap();
        let out = std::process::Command::new(&verified)
            .arg("-u")
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"0\n");
        fs::set_permissions(&verified, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            verify_id_candidate(verified.to_str().unwrap())
                .unwrap_err()
                .contains("writable")
        );
    }

    #[test]
    fn preflight_rejects_empty_resolved_value() {
        // Zero bytes means refusal on the wire, so an empty value must fail at startup,
        // not at first fetch.
        let dir = crate::test_util::temp_dir::TestDir::new("server");
        let env_file = dir.join(".env");
        fs::write(&env_file, "KEY=\n").unwrap();
        let mut credentials = std::collections::HashMap::new();
        credentials.insert(
            PathBuf::from("/run/postmaster-credd/svc/KEY.sock"),
            Entry {
                env_file,
                key: "KEY".to_string(),
                env_file_sha256: vec![{
                    use sha2::Digest as _;
                    sha2::Sha256::digest(b"KEY=\n").into()
                }],
                peer_user: None,
                protocol: SocketProtocol::Raw,
            },
        );
        let cfg = Config {
            keys: KeysSource::File(dir.join(".env.keys")),
            credentials,
        };
        let ring = KeyRing::from_pairs(
            [(
                "DOTENV_PRIVATE_KEY".to_string(),
                Zeroizing::new("11".repeat(32)),
            )],
            &[KeyNaming::Env],
        )
        .unwrap();
        let err = preflight_credentials(&cfg, &ring).unwrap_err();
        assert!(err.contains("empty value"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_absolute_paths_rejects_relative() {
        // Socket and keys paths must be absolute.
        let mut credentials = std::collections::HashMap::new();
        credentials.insert(
            PathBuf::from("relative/key.sock"),
            Entry {
                env_file: PathBuf::from("/x/.env"),
                key: "K".to_string(),
                env_file_sha256: Vec::new(),
                peer_user: None,
                protocol: SocketProtocol::Raw,
            },
        );
        let cfg = Config {
            keys: KeysSource::File(PathBuf::from("/abs/.env.keys")),
            credentials,
        };
        let err = validate_absolute_paths(&cfg).unwrap_err();
        assert!(err.contains("absolute"), "{err}");

        // The keys-file leg: a relative keys path is caught too.
        let cfg2 = Config {
            keys: KeysSource::File(PathBuf::from("rel/.env.keys")),
            credentials: std::collections::HashMap::new(),
        };
        let err = validate_absolute_paths(&cfg2).unwrap_err();
        assert!(err.contains("absolute"), "{err}");
    }

    #[test]
    fn read_capped_passes_at_cap_and_fails_over_cap() {
        // Accept the exact cap; reject excess bytes rather than serving a truncated secret.
        let at_cap = std::io::repeat(0x41).take(MAX_READ_BYTES);
        let got = read_capped(at_cap, Path::new("/test")).unwrap();
        assert_eq!(got.len() as u64, MAX_READ_BYTES);
        assert!(got.iter().all(|b| *b == 0x41));

        let over_cap = std::io::repeat(0x41).take(MAX_READ_BYTES + 1);
        let err = read_capped(over_cap, Path::new("/test")).unwrap_err();
        assert!(err.contains("size cap"), "{err}");
    }

    #[test]
    fn socket_domains_are_checked_before_mutation_including_aliases() {
        let dir = crate::test_util::temp_dir::TestDir::new("socket-domains");
        let parent = dir.join("sockets");
        fs::create_dir(&parent).unwrap();
        std::os::unix::fs::symlink(&parent, dir.join("alias")).unwrap();
        fs::create_dir_all(dir.join("outside/sub")).unwrap();
        std::os::unix::fs::symlink(dir.join("outside"), parent.join("escape")).unwrap();
        for second in [
            parent.join("B.sock"),
            parent.join("nested/B.sock"),
            dir.join("alias/B.sock"),
            parent.join("unused/../B.sock"),
            parent.join("escape/sub/B.sock"),
        ] {
            let first = parent.join("A.sock");
            let cfg = Config {
                keys: KeysSource::File(dir.join(".env.keys")),
                credentials: [first.clone(), second.clone()]
                    .into_iter()
                    .map(|p| {
                        (
                            p,
                            Entry {
                                env_file: dir.join(".env"),
                                key: "KEY".into(),
                                env_file_sha256: Vec::new(),
                                peer_user: None,
                                protocol: SocketProtocol::Raw,
                            },
                        )
                    })
                    .collect(),
            };
            let mut peers = [(first.clone(), Some(1001)), (second.clone(), Some(1002))]
                .into_iter()
                .collect();
            assert!(
                validate_socket_domains(&cfg, &peers, 0)
                    .unwrap_err()
                    .contains("conflicting ownership")
            );
            assert_eq!(fs::read_dir(&parent).unwrap().count(), 1);
            peers.insert(second.clone(), Some(1001));
            validate_socket_domains(&cfg, &peers, 0).unwrap();
            peers.insert(first.clone(), None);
            peers.insert(second, Some(0));
            validate_socket_domains(&cfg, &peers, 0).unwrap();
        }
    }
}
