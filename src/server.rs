//! Serving logic, platform hardening, listener acquisition, and the fetch client.
//!
//! This module contains the bulk of the runtime behavior while keeping
//! main.rs thin.

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

/// Maximum bytes accepted for a credential fetch payload, bundle JSON, or config
/// read. These payloads are small; the cap keeps a hostile or broken
/// peer from forcing unbounded heap allocation. Oversized payloads fail.
const MAX_READ_BYTES: u64 = 16 * 1024 * 1024;

/// Read `reader` to EOF with a hard size cap.
/// Fails rather than truncates when the stream exceeds the cap — a
/// truncated secret must never be served as if complete.
pub(crate) fn read_capped<R: Read>(reader: R, path: &Path) -> Result<Vec<u8>, String> {
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
    Ok(std::mem::take(&mut *buf))
}

/// Connect, read one credential to EOF (hard-capped by `read_capped`).
/// Zero bytes means the server refused to serve — fail closed, exactly
/// like LoadCredential failing.
pub fn fetch_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let stream =
        UnixStream::connect(path).map_err(|e| format!("{}: connect: {e}", path.display()))?;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let buf = Zeroizing::new(read_capped(stream, path)?);
    if buf.is_empty() {
        return Err(format!(
            "{}: server sent zero bytes (refused to serve); failing closed",
            path.display()
        ));
    }
    Ok(buf)
}

/// Connect to a local credential socket, read to EOF, and write to stdout.
/// Available on Linux and macOS. Zero bytes means
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
        .args(["-u", name])
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

/// Bind and listen on all configured credential sockets. Returns
/// a vector of `(UnixListener, path)` pairs ready for serving (the entry
/// is re-looked-up by the caller).
/// Call during single-threaded startup: bind mode temporarily changes umask.
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
            if let Some(parent) = path.parent() {
                // Refuse a symlinked socket parent unconditionally in bind mode:
                // create_dir_all, remove_file, and bind all follow a swapped parent,
                // and the O_NOFOLLOW fd discipline below only runs when privileged with
                // a configured peer_user.
                match fs::symlink_metadata(parent) {
                    Ok(md) if md.file_type().is_symlink() => {
                        return Err(format!(
                            "{}: socket parent is a symlink; refusing to follow",
                            parent.display()
                        ));
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(format!(
                            "{}: cannot stat socket parent: {e}",
                            parent.display()
                        ));
                    }
                }
                fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
                // The parent directory is the filesystem half of the ACL:
                // owned by the consumer's user, execute-only-for-owner, so
                // only that user (and root) can even reach the socket. Only
                // meaningful when we run privileged; dev runs skip it.
                if am_root && let Some(uid) = expected {
                    // Open the directory and operate on the fd throughout: O_NOFOLLOW
                    // rejects a symlink at the final component, and fchown/fchmod on
                    // the fd act on the pinned inode, immune to path swaps.
                    let dir_fd = rustix::fs::open(
                        parent,
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(|e| {
                        format!(
                            "{}: open dir: {e} (refusing to follow a symlink)",
                            parent.display()
                        )
                    })?;
                    rustix::fs::fchown(&dir_fd, Some(rustix::fs::Uid::from_raw(uid)), None)
                        .map_err(|e| format!("{}: fchown: {e}", parent.display()))?;
                    rustix::fs::fchmod(&dir_fd, rustix::fs::Mode::from_bits_truncate(0o500))
                        .map_err(|e| format!("{}: fchmod: {e}", parent.display()))?;
                }
            }
            let _ = fs::remove_file(path);
            // connect(2) needs write on the socket inode; the reachability
            // gate is the 0500 parent dir plus the peer-credential check.
            let mode = if expected.is_some() { 0o666 } else { 0o600 };
            // fchmod on Linux changes the sockfs inode, not the pathname;
            // Darwin rejects it. Bind with the final mode to avoid a chmod race.
            let l = {
                let _umask_guard =
                    UmaskGuard::around_bind(rustix::fs::Mode::from_bits_truncate(mode));
                UnixListener::bind(path).map_err(|e| format!("{}: bind: {e}", path.display()))?
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
        let fds = sd_listen_fds();
        if fds.is_empty() {
            return Err("no sockets inherited from systemd (and --bind not given); \
             start via postmaster-credd.socket"
                .into());
        }
        let mut seen: Vec<PathBuf> = Vec::new();
        let mut out = Vec::new();
        for fd in fds {
            // SAFETY: sd_listen_fds() proved
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
    let file =
        fs::File::open(&args.config).map_err(|e| format!("{}: {e}", args.config.display()))?;
    let raw = read_capped(file, &args.config)?;
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
        assert!(
            err.contains("owned by uid") || err.contains("writable"),
            "{err}"
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn verified_id_binary_finds_a_system_id() {
        // On any Linux host at least one candidate must verify — glibc
        // systems have /usr/bin/id or /bin/id, NixOS has
        // /run/current-system/sw/bin/id.
        let id = verified_id_binary().unwrap();
        assert!(id.is_absolute());
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
