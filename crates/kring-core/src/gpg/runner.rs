//! Runs the `gpg` binary with captured output, a timeout and passphrases over a pipe.
//!
//! Every invocation gets `--batch --no-tty --pinentry-mode loopback --status-fd 4`, so
//! no pinentry window ever appears. A passphrase is written to a dedicated pipe that
//! the child sees as fd 3 (`--passphrase-fd 3`); it never appears in argv or the
//! environment. stdout, stderr and the status lines are each capped at
//! [`MAX_OUTPUT`]; the child is killed when it runs past its timeout.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::{KringError, Result};
use crate::model::SecretValue;

/// Timeout for listing, import and export.
pub const TIMEOUT_DEFAULT: Duration = Duration::from_secs(30);

/// Timeout for key generation.
pub const TIMEOUT_KEYGEN: Duration = Duration::from_secs(120);

/// Maximum bytes captured from each of stdout, stderr and the status fd.
pub const MAX_OUTPUT: usize = 16 * 1024 * 1024;

/// Error message when no `gpg` binary is found in `PATH`.
pub const MSG_GPG_NOT_FOUND: &str = "GnuPG (gpg) was not found in PATH: install GnuPG";

/// Error message for a passphrase gpg cannot read as one line.
pub const MSG_PASSPHRASE_NEWLINE: &str = "The passphrase must not contain a line break";

/// File descriptor number the child reads the passphrase from.
const PASSPHRASE_FD: RawFd = 3;

/// File descriptor number the child writes status lines to.
const STATUS_FD: RawFd = 4;

/// Lowest fd used to park pipe ends in the child before moving them to 3 and 4.
const PARK_FD_MIN: RawFd = 10;

/// Longest single wait in the poll loop, so child exit is noticed promptly.
const POLL_SLICE: Duration = Duration::from_millis(100);

/// Read buffer size of the poll loop.
const READ_CHUNK: usize = 64 * 1024;

/// Replacement for passphrase bytes found in stderr or status output.
const REDACTED: &[u8] = b"<redacted>";

/// Prefix of a GnuPG status line.
const STATUS_PREFIX: &str = "[GNUPG:] ";

/// Captured result of one `gpg` invocation.
#[derive(Debug)]
pub struct GpgOutput {
    /// Exit status of the child.
    pub status: ExitStatus,
    /// Everything written to stdout.
    pub stdout: Vec<u8>,
    /// Everything written to stderr (passphrase bytes redacted).
    pub stderr: Vec<u8>,
    /// Everything written to the status fd (passphrase bytes redacted).
    pub status_lines: Vec<u8>,
}

impl GpgOutput {
    /// True when gpg exited with status 0.
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// True when a status line with `keyword` (e.g. `BAD_PASSPHRASE`) was written.
    pub fn has_status(&self, keyword: &str) -> bool {
        String::from_utf8_lossy(&self.status_lines)
            .lines()
            .filter_map(|l| l.strip_prefix(STATUS_PREFIX))
            .any(|l| l.split(' ').next() == Some(keyword))
    }

    /// stderr as trimmed text (lossy UTF-8).
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

/// Location of the `gpg` binary and the GnuPG home directory to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpgRunner {
    /// Absolute path of the `gpg` binary.
    gpg: PathBuf,
    /// Home directory (`--homedir` and `GNUPGHOME`); `None` uses gpg's default.
    homedir: Option<PathBuf>,
}

impl GpgRunner {
    /// Finds `gpg` in `PATH` (absolute entries only) with gpg's default home directory.
    pub fn locate() -> Result<Self> {
        Self::locate_in(std::env::var_os("PATH").as_deref())
    }

    /// Finds `gpg` in the given `PATH` value; relative entries are skipped.
    pub fn locate_in(path_var: Option<&OsStr>) -> Result<Self> {
        let not_found = || KringError::NotFound(MSG_GPG_NOT_FOUND.into());
        let path_var = path_var.ok_or_else(not_found)?;
        std::env::split_paths(path_var)
            .filter(|dir| dir.is_absolute())
            .map(|dir| dir.join("gpg"))
            .find(|candidate| is_executable(candidate))
            .map(|gpg| Self { gpg, homedir: None })
            .ok_or_else(not_found)
    }

    /// Uses an explicit, absolute `gpg` binary.
    pub fn new(gpg: PathBuf) -> Result<Self> {
        if !gpg.is_absolute() {
            return Err(KringError::InvalidInput(format!(
                "gpg path {} is not absolute",
                gpg.display()
            )));
        }
        Ok(Self { gpg, homedir: None })
    }

    /// Returns the runner using `dir` as GnuPG home (`--homedir` and `GNUPGHOME`).
    pub fn with_homedir(mut self, dir: PathBuf) -> Self {
        self.homedir = Some(dir);
        self
    }

    /// Path of the `gpg` binary.
    pub fn gpg(&self) -> &Path {
        &self.gpg
    }

    /// Explicit home directory, if any.
    pub fn homedir(&self) -> Option<&Path> {
        self.homedir.as_deref()
    }

    /// Runs gpg with `args` after the fixed options, feeding `stdin` and `passphrase`.
    ///
    /// Returns the captured output whatever the exit status; errors only when gpg
    /// cannot be started, runs past `timeout` (it is killed), or writes more than
    /// [`MAX_OUTPUT`] to one stream.
    pub fn run<I, S>(
        &self,
        args: I,
        stdin: Option<&[u8]>,
        passphrase: Option<&SecretValue>,
        timeout: Duration,
    ) -> Result<GpgOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        if passphrase.is_some_and(|p| p.as_bytes().contains(&b'\n')) {
            return Err(KringError::InvalidInput(MSG_PASSPHRASE_NEWLINE.into()));
        }
        let mut cmd = Command::new(&self.gpg);
        cmd.args(self.fixed_args(passphrase.is_some()))
            .args(args)
            .env_remove("GPG_AGENT_INFO")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = &self.homedir {
            cmd.env("GNUPGHOME", dir);
        }

        let (status_read, status_write) = pipe_cloexec().map_err(|e| self.error("pipe", e))?;
        let pass_pipe = match passphrase {
            Some(_) => Some(pipe_cloexec().map_err(|e| self.error("pipe", e))?),
            None => None,
        };
        let child_status = status_write.as_raw_fd();
        let child_pass = pass_pipe.as_ref().map(|(read, _)| read.as_raw_fd());
        // SAFETY: the closure only calls async-signal-safe libc functions (fcntl, dup2, close).
        unsafe {
            cmd.pre_exec(move || install_child_fds(child_pass, child_status));
        }
        let mut child = cmd.spawn().map_err(|e| self.error("start", e))?;
        // The child holds its own copies now; the parent keeps only its ends.
        drop(status_write);
        let pass_write = pass_pipe.map(|(_, write)| write);

        let mut line = Zeroizing::new(Vec::new());
        if let Some(p) = passphrase {
            line.extend_from_slice(p.as_bytes());
            line.push(b'\n');
        }
        let streams = Streams {
            stdout: child.stdout.take().map(OwnedFd::from),
            stderr: child.stderr.take().map(OwnedFd::from),
            status: Some(status_read),
            stdin: child.stdin.take().map(OwnedFd::from),
            passphrase: pass_write,
        };
        let deadline = Instant::now() + timeout;
        let captured = match pump(
            streams,
            stdin.unwrap_or_default(),
            &line,
            &mut child,
            deadline,
        ) {
            Ok(captured) => captured,
            Err(e) => {
                kill(&mut child);
                return Err(e);
            }
        };
        let status = wait_until(&mut child, deadline)?;
        let mut output = GpgOutput {
            status,
            stdout: captured.stdout,
            stderr: captured.stderr,
            status_lines: captured.status,
        };
        if let Some(p) = passphrase {
            redact(&mut output.stderr, p.as_bytes());
            redact(&mut output.status_lines, p.as_bytes());
        }
        Ok(output)
    }

    /// Options passed before the caller's arguments.
    fn fixed_args(&self, with_passphrase: bool) -> Vec<OsString> {
        let mut args: Vec<OsString> = Vec::new();
        if let Some(dir) = &self.homedir {
            args.push("--homedir".into());
            args.push(dir.into());
        }
        for arg in ["--batch", "--no-tty", "--pinentry-mode", "loopback"] {
            args.push(arg.into());
        }
        args.push("--status-fd".into());
        args.push(STATUS_FD.to_string().into());
        if with_passphrase {
            args.push("--passphrase-fd".into());
            args.push(PASSPHRASE_FD.to_string().into());
        }
        args
    }

    /// Builds a [`KringError::Gpg`] for a failed system call while running gpg.
    fn error(&self, what: &str, e: io::Error) -> KringError {
        KringError::Gpg(format!("cannot {what} {}: {e}", self.gpg.display()))
    }
}

/// True when `path` is a regular file with an execute bit.
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Creates a pipe whose both ends are close-on-exec.
fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds: [libc::c_int; 2] = [-1; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 writes.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 succeeded, so both fds are open and owned by nobody else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// In the forked child: moves the passphrase pipe to fd 3 and the status pipe to fd 4.
///
/// Both are first parked above [`PARK_FD_MIN`] so a source already numbered 3 or 4
/// is not clobbered; `dup2` clears close-on-exec on the targets only.
fn install_child_fds(passphrase: Option<RawFd>, status: RawFd) -> io::Result<()> {
    /// Fails with the current errno when `ret` is negative.
    fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ret)
    }
    // SAFETY: fcntl, dup2 and close are async-signal-safe and act on fds we own.
    unsafe {
        let parked_status = check(libc::fcntl(status, libc::F_DUPFD_CLOEXEC, PARK_FD_MIN))?;
        let parked_pass = match passphrase {
            Some(fd) => Some(check(libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, PARK_FD_MIN))?),
            None => None,
        };
        check(libc::dup2(parked_status, STATUS_FD))?;
        libc::close(parked_status);
        match parked_pass {
            Some(fd) => {
                check(libc::dup2(fd, PASSPHRASE_FD))?;
                libc::close(fd);
            }
            // Nothing may be readable as fd 3 without a passphrase.
            None => {
                libc::close(PASSPHRASE_FD);
            }
        }
    }
    Ok(())
}

/// Parent ends of the child's pipes.
struct Streams {
    /// Child stdout (read).
    stdout: Option<OwnedFd>,
    /// Child stderr (read).
    stderr: Option<OwnedFd>,
    /// Status fd (read).
    status: Option<OwnedFd>,
    /// Child stdin (write).
    stdin: Option<OwnedFd>,
    /// Passphrase pipe (write).
    passphrase: Option<OwnedFd>,
}

/// Bytes read from the child.
#[derive(Default)]
struct Captured {
    /// From stdout.
    stdout: Vec<u8>,
    /// From stderr.
    stderr: Vec<u8>,
    /// From the status fd.
    status: Vec<u8>,
}

/// A pipe end being read into a buffer.
struct Reader<'a> {
    /// Open fd, `None` after EOF.
    fd: Option<OwnedFd>,
    /// Destination buffer.
    buf: &'a mut Vec<u8>,
}

/// A pipe end being written from a buffer.
struct Writer<'a> {
    /// Open fd, `None` once everything is written or the reader went away.
    fd: Option<OwnedFd>,
    /// Bytes to write.
    data: &'a [u8],
    /// Bytes already written.
    written: usize,
}

/// Moves data between the parent and the child until all pipes close or the child exits.
///
/// Fails at `deadline` or when a stream exceeds [`MAX_OUTPUT`]; the caller kills the child.
fn pump(
    streams: Streams,
    stdin: &[u8],
    passphrase: &[u8],
    child: &mut Child,
    deadline: Instant,
) -> Result<Captured> {
    let mut captured = Captured::default();
    let mut readers = [
        Reader {
            fd: streams.stdout,
            buf: &mut captured.stdout,
        },
        Reader {
            fd: streams.stderr,
            buf: &mut captured.stderr,
        },
        Reader {
            fd: streams.status,
            buf: &mut captured.status,
        },
    ];
    let mut writers = [
        Writer {
            fd: streams.stdin,
            data: stdin,
            written: 0,
        },
        Writer {
            fd: streams.passphrase,
            data: passphrase,
            written: 0,
        },
    ];
    for fd in readers.iter().filter_map(|r| r.fd.as_ref()) {
        set_nonblocking(fd.as_raw_fd())?;
    }
    for fd in writers.iter().filter_map(|w| w.fd.as_ref()) {
        set_nonblocking(fd.as_raw_fd())?;
    }
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        let mut polls: Vec<libc::pollfd> = Vec::new();
        for r in &readers {
            if let Some(fd) = &r.fd {
                polls.push(pollfd(fd.as_raw_fd(), libc::POLLIN));
            }
        }
        for w in &writers {
            if let Some(fd) = &w.fd {
                polls.push(pollfd(fd.as_raw_fd(), libc::POLLOUT));
            }
        }
        if polls.is_empty() {
            return Ok(captured);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(timed_out());
        }
        let wait = (deadline - now).min(POLL_SLICE);
        // SAFETY: `polls` is a valid array of `polls.len()` pollfd structs.
        let ready = unsafe {
            libc::poll(
                polls.as_mut_ptr(),
                polls.len() as libc::nfds_t,
                wait.as_millis() as libc::c_int,
            )
        };
        if ready < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(KringError::Gpg(format!("poll failed: {e}")));
        }
        if ready == 0 {
            // A child that exited while a grandchild (gpg-agent) keeps a pipe open is done.
            if child.try_wait().ok().flatten().is_some() {
                return Ok(captured);
            }
            continue;
        }
        for r in readers.iter_mut() {
            read_ready(r, &polls, &mut chunk)?;
        }
        for w in writers.iter_mut() {
            write_ready(w, &polls);
        }
    }
}

/// A pollfd for `fd` waiting for `events`.
fn pollfd(fd: RawFd, events: libc::c_short) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

/// True when poll reported activity (data, hangup or error) for `fd`.
fn is_ready(polls: &[libc::pollfd], fd: RawFd) -> bool {
    polls.iter().any(|p| p.fd == fd && p.revents != 0)
}

/// Reads what is available on a ready reader; closes it on EOF or error.
fn read_ready(r: &mut Reader<'_>, polls: &[libc::pollfd], chunk: &mut [u8]) -> Result<()> {
    let Some(fd) = &r.fd else { return Ok(()) };
    if !is_ready(polls, fd.as_raw_fd()) {
        return Ok(());
    }
    // SAFETY: `chunk` is valid for `chunk.len()` bytes of writes.
    let n = unsafe { libc::read(fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
    if n < 0 {
        let e = io::Error::last_os_error();
        if matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            return Ok(());
        }
        r.fd = None;
        return Ok(());
    }
    if n == 0 {
        r.fd = None;
        return Ok(());
    }
    if r.buf.len() + n as usize > MAX_OUTPUT {
        return Err(KringError::Gpg(format!(
            "output exceeds {} MiB, gpg was stopped",
            MAX_OUTPUT / (1024 * 1024)
        )));
    }
    r.buf.extend_from_slice(&chunk[..n as usize]);
    Ok(())
}

/// Writes the next part of a ready writer; closes it when done or when the reader is gone.
fn write_ready(w: &mut Writer<'_>, polls: &[libc::pollfd]) {
    let Some(fd) = &w.fd else { return };
    if w.written >= w.data.len() {
        w.fd = None;
        return;
    }
    if !is_ready(polls, fd.as_raw_fd()) {
        return;
    }
    let rest = &w.data[w.written..];
    // SAFETY: `rest` is valid for `rest.len()` bytes of reads.
    let n = unsafe { libc::write(fd.as_raw_fd(), rest.as_ptr().cast(), rest.len()) };
    if n < 0 {
        let e = io::Error::last_os_error();
        if matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            return;
        }
        // EPIPE and similar: gpg stopped reading; its exit status tells why.
        w.fd = None;
        return;
    }
    w.written += n as usize;
    if w.written >= w.data.len() {
        w.fd = None;
    }
}

/// Sets O_NONBLOCK on a parent pipe end.
fn set_nonblocking(fd: RawFd) -> Result<()> {
    // SAFETY: fcntl on an fd we own.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: as above.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        let e = io::Error::last_os_error();
        return Err(KringError::Gpg(format!("cannot configure pipe: {e}")));
    }
    Ok(())
}

/// Waits for the child to exit, killing it at `deadline`.
fn wait_until(child: &mut Child, deadline: Instant) -> Result<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(e) => {
                kill(child);
                return Err(KringError::Gpg(format!("cannot wait for gpg: {e}")));
            }
        }
        if Instant::now() >= deadline {
            kill(child);
            return Err(timed_out());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Kills and reaps the child, ignoring errors (it may already be gone).
fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// The error for a gpg run past its timeout.
fn timed_out() -> KringError {
    KringError::Gpg("gpg did not finish in time and was stopped".into())
}

/// Replaces every occurrence of `secret` in `buf` with [`REDACTED`].
fn redact(buf: &mut Vec<u8>, secret: &[u8]) {
    if secret.is_empty() || buf.len() < secret.len() {
        return;
    }
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        if buf[i..].starts_with(secret) {
            out.extend_from_slice(REDACTED);
            i += secret.len();
            continue;
        }
        out.push(buf[i]);
        i += 1;
    }
    *buf = out;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// Fake gpg: prints its args, GNUPGHOME and GPG_AGENT_INFO, echoes stdin,
    /// reads fd 3 when open and reports its length on fd 4.
    const FAKE_ECHO: &str = r#"#!/bin/sh
printf 'ARGS %s\n' "$*"
printf 'HOME %s\n' "${GNUPGHOME-unset}"
printf 'AGENT %s\n' "${GPG_AGENT_INFO-unset}"
if { true <&3; } 2>/dev/null; then
  IFS= read -r pw <&3
  printf '[GNUPG:] GOT_PASSPHRASE %s\n' "${#pw}" >&4
else
  printf '[GNUPG:] NO_PASSPHRASE_FD\n' >&4
fi
cat
"#;

    /// Fake gpg that writes the passphrase it read to stderr and the status fd.
    const FAKE_LEAK: &str =
        "#!/bin/sh\nIFS= read -r pw <&3\necho \"bad $pw here\" >&2\necho \"[GNUPG:] X $pw\" >&4\n";

    /// Fake gpg that never finishes.
    const FAKE_SLEEP: &str = "#!/bin/sh\nexec sleep 30\n";

    /// Fake gpg that writes more than the cap.
    const FAKE_FLOOD: &str = "#!/bin/sh\nexec head -c 17000000 /dev/zero\n";

    /// Fake gpg that exits 2 without reading its stdin.
    const FAKE_FAIL: &str = "#!/bin/sh\necho 'gpg: no such key' >&2\nexit 2\n";

    /// Directory with all fake scripts, written once before any of them runs
    /// (writing an executable while another thread forks can fail with ETXTBSY).
    fn fakes() -> &'static Path {
        static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            for (name, body) in [
                ("echo", FAKE_ECHO),
                ("leak", FAKE_LEAK),
                ("sleep", FAKE_SLEEP),
                ("flood", FAKE_FLOOD),
                ("fail", FAKE_FAIL),
            ] {
                let path = dir.path().join(name);
                std::fs::write(&path, body).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            dir
        })
        .path()
    }

    /// A runner for the fake script `name`.
    fn fake(name: &str) -> GpgRunner {
        GpgRunner::new(fakes().join(name)).unwrap()
    }

    /// Passphrase over fd 3, status over fd 4, stdin piped, argv and env as specified.
    #[test]
    fn passphrase_and_status_travel_over_pipes() {
        let runner = fake("echo").with_homedir(PathBuf::from("/tmp/kring-home"));
        let pw = SecretValue::from_text("s3cret pass");
        let out = runner
            .run(
                ["--list-keys", "x"],
                Some(b"hello stdin"),
                Some(&pw),
                TIMEOUT_DEFAULT,
            )
            .unwrap();
        assert!(out.success());
        let stdout = String::from_utf8(out.stdout.clone()).unwrap();
        assert!(stdout.contains(
            "ARGS --homedir /tmp/kring-home --batch --no-tty --pinentry-mode loopback \
             --status-fd 4 --passphrase-fd 3 --list-keys x\n"
        ));
        assert!(stdout.contains("HOME /tmp/kring-home\n"));
        assert!(stdout.contains("AGENT unset\n"));
        assert!(stdout.ends_with("hello stdin"));
        assert!(!stdout.contains("s3cret"));
        assert_eq!(out.status_lines, b"[GNUPG:] GOT_PASSPHRASE 11\n");
        assert!(out.has_status("GOT_PASSPHRASE"));
        assert!(!out.has_status("GOT"));
    }

    /// Without a passphrase fd 3 is closed and no `--passphrase-fd` is passed.
    #[test]
    fn no_passphrase_means_no_fd_3() {
        let out = fake("echo")
            .run(["--list-keys"], None, None, TIMEOUT_DEFAULT)
            .unwrap();
        let stdout = String::from_utf8(out.stdout.clone()).unwrap();
        assert!(!stdout.contains("--passphrase-fd"));
        assert!(!stdout.contains("--homedir"));
        assert!(out.has_status("NO_PASSPHRASE_FD"));
    }

    /// Passphrase bytes echoed by gpg are redacted from stderr and status lines.
    #[test]
    fn passphrase_is_redacted() {
        let pw = SecretValue::from_text("hunter2");
        let out = fake("leak")
            .run(Vec::<&str>::new(), None, Some(&pw), TIMEOUT_DEFAULT)
            .unwrap();
        assert_eq!(out.stderr_text(), "bad <redacted> here");
        assert_eq!(out.status_lines, b"[GNUPG:] X <redacted>\n");
    }

    /// A passphrase with a line break is refused before gpg starts.
    #[test]
    fn newline_in_passphrase_is_refused() {
        let pw = SecretValue::from_text("a\nb");
        let r = fake("echo").run(["x"], None, Some(&pw), TIMEOUT_DEFAULT);
        assert!(matches!(r, Err(KringError::InvalidInput(m)) if m == MSG_PASSPHRASE_NEWLINE));
    }

    /// A child running past its timeout is killed and reported.
    #[test]
    fn timeout_kills_the_child() {
        let started = Instant::now();
        let r = fake("sleep").run(["x"], None, None, Duration::from_millis(300));
        assert!(matches!(r, Err(KringError::Gpg(m)) if m.contains("in time")));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// Output beyond the cap is an error.
    #[test]
    fn output_is_capped() {
        let r = fake("flood").run(["x"], None, None, TIMEOUT_DEFAULT);
        assert!(matches!(r, Err(KringError::Gpg(m)) if m.contains("16 MiB")));
    }

    /// A failing gpg that ignores stdin returns its status and stderr, not an error.
    #[test]
    fn failure_is_returned_as_output() {
        let big = vec![b'x'; 1024 * 1024];
        let out = fake("fail")
            .run(["x"], Some(&big), None, TIMEOUT_DEFAULT)
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(out.stderr_text(), "gpg: no such key");
    }

    /// A missing binary is a start error.
    #[test]
    fn missing_binary_is_an_error() {
        let r =
            GpgRunner::new(fakes().join("absent"))
                .unwrap()
                .run(["x"], None, None, TIMEOUT_DEFAULT);
        assert!(matches!(r, Err(KringError::Gpg(m)) if m.contains("cannot start")));
    }

    /// PATH lookup takes the first absolute dir with an executable `gpg`.
    #[test]
    fn locate_in_path() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        let exec = dir.path().join("exec");
        std::fs::create_dir_all(&plain).unwrap();
        std::fs::create_dir_all(&exec).unwrap();
        std::fs::write(plain.join("gpg"), "").unwrap();
        std::fs::write(exec.join("gpg"), "").unwrap();
        std::fs::set_permissions(exec.join("gpg"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path =
            std::env::join_paths(["relative", plain.to_str().unwrap(), exec.to_str().unwrap()])
                .unwrap();
        let runner = GpgRunner::locate_in(Some(&path)).unwrap();
        assert_eq!(runner.gpg(), exec.join("gpg"));
        assert_eq!(runner.homedir(), None);

        let missing = GpgRunner::locate_in(Some(OsStr::new("relative:/nonexistent-kring")));
        assert!(matches!(missing, Err(KringError::NotFound(m)) if m == MSG_GPG_NOT_FOUND));
        assert!(GpgRunner::locate_in(None).is_err());
        assert!(GpgRunner::new(PathBuf::from("gpg")).is_err());
    }

    /// Redaction replaces every occurrence and leaves other bytes alone.
    #[test]
    fn redact_cases() {
        let mut buf = b"pw x pw".to_vec();
        redact(&mut buf, b"pw");
        assert_eq!(buf, b"<redacted> x <redacted>");
        let mut short = b"p".to_vec();
        redact(&mut short, b"pw");
        assert_eq!(short, b"p");
    }
}
