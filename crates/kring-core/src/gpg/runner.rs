//! Runs the `gpg` binary with captured output, a timeout and passphrases over a pipe.
//!
//! Every invocation gets `--batch --no-tty --pinentry-mode loopback --status-fd 4`, so
//! no pinentry window ever appears. A passphrase is written to a dedicated pipe that
//! the child sees as fd 3 (`--passphrase-fd 3`); it never appears in argv or the
//! environment. [`GpgRunner::run_interactive`] instead answers gpg's prompts over
//! `--command-fd 0` while it runs. stdout, stderr and the status lines are each
//! capped at [`MAX_OUTPUT`]; the child is killed when it runs past its timeout.
//!
//! Captured bytes live in zeroizing buffers that are moved to a larger zeroizing
//! buffer before they would reallocate, so no stale copy is left on the heap. What
//! remains outside kring's control: the kernel pipe buffers and gpg's own memory.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

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

/// Name of the agent client binary, looked up next to `gpg`.
pub const GPG_CONNECT_AGENT: &str = "gpg-connect-agent";

/// File descriptor number the child reads the passphrase from.
const PASSPHRASE_FD: RawFd = 3;

/// File descriptor number the child writes status lines to.
const STATUS_FD: RawFd = 4;

/// File descriptor number gpg reads prompt answers from in interactive mode (stdin).
const COMMAND_FD: RawFd = 0;

/// Lowest fd used to park pipe ends in the child before moving them to 3 and 4.
const PARK_FD_MIN: RawFd = 10;

/// Longest single wait in the poll loop, so child exit is noticed promptly.
const POLL_SLICE: Duration = Duration::from_millis(100);

/// Read buffer size of the poll loop.
const READ_CHUNK: usize = 64 * 1024;

/// Replacement for passphrase bytes found in stderr or status output.
const REDACTED: &[u8] = b"<redacted>";

/// Secrets shorter than this are not redacted (it would mangle unrelated text and
/// reveal the secret by the pattern of replacements).
const MIN_REDACT_LEN: usize = 4;

/// Prefix of a GnuPG status line.
const STATUS_PREFIX: &str = "[GNUPG:] ";

/// Index of the status fd in the reader array of [`pump`].
const STATUS: usize = 2;
/// Index of stdin in the writer array of [`pump`].
const STDIN: usize = 0;
/// Index of the passphrase pipe in the writer array of [`pump`].
const PASS: usize = 1;

/// Captured result of one `gpg` invocation.
pub struct GpgOutput {
    /// Exit status of the child.
    pub status: ExitStatus,
    /// Everything written to stdout (may be secret key material, zeroized on drop).
    pub stdout: Zeroizing<Vec<u8>>,
    /// Everything written to stderr (passphrase bytes redacted).
    pub stderr: Vec<u8>,
    /// Everything written to the status fd (passphrase bytes redacted).
    pub status_lines: Vec<u8>,
}

impl fmt::Debug for GpgOutput {
    /// Shows the exit status, stderr and status lines, but only the length of stdout.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GpgOutput")
            .field("status", &self.status)
            .field("stdout", &format_args!("<{} bytes>", self.stdout.len()))
            .field("stderr", &String::from_utf8_lossy(&self.stderr))
            .field("status_lines", &String::from_utf8_lossy(&self.status_lines))
            .finish()
    }
}

impl GpgOutput {
    /// True when gpg exited with status 0.
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// True when a status line with `keyword` (e.g. `BAD_PASSPHRASE`) was written.
    pub fn has_status(&self, keyword: &str) -> bool {
        !self.status_args(keyword).is_empty()
    }

    /// The arguments (text after the keyword) of every status line with `keyword`.
    pub fn status_args(&self, keyword: &str) -> Vec<String> {
        String::from_utf8_lossy(&self.status_lines)
            .lines()
            .filter_map(|l| l.strip_prefix(STATUS_PREFIX))
            .filter_map(|l| match l.split_once(' ') {
                Some((k, rest)) if k == keyword => Some(rest.to_string()),
                None if l == keyword => Some(String::new()),
                _ => None,
            })
            .collect()
    }

    /// stderr as trimmed text (lossy UTF-8).
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

/// What to do with a status line in [`GpgRunner::run_interactive`].
pub enum Reply<'a> {
    /// Nothing: keep reading.
    Ignore,
    /// Write this passphrase (and a newline) to gpg's command fd.
    Answer(&'a SecretValue),
    /// Close the command fd, so gpg's pending prompt fails.
    Close,
}

/// Location of the `gpg` binary and the GnuPG home directory to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpgRunner {
    /// Absolute path of the `gpg` binary.
    gpg: PathBuf,
    /// Home directory (`--homedir` and `GNUPGHOME`); `None` uses gpg's default.
    homedir: Option<PathBuf>,
}

/// One child process to run and feed.
struct Invocation<'r, 'a> {
    /// Program to run.
    program: PathBuf,
    /// Complete argument list.
    args: Vec<OsString>,
    /// Bytes fed to stdin, which is closed afterwards.
    stdin: Option<&'r [u8]>,
    /// Passphrase fed to fd 3.
    passphrase: Option<&'r SecretValue>,
    /// Prompt handler; stdin then stays open as the command channel.
    responder: Option<&'r mut dyn FnMut(&str) -> Reply<'a>>,
    /// Time after which the child is killed.
    timeout: Duration,
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
        let mut full = self.fixed_args(passphrase.is_some());
        full.extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self.execute(Invocation {
            program: self.gpg.clone(),
            args: full,
            stdin,
            passphrase,
            responder: None,
            timeout,
        })
    }

    /// Runs gpg with `--command-fd 0` and answers its prompts while it runs.
    ///
    /// `responder` sees every status line (without the `[GNUPG:] ` prefix) as it
    /// arrives and decides whether to answer it with a passphrase, ignore it or
    /// close the command fd. Answers are written with a trailing newline and are
    /// redacted from stderr and the status lines. An answer containing a line
    /// break stops gpg with `MSG_PASSPHRASE_NEWLINE`.
    pub fn run_interactive<'a, I, S>(
        &self,
        args: I,
        responder: &mut dyn FnMut(&str) -> Reply<'a>,
        timeout: Duration,
    ) -> Result<GpgOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut full = self.fixed_args(false);
        full.push("--command-fd".into());
        full.push(COMMAND_FD.to_string().into());
        full.extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self.execute(Invocation {
            program: self.gpg.clone(),
            args: full,
            stdin: None,
            passphrase: None,
            responder: Some(responder),
            timeout,
        })
    }

    /// Sends `commands` to gpg-agent with `gpg-connect-agent` (found next to `gpg`).
    ///
    /// The tool gets the same home directory as gpg; the commands are followed by
    /// `/bye`. Use only for commands without secrets (e.g. `KEYINFO --list`).
    pub fn agent_commands(&self, commands: &[&str], timeout: Duration) -> Result<GpgOutput> {
        let program = self.gpg.with_file_name(GPG_CONNECT_AGENT);
        if !is_executable(&program) {
            return Err(KringError::NotFound(format!(
                "{GPG_CONNECT_AGENT} was not found next to {}",
                self.gpg.display()
            )));
        }
        let mut args: Vec<OsString> = Vec::new();
        if let Some(dir) = &self.homedir {
            args.push("--homedir".into());
            args.push(dir.into());
        }
        args.extend(commands.iter().map(OsString::from));
        args.push("/bye".into());
        self.execute(Invocation {
            program,
            args,
            stdin: None,
            passphrase: None,
            responder: None,
            timeout,
        })
    }

    /// Spawns one child, moves data until it is done and collects its output.
    ///
    /// The program is checked up front: the child moves pipes onto fds 3 and 4,
    /// which may be where the standard library keeps its exec-error pipe, so a
    /// failing `exec` would otherwise look like a child that exited at once.
    fn execute(&self, inv: Invocation<'_, '_>) -> Result<GpgOutput> {
        if !is_executable(&inv.program) {
            let e = io::Error::from(io::ErrorKind::NotFound);
            return Err(KringError::Gpg(format!(
                "cannot start {}: {e}",
                inv.program.display()
            )));
        }
        let interactive = inv.responder.is_some();
        let mut cmd = Command::new(&inv.program);
        cmd.args(&inv.args)
            .env_remove("GPG_AGENT_INFO")
            .stdin(if inv.stdin.is_some() || interactive {
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
        let pass_pipe = match inv.passphrase {
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

        let mut stdin_data = Zeroizing::new(Vec::new());
        append_zeroizing(&mut stdin_data, inv.stdin.unwrap_or_default());
        let readers = [
            Reader::new(child.stdout.take().map(OwnedFd::from)),
            Reader::new(child.stderr.take().map(OwnedFd::from)),
            Reader::new(Some(status_read)),
        ];
        let writers = [
            Writer {
                fd: child.stdin.take().map(OwnedFd::from),
                data: stdin_data,
                written: 0,
                keep_open: interactive,
            },
            Writer {
                fd: pass_write,
                data: inv.passphrase.map(passphrase_line).unwrap_or_default(),
                written: 0,
                keep_open: false,
            },
        ];
        let mut secrets: Vec<&SecretValue> = inv.passphrase.into_iter().collect();
        let mut answered: Vec<&SecretValue> = Vec::new();
        let deadline = Instant::now() + inv.timeout;
        let pumped = pump(
            readers,
            writers,
            inv.responder,
            &mut answered,
            &mut child,
            deadline,
        );
        let [stdout, stderr, status_lines] = match pumped {
            Ok(buffers) => buffers,
            Err(e) => {
                kill(&mut child);
                return Err(e);
            }
        };
        let status = wait_until(&mut child, deadline)?;
        secrets.extend(answered);
        let secret_bytes: Vec<&[u8]> = secrets.iter().map(|s| s.as_bytes()).collect();
        Ok(GpgOutput {
            status,
            stdout,
            stderr: redact(&stderr, &secret_bytes),
            status_lines: redact(&status_lines, &secret_bytes),
        })
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

/// The passphrase plus a newline, in a buffer allocated once at its final size.
fn passphrase_line(passphrase: &SecretValue) -> Zeroizing<Vec<u8>> {
    let bytes = passphrase.as_bytes();
    let mut line = Zeroizing::new(Vec::with_capacity(bytes.len() + 1));
    line.extend_from_slice(bytes);
    line.push(b'\n');
    line
}

/// Appends `data` to `buf`, moving to a larger zeroizing buffer instead of reallocating.
///
/// A plain `extend` could reallocate and free the old block without wiping it; here
/// the old buffer is dropped as a [`Zeroizing`] and thus overwritten.
fn append_zeroizing(buf: &mut Zeroizing<Vec<u8>>, data: &[u8]) {
    if buf.capacity() - buf.len() < data.len() {
        let needed = buf.len() + data.len();
        let mut grown = Zeroizing::new(Vec::with_capacity(needed.max(buf.capacity() * 2)));
        grown.extend_from_slice(buf);
        *buf = grown;
    }
    buf.extend_from_slice(data);
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

/// A pipe end being read into a zeroizing buffer.
struct Reader {
    /// Open fd, `None` after EOF.
    fd: Option<OwnedFd>,
    /// Bytes read so far.
    buf: Zeroizing<Vec<u8>>,
}

impl Reader {
    /// A reader for `fd` with an empty buffer.
    fn new(fd: Option<OwnedFd>) -> Self {
        Self {
            fd,
            buf: Zeroizing::new(Vec::new()),
        }
    }
}

/// A pipe end being written from a zeroizing buffer.
struct Writer {
    /// Open fd, `None` once closed.
    fd: Option<OwnedFd>,
    /// Bytes to write (answers are appended in interactive mode).
    data: Zeroizing<Vec<u8>>,
    /// Bytes of `data` already written.
    written: usize,
    /// Stay open when drained (command channel waiting for the next answer).
    keep_open: bool,
}

impl Writer {
    /// True when bytes are waiting to be written.
    fn pending(&self) -> bool {
        self.written < self.data.len()
    }
}

/// Moves data between the parent and the child until all pipes close or the child exits.
///
/// With a `responder`, each complete status line is passed to it and its answers are
/// queued on the stdin writer (recorded in `answered` for redaction). Fails at
/// `deadline`, on a read error, or when a stream exceeds [`MAX_OUTPUT`]; the caller
/// kills the child. Returns the stdout, stderr and status buffers.
fn pump<'a>(
    mut readers: [Reader; 3],
    mut writers: [Writer; 2],
    mut responder: Option<&mut dyn FnMut(&str) -> Reply<'a>>,
    answered: &mut Vec<&'a SecretValue>,
    child: &mut Child,
    deadline: Instant,
) -> Result<[Zeroizing<Vec<u8>>; 3]> {
    for fd in readers.iter().filter_map(|r| r.fd.as_ref()) {
        set_nonblocking(fd.as_raw_fd())?;
    }
    for fd in writers.iter().filter_map(|w| w.fd.as_ref()) {
        set_nonblocking(fd.as_raw_fd())?;
    }
    let mut chunk = Zeroizing::new(vec![0u8; READ_CHUNK]);
    let mut status_seen = 0;
    loop {
        for w in writers.iter_mut() {
            if !w.pending() && !w.keep_open {
                w.fd = None;
            }
        }
        let mut polls: Vec<libc::pollfd> = Vec::new();
        for r in &readers {
            if let Some(fd) = &r.fd {
                polls.push(pollfd(fd.as_raw_fd(), libc::POLLIN));
            }
        }
        for w in writers.iter().filter(|w| w.pending()) {
            if let Some(fd) = &w.fd {
                polls.push(pollfd(fd.as_raw_fd(), libc::POLLOUT));
            }
        }
        if readers.iter().all(|r| r.fd.is_none()) && polls.is_empty() {
            return Ok(readers.map(|r| r.buf));
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
                return Ok(readers.map(|r| r.buf));
            }
            continue;
        }
        for r in readers.iter_mut() {
            read_ready(r, &polls, &mut chunk)?;
        }
        if let Some(respond) = responder.as_mut() {
            let status = &readers[STATUS].buf;
            while let Some(end) = status[status_seen..].iter().position(|&b| b == b'\n') {
                let line = &status[status_seen..status_seen + end];
                status_seen += end + 1;
                let text = String::from_utf8_lossy(line);
                let Some(record) = text.trim_end_matches('\r').strip_prefix(STATUS_PREFIX) else {
                    continue;
                };
                apply_reply(&mut writers[STDIN], respond(record), answered)?;
            }
        }
        for w in writers.iter_mut() {
            write_ready(w, &polls);
        }
        // The passphrase is no longer needed once it is written.
        if writers[PASS].fd.is_none() {
            writers[PASS].data.zeroize();
        }
    }
}

/// Queues a responder's answer on the command channel, or closes it.
fn apply_reply<'a>(
    command: &mut Writer,
    reply: Reply<'a>,
    answered: &mut Vec<&'a SecretValue>,
) -> Result<()> {
    match reply {
        Reply::Ignore => {}
        Reply::Close => {
            command.fd = None;
            command.keep_open = false;
        }
        Reply::Answer(secret) => {
            if secret.as_bytes().contains(&b'\n') {
                return Err(KringError::InvalidInput(MSG_PASSPHRASE_NEWLINE.into()));
            }
            answered.push(secret);
            append_zeroizing(&mut command.data, &passphrase_line(secret));
        }
    }
    Ok(())
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

/// Reads what is available on a ready reader; closes it on EOF.
///
/// A read error other than EAGAIN/EINTR fails the run instead of silently
/// truncating the output.
fn read_ready(r: &mut Reader, polls: &[libc::pollfd], chunk: &mut [u8]) -> Result<()> {
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
        return Err(KringError::Gpg(format!("cannot read gpg output: {e}")));
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
    append_zeroizing(&mut r.buf, &chunk[..n as usize]);
    Ok(())
}

/// Writes the next part of a ready writer; closes it when the reader is gone.
///
/// A drained command channel (`keep_open`) is wiped and reused for later answers.
fn write_ready(w: &mut Writer, polls: &[libc::pollfd]) {
    let Some(fd) = &w.fd else { return };
    if !w.pending() || !is_ready(polls, fd.as_raw_fd()) {
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
    if w.pending() {
        return;
    }
    if w.keep_open {
        w.data.zeroize();
        w.written = 0;
        return;
    }
    w.fd = None;
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

/// Returns a copy of `buf` with every occurrence of each secret replaced by [`REDACTED`].
///
/// Secrets shorter than [`MIN_REDACT_LEN`] bytes are left alone. The caller drops
/// `buf` as a zeroizing buffer, so the unredacted bytes do not linger.
fn redact(buf: &[u8], secrets: &[&[u8]]) -> Vec<u8> {
    let secrets: Vec<&[u8]> = secrets
        .iter()
        .copied()
        .filter(|s| s.len() >= MIN_REDACT_LEN)
        .collect();
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    'scan: while i < buf.len() {
        for secret in &secrets {
            if buf[i..].starts_with(secret) {
                out.extend_from_slice(REDACTED);
                i += secret.len();
                continue 'scan;
            }
        }
        out.push(buf[i]);
        i += 1;
    }
    out
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

    /// Fake gpg that prompts twice on the status fd, reads the answers from stdin
    /// (the command fd), then asks a question that must hit EOF.
    const FAKE_PROMPT: &str = r#"#!/bin/sh
printf 'ARGS %s\n' "$*"
echo '[GNUPG:] GET_HIDDEN passphrase.enter' >&4
IFS= read -r a
echo '[GNUPG:] GOT_IT' >&4
echo '[GNUPG:] GET_HIDDEN passphrase.enter' >&4
IFS= read -r b
printf 'first=%s second=%s\n' "${#a}" "${#b}"
echo "leak $a $b" >&2
echo "[GNUPG:] ECHO $b" >&4
echo '[GNUPG:] GET_BOOL confirm' >&4
if IFS= read -r c; then echo 'got c'; else echo 'eof'; fi
"#;

    /// Fake gpg-connect-agent: prints its args and GNUPGHOME.
    const FAKE_AGENT: &str =
        "#!/bin/sh\nprintf 'ARGS %s\\n' \"$*\"\nprintf 'HOME %s\\n' \"${GNUPGHOME-unset}\"\n";

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
                ("prompt", FAKE_PROMPT),
                (GPG_CONNECT_AGENT, FAKE_AGENT),
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
        let stdout = String::from_utf8(out.stdout.to_vec()).unwrap();
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
        let stdout = String::from_utf8(out.stdout.to_vec()).unwrap();
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
        assert!(
            matches!(&r, Err(KringError::Gpg(m)) if m.contains("cannot start")),
            "{r:?}"
        );
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

    /// Redaction replaces every occurrence of each secret and leaves other bytes alone.
    #[test]
    fn redact_cases() {
        assert_eq!(
            redact(b"pass x pass", &[b"pass"]),
            b"<redacted> x <redacted>"
        );
        assert_eq!(redact(b"p", &[b"pass"]), b"p");
        assert_eq!(
            redact(b"old1 new22", &[b"old1", b"new22"]),
            b"<redacted> <redacted>"
        );
        assert_eq!(redact(b"a abc", &[b"abc"]), b"a abc", "too short");
        assert_eq!(redact(b"", &[]), b"");
    }

    /// A passphrase shorter than 4 bytes is not redacted (it would mangle the text).
    #[test]
    fn short_passphrase_is_not_redacted() {
        let pw = SecretValue::from_text("abc");
        let out = fake("leak")
            .run(Vec::<&str>::new(), None, Some(&pw), TIMEOUT_DEFAULT)
            .unwrap();
        assert_eq!(out.stderr_text(), "bad abc here");
    }

    /// The passphrase line is allocated once at its final size.
    #[test]
    fn passphrase_line_has_exact_capacity() {
        let pw = SecretValue::from_text("correct horse");
        let line = passphrase_line(&pw);
        assert_eq!(line.as_slice(), b"correct horse\n");
        assert_eq!(line.capacity(), pw.len() + 1);
        assert_eq!(
            passphrase_line(&SecretValue::from_text("")).as_slice(),
            b"\n"
        );
    }

    /// Growing a zeroizing buffer keeps its content and never reallocates in place.
    #[test]
    fn append_zeroizing_grows_into_a_new_buffer() {
        let mut buf = Zeroizing::new(Vec::new());
        append_zeroizing(&mut buf, b"abc");
        assert_eq!(buf.capacity(), 3);
        let before = buf.as_ptr();
        append_zeroizing(&mut buf, b"defg");
        assert_eq!(buf.as_slice(), b"abcdefg");
        assert!(buf.capacity() >= 7);
        assert_ne!(buf.as_ptr(), before, "moved to a new allocation");
        let cap = buf.capacity();
        let at = buf.as_ptr();
        let fill = vec![b'x'; cap - buf.len()];
        append_zeroizing(&mut buf, &fill);
        assert_eq!(buf.as_ptr(), at, "fits without growing");
    }

    /// A read error other than EAGAIN/EINTR fails instead of truncating the output.
    #[test]
    fn read_error_is_reported() {
        let (_read, write) = pipe_cloexec().unwrap();
        let raw = write.as_raw_fd();
        // Reading the write end of a pipe fails with EBADF.
        let mut r = Reader::new(Some(write));
        let mut polls = [pollfd(raw, libc::POLLIN)];
        polls[0].revents = libc::POLLIN;
        let mut chunk = [0u8; 16];
        let res = read_ready(&mut r, &polls, &mut chunk);
        assert!(
            matches!(&res, Err(KringError::Gpg(m)) if m.starts_with("cannot read gpg output")),
            "{res:?}"
        );
        assert!(r.fd.is_none());
    }

    /// Debug output shows the stdout length, never its bytes.
    #[test]
    fn debug_hides_stdout() {
        let out = fake("echo")
            .run(["x"], Some(b"TOPSECRET"), None, TIMEOUT_DEFAULT)
            .unwrap();
        assert!(out.stdout.ends_with(b"TOPSECRET"));
        let shown = format!("{out:?}");
        assert!(!shown.contains("TOPSECRET"), "{shown}");
        assert!(shown.contains(&format!("<{} bytes>", out.stdout.len())));
        assert!(shown.contains("NO_PASSPHRASE_FD"));
    }

    /// Status arguments are returned per keyword; a bare keyword has empty arguments.
    #[test]
    fn status_args_by_keyword() {
        let out = fake("echo")
            .run(["x"], None, None, TIMEOUT_DEFAULT)
            .unwrap();
        assert_eq!(out.status_args("NO_PASSPHRASE_FD"), [""]);
        assert!(out.status_args("NO").is_empty());
        let pw = SecretValue::from_text("12345");
        let out = fake("echo")
            .run(["x"], None, Some(&pw), TIMEOUT_DEFAULT)
            .unwrap();
        assert_eq!(out.status_args("GOT_PASSPHRASE"), ["5"]);
    }

    /// Interactive mode answers prompts in order over stdin and redacts the answers.
    #[test]
    fn interactive_answers_prompts_in_order() {
        let old = SecretValue::from_text("old-pass");
        let new = SecretValue::from_text("new-passphrase");
        let mut seen: Vec<String> = Vec::new();
        let mut prompts = 0;
        let mut responder = |line: &str| {
            seen.push(line.to_string());
            match line {
                "GET_HIDDEN passphrase.enter" => {
                    prompts += 1;
                    Reply::Answer(if prompts == 1 { &old } else { &new })
                }
                l if l.starts_with("GET_") => Reply::Close,
                _ => Reply::Ignore,
            }
        };
        let out = fake("prompt")
            .run_interactive(["--passwd", "FPR"], &mut responder, TIMEOUT_DEFAULT)
            .unwrap();
        assert!(out.success(), "{out:?}");
        let stdout = String::from_utf8(out.stdout.to_vec()).unwrap();
        assert!(
            stdout.contains("ARGS --batch --no-tty --pinentry-mode loopback --status-fd 4 --command-fd 0 --passwd FPR\n"),
            "{stdout}"
        );
        assert!(stdout.contains("first=8 second=14\n"), "{stdout}");
        assert!(stdout.ends_with("eof\n"), "{stdout}");
        assert_eq!(out.stderr_text(), "leak <redacted> <redacted>");
        assert!(out.has_status("ECHO"));
        assert_eq!(out.status_args("ECHO"), ["<redacted>"]);
        assert_eq!(seen.len(), 5, "{seen:?}");
        assert_eq!(seen[4], "GET_BOOL confirm");
    }

    /// An interactive answer with a line break stops gpg.
    #[test]
    fn interactive_newline_answer_is_refused() {
        let bad = SecretValue::from_text("a\nb");
        let mut responder = |line: &str| {
            if line.starts_with("GET_HIDDEN") {
                return Reply::Answer(&bad);
            }
            Reply::Ignore
        };
        let r = fake("prompt").run_interactive(["x"], &mut responder, TIMEOUT_DEFAULT);
        assert!(matches!(r, Err(KringError::InvalidInput(m)) if m == MSG_PASSPHRASE_NEWLINE));
    }

    /// Agent commands go to gpg-connect-agent next to gpg, with the home dir and `/bye`.
    #[test]
    fn agent_commands_use_connect_agent() {
        let runner = fake("echo").with_homedir(PathBuf::from("/tmp/kring-home"));
        let out = runner
            .agent_commands(&["KEYINFO --list"], TIMEOUT_DEFAULT)
            .unwrap();
        let stdout = String::from_utf8(out.stdout.to_vec()).unwrap();
        assert_eq!(
            stdout,
            "ARGS --homedir /tmp/kring-home KEYINFO --list /bye\nHOME /tmp/kring-home\n"
        );
        let missing = GpgRunner::new(PathBuf::from("/nonexistent-kring/gpg")).unwrap();
        let r = missing.agent_commands(&["x"], TIMEOUT_DEFAULT);
        assert!(matches!(r, Err(KringError::NotFound(m)) if m.contains(GPG_CONNECT_AGENT)));
    }
}
