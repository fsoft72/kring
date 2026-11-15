//! Throwaway GnuPG home directories for the gpg integration tests.
//!
//! Every home is a fresh 0700 temp dir passed as `--homedir` and `GNUPGHOME`; its
//! daemons are stopped with `gpgconf --homedir <dir> --kill all` on drop (and its
//! socket dir below `$XDG_RUNTIME_DIR/gnupg` removed), so the user's `~/.gnupg` and
//! gpg-agent are never touched.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use kring_core::gpg::GpgRunner;

/// A temp GnuPG home whose agent is killed on drop.
pub struct TempGnupgHome {
    /// Runner bound to this home.
    pub runner: GpgRunner,
    /// The home directory.
    pub dir: tempfile::TempDir,
}

impl TempGnupgHome {
    /// Creates a 0700 home; `None` when gpg is not installed.
    pub fn new() -> Option<Self> {
        let runner = GpgRunner::locate().ok()?;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let runner = runner.with_homedir(dir.path().to_path_buf());
        Some(Self { runner, dir })
    }

    /// Path of `gpgconf` next to the located gpg.
    pub fn gpgconf(&self) -> std::path::PathBuf {
        self.runner.gpg().with_file_name("gpgconf")
    }
}

impl Drop for TempGnupgHome {
    /// Stops every GnuPG daemon started for this home and removes its socket dir.
    fn drop(&mut self) {
        kill_daemons(&self.gpgconf(), self.dir.path());
        remove_socket_dir(&self.gpgconf(), self.dir.path());
    }
}

/// Runs `gpgconf --homedir <dir> --remove-socketdir` (the dir below `$XDG_RUNTIME_DIR/gnupg`).
pub fn remove_socket_dir(gpgconf_path: &Path, dir: &Path) {
    gpgconf(gpgconf_path, dir, &["--remove-socketdir"]);
}

/// Runs `gpgconf --homedir <dir> --kill all` scoped to `dir`.
pub fn kill_daemons(gpgconf_path: &Path, dir: &Path) {
    gpgconf(gpgconf_path, dir, &["--kill", "all"]);
}

/// Runs `gpgconf --homedir <dir> <args>` scoped to `dir`.
///
/// Failures cannot fail a test from `Drop`, so they are reported on stderr.
fn gpgconf(gpgconf: &Path, dir: &Path, args: &[&str]) {
    let status = Command::new(gpgconf)
        .arg("--homedir")
        .arg(dir)
        .args(args)
        .env("GNUPGHOME", dir)
        .env_remove("GPG_AGENT_INFO")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "WARNING: {} {args:?} for {} exited with {s}",
            gpgconf.display(),
            dir.display()
        ),
        Err(e) => eprintln!(
            "WARNING: cannot run {} {args:?} for {}: {e}",
            gpgconf.display(),
            dir.display()
        ),
    }
}
