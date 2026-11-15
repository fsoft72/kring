//! gpg runner and key listing against the real `gpg` binary in temp home directories.
//!
//! Every test uses its own 0700 home directory (`--homedir` and `GNUPGHOME`), and its
//! gpg-agent is killed with `gpgconf --homedir <dir> --kill all` on drop, so the
//! user's `~/.gnupg` and agent are never touched.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use kring_core::KringError;
use kring_core::gpg::{GpgAlgorithm, GpgRunner, TIMEOUT_DEFAULT, TIMEOUT_KEYGEN, list_keys};
use kring_core::model::SecretValue;

/// Passphrase of generated test keys.
const FIXTURE_PW: &str = "fixture-pw";

/// User id of the generated test key.
const TEST_UID: &str = "Kring Test <kring-test@example.invalid>";

/// A temp GnuPG home whose agent is killed on drop.
struct TempGnupgHome {
    /// Runner bound to this home.
    runner: GpgRunner,
    /// The home directory.
    dir: tempfile::TempDir,
}

impl TempGnupgHome {
    /// Creates a 0700 home; `None` when gpg is not installed.
    fn new() -> Option<Self> {
        let runner = GpgRunner::locate().ok()?;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let runner = runner.with_homedir(dir.path().to_path_buf());
        Some(Self { runner, dir })
    }
}

impl Drop for TempGnupgHome {
    /// Stops every GnuPG daemon started for this home.
    fn drop(&mut self) {
        let gpgconf = self.runner.gpg().with_file_name("gpgconf");
        kill_daemons(&gpgconf, self.dir.path());
    }
}

/// Runs `gpgconf --homedir <dir> --kill all` scoped to `dir`.
///
/// Failures cannot fail a test from `Drop`, so they are reported on stderr.
fn kill_daemons(gpgconf: &Path, dir: &Path) {
    let status = Command::new(gpgconf)
        .arg("--homedir")
        .arg(dir)
        .args(["--kill", "all"])
        .env("GNUPGHOME", dir)
        .env_remove("GPG_AGENT_INFO")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "WARNING: {} --kill all for {} exited with {s}",
            gpgconf.display(),
            dir.display()
        ),
        Err(e) => eprintln!(
            "WARNING: cannot run {} to stop the daemons of {}: {e}",
            gpgconf.display(),
            dir.display()
        ),
    }
}

/// A generated key is listed with its secret; its public export imported elsewhere is not.
#[test]
fn generate_list_export_import() {
    let Some(home) = TempGnupgHome::new() else {
        eprintln!("SKIPPED: gpg is not installed");
        return;
    };
    assert!(list_keys(&home.runner).unwrap().is_empty());

    let pw = SecretValue::from_text(FIXTURE_PW);
    let created = home
        .runner
        .run(
            ["--quick-gen-key", TEST_UID, "default", "default", "never"],
            None,
            Some(&pw),
            TIMEOUT_KEYGEN,
        )
        .unwrap();
    assert!(created.success(), "{}", created.stderr_text());
    assert!(created.has_status("KEY_CREATED"));

    let keys = list_keys(&home.runner).unwrap();
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    assert!(key.secret);
    assert!(!key.card);
    assert_eq!(key.fingerprint.len(), 40);
    assert!(key.fingerprint.ends_with(&key.key_id));
    assert_eq!(key.uids.len(), 1);
    assert_eq!(key.uids[0].uid, TEST_UID);
    assert_eq!(key.expires, None);
    assert!(key.created > 0);
    assert!(matches!(key.algorithm, GpgAlgorithm::EdDsa(_)), "{key:?}");
    assert_eq!(key.subkeys.len(), 1);
    assert_eq!(key.subkeys[0].capabilities, "e");
    assert_eq!(key.subkeys[0].fingerprint.len(), 40);

    let export = home
        .runner
        .run(
            ["--armor", "--export", key.fingerprint.as_str()],
            None,
            None,
            TIMEOUT_DEFAULT,
        )
        .unwrap();
    assert!(export.success(), "{}", export.stderr_text());
    assert!(
        export
            .stdout
            .starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
    );

    let Some(other) = TempGnupgHome::new() else {
        unreachable!("gpg was found above")
    };
    let imported = other
        .runner
        .run(
            ["--import"],
            Some(&export.stdout[..]),
            None,
            TIMEOUT_DEFAULT,
        )
        .unwrap();
    assert!(imported.success(), "{}", imported.stderr_text());
    assert!(imported.has_status("IMPORT_OK"));

    let listed = list_keys(&other.runner).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].fingerprint, key.fingerprint);
    assert!(!listed[0].secret);
    assert_eq!(listed[0].uids[0].uid, TEST_UID);
}

/// A failing listing (unusable home directory) is an error, not an empty list.
#[test]
fn listing_in_a_missing_home_fails() {
    let Some(home) = TempGnupgHome::new() else {
        eprintln!("SKIPPED: gpg is not installed");
        return;
    };
    let missing = home.dir.path().join("absent");
    let runner = home.runner.clone().with_homedir(missing.clone());
    let r = list_keys(&runner);
    kill_daemons(&home.runner.gpg().with_file_name("gpgconf"), &missing);
    assert!(
        matches!(&r, Err(KringError::Gpg(m)) if m.starts_with("--list-keys failed")),
        "{r:?}"
    );
}
