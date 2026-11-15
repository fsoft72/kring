//! Restore of keyring files from backups.
//!
//! Restore runs in phases: validate names, decrypt and verify every file,
//! back up what is about to be overwritten, then write. Everything that can
//! fail for content reasons (names, passphrase, sha256, stale temp files,
//! pre-restore backup) happens before the first write, so a restore either
//! changes nothing or, after an I/O failure in the write phase, a prefix of
//! the files (the error names the files already restored).

use super::create::{BackupFile, BackupInfo, BackupManager, io_err};
use crate::error::{KringError, Result};
use crate::model::SecretValue;
use age::secrecy::SecretString;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Command the user must run (it is never run by kring) after a restore.
pub const RESTART_HINT: &str = "systemctl --user restart gnome-keyring-daemon";
/// Reason recorded on the backup of the files a restore overwrites.
const PRE_RESTORE_REASON: &str = "pre-restore";
/// Message for a wrong passphrase or an undecryptable age entry.
const WRONG_PASSPHRASE: &str = "Wrong passphrase for backup";

/// Outcome of a restore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreReport {
    /// Files written, in order.
    pub restored: Vec<PathBuf>,
    /// Backup of the files that were overwritten, if any of them existed.
    pub pre_restore_backup: Option<BackupInfo>,
}

/// Reads a file of a backup, decrypting `.age` entries and verifying sha256.
///
/// An encrypted entry without a passphrase is `PassphraseRequired`; a wrong
/// passphrase is `InvalidInput("Wrong passphrase for backup")`; a digest that
/// differs from the manifest is `InvalidInput("Backup file corrupted ...")`.
pub fn read_backup_file(
    info: &BackupInfo,
    file: &BackupFile,
    passphrase: Option<&SecretValue>,
) -> Result<Zeroizing<Vec<u8>>> {
    let raw = Zeroizing::new(fs::read(&file.stored).map_err(|e| io_err(&file.stored, e))?);
    let plain = if file.encrypted {
        decrypt(&raw, passphrase)?
    } else {
        raw
    };
    if hex::encode(Sha256::digest(plain.as_slice())) != file.sha256 {
        return Err(KringError::InvalidInput(format!(
            "Backup file corrupted: {} in {}",
            file.stored.display(),
            info.dir.display()
        )));
    }
    Ok(plain)
}

/// Decrypts an age scrypt-passphrase blob into a zeroizing buffer.
fn decrypt(blob: &[u8], passphrase: Option<&SecretValue>) -> Result<Zeroizing<Vec<u8>>> {
    let pass = passphrase.ok_or(KringError::PassphraseRequired)?;
    let text = pass
        .as_text()
        .ok_or_else(|| KringError::InvalidInput("passphrase is not valid UTF-8".into()))?;
    let bad = || KringError::InvalidInput(WRONG_PASSPHRASE.into());
    let decryptor = age::Decryptor::new(blob).map_err(|_| bad())?;
    let identity = age::scrypt::Identity::new(SecretString::from(text.to_string()));
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| bad())?;
    let mut plain = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut plain).map_err(|_| bad())?;
    Ok(plain)
}

/// Returns the destination of a backed-up file: always inside `keyrings_dir`.
///
/// Only `*.keyring` files and `default` are accepted.
fn destination(file: &BackupFile, keyrings_dir: &Path) -> Result<PathBuf> {
    let name = file.original.file_name().and_then(|n| n.to_str());
    let allowed = name.is_some_and(|n| n == "default" || n.strip_suffix(".keyring").is_some());
    match name {
        Some(n) if allowed && n != ".keyring" => Ok(keyrings_dir.join(n)),
        _ => Err(KringError::InvalidInput(format!(
            "Refusing to restore {}: not a keyring file",
            file.original.display()
        ))),
    }
}

/// Returns the temporary path used while writing `dest`.
fn temp_path(dest: &Path) -> PathBuf {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    dest.with_file_name(format!(".{name}.kring-restore.tmp"))
}

/// Writes `bytes` to `dest` through a temp file in the same directory.
///
/// The temp file is created with `create_new` and mode 0600, synced, then
/// renamed over `dest`; on failure the temp file is removed.
fn write_atomic(dest: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = temp_path(dest);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| io_err(&tmp, e))?;
    let written = f.write_all(bytes).and_then(|_| f.sync_all());
    drop(f);
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(io_err(&tmp, e));
    }
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_file(&tmp);
        return Err(io_err(dest, e));
    }
    Ok(())
}

/// Restores `files` of backup `info` into `keyrings_dir`, overwriting.
///
/// Targets are `<keyrings_dir>/<file name of original>`. Every file is
/// decrypted and checked against its sha256 before anything is written, then
/// the current versions of the files that exist are backed up with reason
/// `pre-restore` (using `passphrase` for plaintext ones); if that backup
/// fails nothing is restored. The write phase is atomic per file. Only an
/// I/O failure during the write phase can leave a partial restore; the error
/// message then lists the files already restored. The caller should show
/// [`RESTART_HINT`] afterwards.
pub fn restore(
    manager: &BackupManager,
    info: &BackupInfo,
    files: &[BackupFile],
    keyrings_dir: &Path,
    passphrase: Option<&SecretValue>,
) -> Result<RestoreReport> {
    let mut dests = Vec::new();
    for file in files {
        let dest = destination(file, keyrings_dir)?;
        if dests.contains(&dest) {
            return Err(KringError::InvalidInput(format!(
                "{} appears twice in the restore set",
                dest.display()
            )));
        }
        if temp_path(&dest).exists() {
            return Err(KringError::InvalidInput(format!(
                "A previous restore left {}; remove it and retry",
                temp_path(&dest).display()
            )));
        }
        dests.push(dest);
    }
    let mut contents = Vec::new();
    for file in files {
        contents.push(read_backup_file(info, file, passphrase)?);
    }

    let existing: Vec<PathBuf> = dests.iter().filter(|d| d.exists()).cloned().collect();
    let pre_restore_backup = if existing.is_empty() {
        None
    } else {
        Some(manager.create(PRE_RESTORE_REASON, &existing, passphrase)?)
    };

    let mut restored: Vec<PathBuf> = Vec::new();
    for (dest, bytes) in dests.iter().zip(&contents) {
        if let Err(e) = write_atomic(dest, bytes) {
            let done: Vec<_> = restored.iter().map(|p| p.display().to_string()).collect();
            return Err(KringError::Io {
                path: dest.clone(),
                message: format!(
                    "{e}; partially restored, already restored: [{}]",
                    done.join(", ")
                ),
            });
        }
        restored.push(dest.clone());
    }
    Ok(RestoreReport {
        restored,
        pre_restore_backup,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::KEYRING_MAGIC;
    use std::os::unix::fs::PermissionsExt;

    /// Temp tree: manager, keyrings dir (live files) and a source dir.
    fn setup() -> (tempfile::TempDir, BackupManager, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let live = tmp.path().join("keyrings");
        let src = tmp.path().join("src");
        fs::create_dir(&live).unwrap();
        fs::create_dir(&src).unwrap();
        let mgr = BackupManager {
            root: tmp.path().join("backups"),
            keep: 20,
        };
        (tmp, mgr, live, src)
    }

    /// Binary keyring content with a distinguishing payload.
    fn binary(payload: &str) -> Vec<u8> {
        let mut b = KEYRING_MAGIC.to_vec();
        b.extend_from_slice(payload.as_bytes());
        b
    }

    /// A binary file is restored byte for byte with mode 0600; no pre-backup when absent.
    #[test]
    fn restore_binary_file() {
        let (_t, mgr, live, src) = setup();
        let orig = src.join("a.keyring");
        fs::write(&orig, binary("one")).unwrap();
        let info = mgr.create("t", &[orig], None).unwrap();
        let report = restore(&mgr, &info, &info.files, &live, None).unwrap();
        let dest = live.join("a.keyring");
        assert_eq!(report.restored, std::slice::from_ref(&dest));
        assert!(report.pre_restore_backup.is_none());
        assert_eq!(fs::read(&dest).unwrap(), binary("one"));
        assert_eq!(
            fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!temp_path(&dest).exists());
    }

    /// Encrypted plaintext entries need the right passphrase.
    #[test]
    fn restore_encrypted_plaintext_file_needs_passphrase() {
        let (_t, mgr, live, src) = setup();
        let orig = src.join("p.keyring");
        fs::write(&orig, "[keyring]\ndisplay-name=x\n").unwrap();
        let pass = SecretValue::from_text("hunter2");
        let info = mgr.create("t", &[orig], Some(&pass)).unwrap();

        let err = restore(&mgr, &info, &info.files, &live, None).unwrap_err();
        assert!(matches!(err, KringError::PassphraseRequired));
        let wrong = SecretValue::from_text("nope");
        match restore(&mgr, &info, &info.files, &live, Some(&wrong)) {
            Err(KringError::InvalidInput(m)) => assert_eq!(m, WRONG_PASSPHRASE),
            other => panic!("unexpected {other:?}"),
        }
        assert!(!live.join("p.keyring").exists());

        restore(&mgr, &info, &info.files, &live, Some(&pass)).unwrap();
        assert_eq!(
            fs::read(live.join("p.keyring")).unwrap(),
            b"[keyring]\ndisplay-name=x\n"
        );
    }

    /// The current file is backed up (pre-restore) before being overwritten.
    #[test]
    fn restore_backs_up_current_first() {
        let (_t, mgr, live, src) = setup();
        let orig = src.join("a.keyring");
        fs::write(&orig, binary("old")).unwrap();
        let info = mgr.create("t", &[orig], None).unwrap();
        let dest = live.join("a.keyring");
        fs::write(&dest, binary("current")).unwrap();

        let report = restore(&mgr, &info, &info.files, &live, None).unwrap();
        let pre = report.pre_restore_backup.expect("pre-restore backup");
        assert_eq!(pre.reason, "pre-restore");
        assert_eq!(pre.files[0].original, dest);
        assert_eq!(fs::read(&pre.files[0].stored).unwrap(), binary("current"));
        assert_eq!(fs::read(&dest).unwrap(), binary("old"));
    }

    /// A failing pre-restore backup aborts: the current file is untouched.
    #[test]
    fn restore_aborts_when_pre_backup_fails() {
        let (t, mgr, live, src) = setup();
        let orig = src.join("a.keyring");
        fs::write(&orig, binary("old")).unwrap();
        let info = mgr.create("t", &[orig], None).unwrap();
        let dest = live.join("a.keyring");
        fs::write(&dest, binary("current")).unwrap();

        // A manager whose root is a regular file cannot create backups.
        let blocker = t.path().join("blocker");
        fs::write(&blocker, "x").unwrap();
        let broken = BackupManager {
            root: blocker,
            keep: 20,
        };
        assert!(restore(&broken, &info, &info.files, &live, None).is_err());
        assert_eq!(fs::read(&dest).unwrap(), binary("current"));
    }

    /// A plaintext current file without a passphrase aborts before any write.
    #[test]
    fn restore_plaintext_current_needs_passphrase() {
        let (_t, mgr, live, src) = setup();
        let orig = src.join("a.keyring");
        fs::write(&orig, binary("old")).unwrap();
        let info = mgr.create("t", &[orig], None).unwrap();
        let dest = live.join("a.keyring");
        fs::write(&dest, "[keyring]\n").unwrap();
        let err = restore(&mgr, &info, &info.files, &live, None).unwrap_err();
        assert!(matches!(err, KringError::PassphraseRequired));
        assert_eq!(fs::read(&dest).unwrap(), b"[keyring]\n");
    }

    /// A tampered stored copy is detected and nothing is written, even for earlier files.
    #[test]
    fn sha_mismatch_detected() {
        let (_t, mgr, live, src) = setup();
        let a = src.join("a.keyring");
        let b = src.join("b.keyring");
        fs::write(&a, binary("a")).unwrap();
        fs::write(&b, binary("b")).unwrap();
        let info = mgr.create("t", &[a, b], None).unwrap();
        fs::write(&info.files[1].stored, binary("tampered")).unwrap();

        match read_backup_file(&info, &info.files[1], None) {
            Err(KringError::InvalidInput(m)) => assert!(m.starts_with("Backup file corrupted")),
            other => panic!("unexpected {other:?}"),
        }
        assert!(restore(&mgr, &info, &info.files, &live, None).is_err());
        assert!(!live.join("a.keyring").exists());
    }

    /// Originals that are not keyring files, or that escape the dir, are refused.
    #[test]
    fn rejects_non_keyring_names() {
        let (_t, mgr, live, src) = setup();
        let f = src.join("a.keyring");
        fs::write(&f, binary("a")).unwrap();
        let info = mgr.create("t", &[f], None).unwrap();
        for bad in ["passwd", "notes.txt", ".keyring", "..", "/"] {
            let mut file = info.files[0].clone();
            file.original = PathBuf::from("/etc").join(bad);
            let err = restore(&mgr, &info, &[file], &live, None).unwrap_err();
            assert!(matches!(err, KringError::InvalidInput(_)), "{bad}");
        }
        // Directories in the original are dropped: the target stays in keyrings_dir.
        let mut file = info.files[0].clone();
        file.original = PathBuf::from("/elsewhere/default");
        let report = restore(&mgr, &info, &[file], &live, None).unwrap();
        assert_eq!(report.restored, [live.join("default")]);
    }

    /// A stale temp file is reported and nothing is touched.
    #[test]
    fn stale_temp_is_reported() {
        let (_t, mgr, live, src) = setup();
        let f = src.join("a.keyring");
        fs::write(&f, binary("a")).unwrap();
        let info = mgr.create("t", &[f], None).unwrap();
        let stale = temp_path(&live.join("a.keyring"));
        fs::write(&stale, "x").unwrap();
        match restore(&mgr, &info, &info.files, &live, None) {
            Err(KringError::InvalidInput(m)) => assert!(m.contains(&stale.display().to_string())),
            other => panic!("unexpected {other:?}"),
        }
        assert!(!live.join("a.keyring").exists());
    }
}
