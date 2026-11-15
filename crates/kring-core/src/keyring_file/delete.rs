//! Deleting a keyring file the daemon does not serve, optionally after a backup.

use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::retire::{
    RetireMode, check_location, check_unchanged, invalid, retire_mode, verify_backup_entry,
};
use super::scan::{KeyringFileInfo, KeyringFormat, detect_format};
use crate::backup::{BackupInfo, BackupManager, io_err};
use crate::error::Result;
use crate::model::{CollectionInfo, SecretValue};

/// Reason recorded on the backup made before a file is deleted.
const DELETE_REASON: &str = "delete-file";
/// Message for a file the daemon serves live.
pub const MSG_DELETE_LIVE: &str = "Loaded by gnome-keyring: delete this keyring from Secrets";

/// Whether a file is backed up before [`delete_file`] removes it.
#[derive(Clone, Debug)]
pub enum DeleteBackup {
    /// Back up first; the passphrase encrypts the copy of a plaintext file
    /// (required then, ignored for a binary file).
    With(Option<SecretValue>),
    /// Remove the file without any backup.
    Without,
}

/// Outcome of [`delete_file`].
#[derive(Clone, Debug)]
pub struct DeleteReport {
    /// The backup made before the removal, when one was requested.
    pub backup: Option<BackupInfo>,
    /// Name (`KeyringFileInfo::name`) of the removed file.
    pub removed: String,
}

/// Deletes keyring file `info`, of any format, optionally after a backup.
///
/// Preconditions, each failing with `InvalidInput`: the daemon does not serve
/// the file (re-checked against `live`); the path is a regular `*.keyring`
/// file (not a symlink) directly inside `keyrings_dir`; the file is unchanged
/// since the scan (size and mtime, checked again right before the unlink).
///
/// With [`DeleteBackup::With`] the file is backed up first (reason
/// `delete-file`): a plaintext file without a passphrase fails with
/// `PassphraseRequired`. The file is removed only after the manifest lists it
/// with the sha256 of the bytes read before the backup, encrypted unless the
/// bytes are a binary keyring. Any backup failure keeps the file. The backup
/// is never pruned afterwards, since its original no longer exists.
pub fn delete_file(
    manager: &BackupManager,
    info: &KeyringFileInfo,
    keyrings_dir: &Path,
    live: &[CollectionInfo],
    backup: DeleteBackup,
) -> Result<DeleteReport> {
    if retire_mode(info, live) != RetireMode::DeleteFile {
        return Err(invalid(MSG_DELETE_LIVE));
    }
    check_location(info, keyrings_dir)?;
    check_unchanged(info)?;
    let backup = match backup {
        DeleteBackup::With(passphrase) => Some(back_up(manager, info, passphrase.as_ref())?),
        DeleteBackup::Without => None,
    };
    check_unchanged(info)?;
    std::fs::remove_file(&info.path).map_err(|e| io_err(&info.path, e))?;
    Ok(DeleteReport {
        backup,
        removed: info.name.clone(),
    })
}

/// Backs up `info` and verifies that the manifest lists the bytes read before the backup.
fn back_up(
    manager: &BackupManager,
    info: &KeyringFileInfo,
    passphrase: Option<&SecretValue>,
) -> Result<BackupInfo> {
    let bytes = Zeroizing::new(std::fs::read(&info.path).map_err(|e| io_err(&info.path, e))?);
    let digest = hex::encode(Sha256::digest(bytes.as_slice()));
    let must_encrypt = detect_format(&bytes) != KeyringFormat::BinaryV0;
    let backup = manager.create(DELETE_REASON, std::slice::from_ref(&info.path), passphrase)?;
    verify_backup_entry(&backup, &info.path, &digest, must_encrypt)?;
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KringError;
    use crate::keyring_file::scan_dir;
    use crate::model::CollectionId;

    /// Plaintext keyring content.
    const PLAIN: &str = "[keyring]\ndisplay-name=Test\nlock-on-idle=false\nlock-after=false\n";

    /// Directory with the synthetic fixtures.
    fn fixtures() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keyrings")
    }

    /// Writes `content` as `file` in a temp keyrings dir and scans it.
    fn fixture(file: &str, content: &[u8]) -> (tempfile::TempDir, KeyringFileInfo, BackupManager) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keyrings");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join(file), content).unwrap();
        let info = scan_dir(&dir).unwrap().remove(0);
        let mgr = BackupManager {
            root: tmp.path().join("backups"),
            keep: 20,
        };
        (tmp, info, mgr)
    }

    /// Copies the synthetic binary fixture into a temp keyrings dir.
    fn binary_fixture() -> (tempfile::TempDir, KeyringFileInfo, BackupManager) {
        let bytes = std::fs::read(fixtures().join("binary_two_items.keyring")).unwrap();
        fixture("bin.keyring", &bytes)
    }

    /// Deletes with the keyrings dir taken from the file's parent.
    fn delete(
        mgr: &BackupManager,
        info: &KeyringFileInfo,
        live: &[CollectionInfo],
        backup: DeleteBackup,
    ) -> Result<DeleteReport> {
        let dir = info.path.parent().unwrap().to_path_buf();
        delete_file(mgr, info, &dir, live, backup)
    }

    /// Builds a live collection with the given object path.
    fn coll(path: &str) -> CollectionInfo {
        CollectionInfo {
            id: CollectionId(path.to_string()),
            label: "x".into(),
            locked: false,
            item_count: 0,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        }
    }

    /// Asserts an `InvalidInput` refusal, a kept file and no backup root.
    fn assert_refused(r: Result<DeleteReport>, info: &KeyringFileInfo, mgr: &BackupManager) {
        assert!(matches!(r, Err(KringError::InvalidInput(_))), "{r:?}");
        assert!(info.path.exists());
        assert!(!mgr.root.exists());
    }

    /// A binary file is backed up as is (no passphrase needed) and removed.
    #[test]
    fn binary_with_backup() {
        let (_t, info, mgr) = binary_fixture();
        let bytes = std::fs::read(&info.path).unwrap();
        let r = delete(&mgr, &info, &[], DeleteBackup::With(None)).unwrap();
        assert_eq!(r.removed, "bin");
        assert!(!info.path.exists());
        let backup = r.backup.unwrap();
        assert_eq!(backup.reason, DELETE_REASON);
        assert_eq!(backup.files.len(), 1);
        assert!(!backup.files[0].encrypted);
        assert_eq!(backup.files[0].sha256, hex::encode(Sha256::digest(&bytes)));
        let listed = mgr.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].dir, backup.dir);
    }

    /// A plaintext file without a passphrase is refused with `PassphraseRequired` and kept.
    #[test]
    fn plaintext_with_backup_needs_passphrase() {
        let (_t, info, mgr) = fixture("p.keyring", PLAIN.as_bytes());
        let r = delete(&mgr, &info, &[], DeleteBackup::With(None));
        assert!(matches!(r, Err(KringError::PassphraseRequired)), "{r:?}");
        assert!(info.path.exists());
        assert!(mgr.list().unwrap().is_empty());
    }

    /// A plaintext file with a passphrase is backed up encrypted and removed.
    #[test]
    fn plaintext_with_passphrase() {
        let (_t, info, mgr) = fixture("p.keyring", PLAIN.as_bytes());
        let pass = SecretValue::from_text("pw");
        let r = delete(&mgr, &info, &[], DeleteBackup::With(Some(pass.clone()))).unwrap();
        assert!(!info.path.exists());
        let backup = r.backup.unwrap();
        assert!(backup.files[0].encrypted);
        let plain =
            crate::backup::read_backup_file(&backup, &backup.files[0], Some(&pass)).unwrap();
        assert_eq!(plain.as_slice(), PLAIN.as_bytes());
    }

    /// An unknown file (any format) is accepted and removed without a backup.
    #[test]
    fn without_backup() {
        let bytes = std::fs::read(fixtures().join("garbage.keyring")).unwrap();
        let (_t, info, mgr) = fixture("g.keyring", &bytes);
        assert_eq!(info.format, KeyringFormat::Unknown);
        let r = delete(&mgr, &info, &[], DeleteBackup::Without).unwrap();
        assert!(r.backup.is_none());
        assert_eq!(r.removed, "g");
        assert!(!info.path.exists());
        assert!(!mgr.root.exists());
    }

    /// A file served live by the daemon is refused with the Secrets hint.
    #[test]
    fn live_refused() {
        let (_t, info, mgr) = binary_fixture();
        let live = [coll("/org/freedesktop/secrets/collection/bin")];
        let r = delete(&mgr, &info, &live, DeleteBackup::Without);
        assert!(matches!(&r, Err(KringError::InvalidInput(m)) if m == MSG_DELETE_LIVE));
        assert_refused(r, &info, &mgr);
    }

    /// Symlinks and files outside the keyrings dir are refused.
    #[test]
    fn symlink_and_outside_dir_refused() {
        let (tmp, info, mgr) = fixture("a.keyring", PLAIN.as_bytes());
        let other = tmp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let r = delete_file(&mgr, &info, &other, &[], DeleteBackup::Without);
        assert_refused(r, &info, &mgr);

        let dir = info.path.parent().unwrap().to_path_buf();
        let target = tmp.path().join("target.keyring");
        std::fs::write(&target, PLAIN).unwrap();
        let link = dir.join("link.keyring");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut linked = info.clone();
        linked.path = link.clone();
        linked.name = "link".into();
        let r = delete_file(&mgr, &linked, &dir, &[], DeleteBackup::Without);
        assert_refused(r, &linked, &mgr);
        assert!(target.exists());
    }

    /// A file changed since the scan is refused, with and without backup.
    #[test]
    fn changed_since_scan_refused() {
        let (_t, info, mgr) = fixture("c.keyring", PLAIN.as_bytes());
        std::fs::write(&info.path, format!("{PLAIN}extra=1\n")).unwrap();
        let r = delete(&mgr, &info, &[], DeleteBackup::Without);
        assert!(
            r.unwrap_err()
                .to_string()
                .contains("File changed since scan")
        );
        assert!(info.path.exists());
        let pass = Some(SecretValue::from_text("pw"));
        assert_refused(
            delete(&mgr, &info, &[], DeleteBackup::With(pass)),
            &info,
            &mgr,
        );
    }

    /// A failing backup keeps the file.
    #[test]
    fn backup_failure_keeps_file() {
        let (tmp, info, _m) = binary_fixture();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let mgr = BackupManager {
            root: blocker.join("sub"),
            keep: 20,
        };
        assert!(delete(&mgr, &info, &[], DeleteBackup::With(None)).is_err());
        assert!(info.path.exists());
    }

    /// The deleted file's backup survives pruning (its original is gone).
    #[test]
    fn backup_of_deleted_file_is_pinned() {
        let (tmp, info, _m) = binary_fixture();
        let mgr = BackupManager {
            root: tmp.path().join("backups"),
            keep: 1,
        };
        let r = delete(&mgr, &info, &[], DeleteBackup::With(None)).unwrap();
        let pinned = r.backup.unwrap().dir;
        let other = tmp.path().join("keyrings/other.keyring");
        std::fs::write(&other, PLAIN).unwrap();
        let pass = SecretValue::from_text("pw");
        for _ in 0..3 {
            mgr.create("test", std::slice::from_ref(&other), Some(&pass))
                .unwrap();
        }
        assert!(pinned.exists());
    }
}
