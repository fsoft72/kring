//! Retiring a plaintext keyring file: encrypted backup first, then removal.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::scan::{KeyringFileInfo, KeyringFormat};
use crate::backup::{BackupInfo, BackupManager};
use crate::error::{KringError, Result};
use crate::model::{CollectionId, CollectionInfo, SecretValue, decode_path_segment};

/// Reason recorded on the backup made before a plaintext file is retired.
const RETIRE_REASON: &str = "retire-plaintext";
/// Object path prefix of real (non-alias) collections.
const COLLECTION_PREFIX: &str = "/org/freedesktop/secrets/collection/";

/// How a plaintext keyring file must be retired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetireMode {
    /// The daemon does not serve this keyring: the file can be deleted directly.
    DeleteFile,
    /// The daemon serves it live: delete the collection through the daemon.
    DeleteLiveCollection(CollectionId),
}

/// Decides how to retire `info`: live when a collection path segment decodes to `info.name`.
///
/// Alias paths never match.
pub fn retire_mode(info: &KeyringFileInfo, live: &[CollectionInfo]) -> RetireMode {
    for c in live {
        let Some(segment) = c.id.0.strip_prefix(COLLECTION_PREFIX) else {
            continue;
        };
        if decode_path_segment(segment).is_ok_and(|n| n == info.name) {
            return RetireMode::DeleteLiveCollection(c.id.clone());
        }
    }
    RetireMode::DeleteFile
}

/// Backs up a plaintext keyring file (age-encrypted with `passphrase`) and then deletes it.
///
/// Preconditions, each failing with `InvalidInput`: the mode is `DeleteFile`
/// (re-checked against `live`), the file is plaintext and not binary, and it is
/// unchanged since the scan (size and mtime). The file is removed only after the
/// backup manifest lists it with the sha256 of its current content.
pub fn retire_file(
    manager: &BackupManager,
    info: &KeyringFileInfo,
    live: &[CollectionInfo],
    passphrase: &SecretValue,
) -> Result<BackupInfo> {
    if retire_mode(info, live) != RetireMode::DeleteFile {
        return Err(invalid(
            "Keyring is live in the daemon, delete the collection instead",
        ));
    }
    if !info.plaintext {
        return Err(invalid("Only plaintext keyring files can be retired"));
    }
    if info.format == KeyringFormat::BinaryV0 {
        return Err(invalid("Binary keyring files cannot be retired"));
    }
    check_unchanged(info)?;
    let bytes = std::fs::read(&info.path).map_err(|e| io_err(&info.path, e))?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let backup = manager.create(
        RETIRE_REASON,
        std::slice::from_ref(&info.path),
        Some(passphrase),
    )?;
    let listed = backup
        .files
        .iter()
        .any(|f| f.original == info.path && f.sha256 == digest);
    if !listed {
        return Err(invalid(
            "Backup does not list the file with the expected checksum, file kept",
        ));
    }
    std::fs::remove_file(&info.path).map_err(|e| io_err(&info.path, e))?;
    Ok(backup)
}

/// Fails unless the file on disk still has the size and mtime recorded at scan time.
fn check_unchanged(info: &KeyringFileInfo) -> Result<()> {
    let stale = || invalid("File changed since scan, rescan first");
    let meta = std::fs::metadata(&info.path).map_err(|_| stale())?;
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    if meta.len() != info.size || modified != info.modified {
        return Err(stale());
    }
    Ok(())
}

/// Builds an `InvalidInput` error.
fn invalid(msg: &str) -> KringError {
    KringError::InvalidInput(msg.to_string())
}

/// Wraps an I/O error with the path.
fn io_err(path: &Path, e: std::io::Error) -> KringError {
    KringError::InvalidInput(format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring_file::scan_dir;
    use crate::model::encode_path_segment;

    const PLAIN: &str = "[keyring]\ndisplay-name=Test\nlock-on-idle=false\nlock-after=false\n";

    /// Builds a collection info with the given object path.
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

    /// Writes a file in a temp keyrings dir and scans it.
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

    /// Live detection handles escaped names and ignores aliases and other names.
    #[test]
    fn retire_mode_detects_live_collection() {
        let (_t, info, _m) = fixture("Default_keyring.keyring", PLAIN.as_bytes());
        assert_eq!(info.name, "Default_keyring");
        let path = format!(
            "/org/freedesktop/secrets/collection/{}",
            encode_path_segment("Default_keyring")
        );
        assert!(path.ends_with("Default_5fkeyring"));
        assert_eq!(
            retire_mode(&info, &[coll(&path)]),
            RetireMode::DeleteLiveCollection(CollectionId(path.clone()))
        );
        let others = [
            coll("/org/freedesktop/secrets/collection/login"),
            coll("/org/freedesktop/secrets/collection/Default_keyring"),
            coll("/org/freedesktop/secrets/aliases/Default_5fkeyring"),
        ];
        assert_eq!(retire_mode(&info, &others), RetireMode::DeleteFile);
        assert_eq!(retire_mode(&info, &[]), RetireMode::DeleteFile);
    }

    /// The backup is made and verified before the file is removed.
    #[test]
    fn retire_backs_up_then_deletes() {
        let (_t, info, mgr) = fixture("old.keyring", PLAIN.as_bytes());
        let pass = SecretValue::from_text("pw");
        let backup = retire_file(&mgr, &info, &[], &pass).unwrap();
        assert!(!info.path.exists());
        assert_eq!(backup.reason, RETIRE_REASON);
        assert!(backup.files[0].encrypted);
        let plain =
            crate::backup::read_backup_file(&backup, &backup.files[0], Some(&pass)).unwrap();
        assert_eq!(plain.as_slice(), PLAIN.as_bytes());
    }

    /// Binary, live and stale files are refused and kept.
    #[test]
    fn retire_refuses_binary() {
        let mut bin = crate::backup::KEYRING_MAGIC.to_vec();
        bin.extend_from_slice(b"payload");
        let (_t, info, mgr) = fixture("b.keyring", &bin);
        let pass = SecretValue::from_text("pw");
        let err = retire_file(&mgr, &info, &[], &pass).unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
        assert!(info.path.exists());
        assert!(!mgr.root.exists());

        let (_t, info, mgr) = fixture("p.keyring", PLAIN.as_bytes());
        let live = [coll("/org/freedesktop/secrets/collection/p")];
        assert!(matches!(
            retire_file(&mgr, &info, &live, &pass),
            Err(KringError::InvalidInput(_))
        ));
        std::fs::write(&info.path, format!("{PLAIN}extra=1\n")).unwrap();
        let err = retire_file(&mgr, &info, &[], &pass).unwrap_err();
        assert_eq!(
            err.to_string(),
            KringError::InvalidInput("File changed since scan, rescan first".into()).to_string()
        );
        assert!(info.path.exists());
    }

    /// A failing backup leaves the file in place.
    #[test]
    fn retire_keeps_file_when_backup_fails() {
        let (tmp, info, _m) = fixture("k.keyring", PLAIN.as_bytes());
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let mgr = BackupManager {
            root: blocker.join("sub"),
            keep: 20,
        };
        let pass = SecretValue::from_text("pw");
        assert!(retire_file(&mgr, &info, &[], &pass).is_err());
        assert!(info.path.exists());
    }
}
