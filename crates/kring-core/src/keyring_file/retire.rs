//! Retiring a plaintext keyring file: encrypted backup first, then removal.

use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::scan::{KeyringFileInfo, KeyringFormat, detect_format};
use crate::backup::{BackupInfo, BackupManager, io_err};
use crate::error::{KringError, Result};
use crate::model::{CollectionId, CollectionInfo, SecretValue, decode_path_segment};

/// Reason recorded on the backup made before a plaintext file is retired.
const RETIRE_REASON: &str = "retire-plaintext";
/// Message for a file that no longer matches the scan.
const STALE_MESSAGE: &str = "File changed since scan, rescan first";
/// Extension of keyring files.
const KEYRING_EXTENSION: &str = "keyring";
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
/// (re-checked against `live`); the path is a regular `*.keyring` file (not a
/// symlink) directly inside `keyrings_dir`; `info.plaintext` is set and the
/// bytes on disk are not a binary keyring (decided from the bytes, not from
/// `info`); the file is unchanged since the scan (size and mtime, checked
/// again right before the unlink). The file is removed only after the backup
/// manifest lists it as encrypted with the sha256 of its current content.
pub fn retire_file(
    manager: &BackupManager,
    info: &KeyringFileInfo,
    keyrings_dir: &Path,
    live: &[CollectionInfo],
    passphrase: &SecretValue,
) -> Result<BackupInfo> {
    let digest = precheck(info, keyrings_dir, live)?;
    let backup = manager.create(
        RETIRE_REASON,
        std::slice::from_ref(&info.path),
        Some(passphrase),
    )?;
    verify_backup(&backup, &info.path, &digest)?;
    check_unchanged(info)?;
    std::fs::remove_file(&info.path).map_err(|e| io_err(&info.path, e))?;
    Ok(backup)
}

/// Runs the checks shared by single and batch retire and returns the sha256 of the file.
///
/// Order: not live, plaintext flag, location, unchanged since scan, then the
/// bytes on disk must not be a binary keyring (decided from the bytes).
fn precheck(
    info: &KeyringFileInfo,
    keyrings_dir: &Path,
    live: &[CollectionInfo],
) -> Result<String> {
    if retire_mode(info, live) != RetireMode::DeleteFile {
        return Err(invalid(
            "Keyring is live in the daemon, delete the collection instead",
        ));
    }
    if !info.plaintext {
        return Err(invalid("Only plaintext keyring files can be retired"));
    }
    check_location(info, keyrings_dir)?;
    check_unchanged(info)?;
    let bytes = Zeroizing::new(std::fs::read(&info.path).map_err(|e| io_err(&info.path, e))?);
    if detect_format(&bytes) == KeyringFormat::BinaryV0 {
        return Err(invalid("Binary keyring files cannot be retired"));
    }
    Ok(hex::encode(Sha256::digest(bytes.as_slice())))
}

/// Outcome of [`retire_files_batch`].
#[derive(Clone, Debug)]
pub struct RetireBatchReport {
    /// The single backup holding every file that passed the pre-checks.
    ///
    /// `None` when no file passed them (no backup is created then).
    pub backup: Option<BackupInfo>,
    /// Names (`KeyringFileInfo::name`) of the files that were backed up and removed.
    pub removed: Vec<String>,
    /// Names of the files that were kept, each with the reason.
    pub kept: Vec<(String, String)>,
}

/// Retires many plaintext keyring files with ONE encrypted backup.
///
/// Every file goes through the same pre-checks as [`retire_file`]; a file
/// failing them is listed in `kept` and excluded. The remaining files are
/// backed up together, then each is verified in the manifest (encrypted and
/// sha256) and unlinked after a final unchanged check; a file failing either
/// step is kept and listed, the others proceed. A backup failure is returned
/// as an error and nothing is removed. Entries are de-duplicated by path
/// (the first one wins).
///
/// # Errors
///
/// `InvalidInput` when `infos` is empty, or the backup error.
pub fn retire_files_batch(
    manager: &BackupManager,
    infos: &[KeyringFileInfo],
    keyrings_dir: &Path,
    live: &[CollectionInfo],
    passphrase: &SecretValue,
) -> Result<RetireBatchReport> {
    if infos.is_empty() {
        return Err(invalid("No files to retire"));
    }
    let mut kept = Vec::new();
    let mut accepted: Vec<(&KeyringFileInfo, String)> = Vec::new();
    for (index, info) in infos.iter().enumerate() {
        // The same path listed twice is retired once: the first entry wins.
        if infos[..index]
            .iter()
            .any(|earlier| earlier.path == info.path)
        {
            continue;
        }
        match precheck(info, keyrings_dir, live) {
            Ok(digest) => accepted.push((info, digest)),
            Err(e) => kept.push((info.name.clone(), e.to_string())),
        }
    }
    if accepted.is_empty() {
        return Ok(RetireBatchReport {
            backup: None,
            removed: Vec::new(),
            kept,
        });
    }
    let paths: Vec<_> = accepted.iter().map(|(i, _)| i.path.clone()).collect();
    let backup = manager.create(RETIRE_REASON, &paths, Some(passphrase))?;
    let mut removed = Vec::new();
    for (info, digest) in accepted {
        let outcome = verify_backup(&backup, &info.path, &digest)
            .and_then(|()| check_unchanged(info))
            .and_then(|()| std::fs::remove_file(&info.path).map_err(|e| io_err(&info.path, e)));
        match outcome {
            Ok(()) => removed.push(info.name.clone()),
            Err(e) => kept.push((info.name.clone(), e.to_string())),
        }
    }
    Ok(RetireBatchReport {
        backup: Some(backup),
        removed,
        kept,
    })
}

/// Fails unless the manifest lists `path` as encrypted with the given sha256.
fn verify_backup(backup: &BackupInfo, path: &Path, digest: &str) -> Result<()> {
    let Some(entry) = backup
        .files
        .iter()
        .find(|f| f.original == path && f.sha256 == digest)
    else {
        return Err(invalid(
            "Backup does not list the file with the expected checksum, file kept",
        ));
    };
    if !entry.encrypted {
        return Err(invalid("Backup not encrypted, file kept"));
    }
    Ok(())
}

/// Fails unless `info.path` is a non-symlink `*.keyring` file directly in `keyrings_dir`.
fn check_location(info: &KeyringFileInfo, keyrings_dir: &Path) -> Result<()> {
    if info.path.extension().is_none_or(|e| e != KEYRING_EXTENSION) {
        return Err(invalid("Only .keyring files can be retired"));
    }
    let meta = std::fs::symlink_metadata(&info.path).map_err(|e| meta_err(&info.path, e))?;
    if !meta.file_type().is_file() {
        return Err(invalid("Keyring path is not a regular file"));
    }
    let parent = info
        .path
        .parent()
        .ok_or_else(|| invalid("Keyring path has no parent directory"))?;
    let parent = std::fs::canonicalize(parent).map_err(|e| io_err(parent, e))?;
    let dir = std::fs::canonicalize(keyrings_dir).map_err(|e| io_err(keyrings_dir, e))?;
    if parent != dir {
        return Err(invalid("Keyring file is outside the keyrings directory"));
    }
    Ok(())
}

/// Maps a metadata error: a vanished file means the scan is stale, anything else is I/O.
fn meta_err(path: &Path, e: std::io::Error) -> KringError {
    if e.kind() == std::io::ErrorKind::NotFound {
        return invalid(STALE_MESSAGE);
    }
    io_err(path, e)
}

/// Fails unless the file on disk still has the size and mtime recorded at scan time.
fn check_unchanged(info: &KeyringFileInfo) -> Result<()> {
    let meta = std::fs::metadata(&info.path).map_err(|e| meta_err(&info.path, e))?;
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    if meta.len() != info.size || modified != info.modified {
        return Err(invalid(STALE_MESSAGE));
    }
    Ok(())
}

/// Builds an `InvalidInput` error.
fn invalid(msg: &str) -> KringError {
    KringError::InvalidInput(msg.to_string())
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

    /// Default call: keyrings dir is the parent of the file.
    fn retire(
        mgr: &BackupManager,
        info: &KeyringFileInfo,
        live: &[CollectionInfo],
    ) -> Result<BackupInfo> {
        let dir = info.path.parent().unwrap().to_path_buf();
        retire_file(mgr, info, &dir, live, &SecretValue::from_text("pw"))
    }

    /// The backup is made and verified before the file is removed.
    #[test]
    fn retire_backs_up_then_deletes() {
        let (_t, info, mgr) = fixture("old.keyring", PLAIN.as_bytes());
        let pass = SecretValue::from_text("pw");
        let backup = retire(&mgr, &info, &[]).unwrap();
        assert!(!info.path.exists());
        assert_eq!(backup.reason, RETIRE_REASON);
        assert!(backup.files[0].encrypted);
        assert_eq!(
            backup.files[0].sha256,
            hex::encode(Sha256::digest(PLAIN.as_bytes()))
        );
        let plain =
            crate::backup::read_backup_file(&backup, &backup.files[0], Some(&pass)).unwrap();
        assert_eq!(plain.as_slice(), PLAIN.as_bytes());
    }

    /// Asserts a refusal with `InvalidInput`, a kept file and no backup root.
    fn assert_refused(r: Result<BackupInfo>, info: &KeyringFileInfo, mgr: &BackupManager) {
        assert!(matches!(r, Err(KringError::InvalidInput(_))), "{r:?}");
        assert!(info.path.exists());
        assert!(!mgr.root.exists());
    }

    /// Binary files are refused, from the bytes even when `info` claims plaintext.
    #[test]
    fn retire_refuses_binary() {
        let mut bin = crate::backup::KEYRING_MAGIC.to_vec();
        bin.extend_from_slice(b"payload");
        let (_t, mut info, mgr) = fixture("b.keyring", &bin);
        assert_refused(retire(&mgr, &info, &[]), &info, &mgr);
        info.plaintext = true;
        info.format = KeyringFormat::Textual;
        assert_refused(retire(&mgr, &info, &[]), &info, &mgr);
    }

    /// Live collections and `plaintext == false` are refused.
    #[test]
    fn retire_refuses_live_and_not_plaintext() {
        let (_t, mut info, mgr) = fixture("p.keyring", PLAIN.as_bytes());
        let live = [coll("/org/freedesktop/secrets/collection/p")];
        assert_refused(retire(&mgr, &info, &live), &info, &mgr);
        info.plaintext = false;
        assert_refused(retire(&mgr, &info, &[]), &info, &mgr);
    }

    /// Non-`.keyring` paths are refused even when flagged plaintext.
    #[test]
    fn retire_refuses_other_extension() {
        let (_t, mut info, mgr) = fixture("a.keyring", PLAIN.as_bytes());
        let other = info.path.with_file_name("notes.txt");
        std::fs::rename(&info.path, &other).unwrap();
        info.path = other;
        info.plaintext = true;
        assert_refused(retire(&mgr, &info, &[]), &info, &mgr);
    }

    /// Files outside the keyrings dir and symlinks are refused.
    #[test]
    fn retire_refuses_outside_dir_and_symlink() {
        let (tmp, info, mgr) = fixture("a.keyring", PLAIN.as_bytes());
        let other = tmp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let pass = SecretValue::from_text("pw");
        let r = retire_file(&mgr, &info, &other, &[], &pass);
        assert_refused(r, &info, &mgr);

        let dir = info.path.parent().unwrap().to_path_buf();
        let target = tmp.path().join("target.keyring");
        std::fs::write(&target, PLAIN).unwrap();
        let link = dir.join("link.keyring");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut linked = info.clone();
        linked.path = link;
        linked.name = "link".into();
        let r = retire_file(&mgr, &linked, &dir, &[], &pass);
        assert_refused(r, &linked, &mgr);
        assert!(target.exists());
    }

    /// A file changed after the scan (size, or mtime only) is refused.
    #[test]
    fn retire_refuses_changed_since_scan() {
        let (_t, info, mgr) = fixture("c.keyring", PLAIN.as_bytes());
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&info.path)
            .unwrap();
        f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(info.modified + 100))
            .unwrap();
        drop(f);
        let err = retire(&mgr, &info, &[]).unwrap_err();
        assert!(err.to_string().contains("File changed since scan"));
        assert!(info.path.exists());
        assert!(!mgr.root.exists());

        let (_t, info, mgr) = fixture("d.keyring", PLAIN.as_bytes());
        std::fs::write(&info.path, format!("{PLAIN}extra=1\n")).unwrap();
        assert_refused(retire(&mgr, &info, &[]), &info, &mgr);
        std::fs::remove_file(&info.path).unwrap();
        let err = retire(&mgr, &info, &[]).unwrap_err();
        assert!(err.to_string().contains("File changed since scan"));
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
        assert!(retire(&mgr, &info, &[]).is_err());
        assert!(info.path.exists());
    }

    /// The manifest check fails closed on a missing, mismatching or unencrypted entry.
    ///
    /// A real `BackupManager` always lists the file it was given, so the guard
    /// is exercised directly with fabricated manifests.
    #[test]
    fn verify_backup_fails_closed() {
        let path = std::path::PathBuf::from("/x/a.keyring");
        let entry = |original: &str, sha: &str, encrypted: bool| crate::backup::BackupFile {
            original: original.into(),
            stored: "/b/a.keyring.age".into(),
            sha256: sha.into(),
            encrypted,
        };
        let backup = |files| BackupInfo {
            dir: "/b".into(),
            reason: RETIRE_REASON.into(),
            created: String::new(),
            files,
            seq: 1,
            prune_warning: None,
            pruned: Vec::new(),
        };
        let msg = |b: &BackupInfo| verify_backup(b, &path, "abc").unwrap_err().to_string();
        assert!(msg(&backup(vec![])).contains("does not list"));
        assert!(msg(&backup(vec![entry("/x/other", "abc", true)])).contains("does not list"));
        assert!(msg(&backup(vec![entry("/x/a.keyring", "zzz", true)])).contains("does not list"));
        assert!(msg(&backup(vec![entry("/x/a.keyring", "abc", false)])).contains("not encrypted"));
        assert!(
            verify_backup(
                &backup(vec![entry("/x/a.keyring", "abc", true)]),
                &path,
                "abc"
            )
            .is_ok()
        );
    }

    /// Writes a plaintext file next to the scanned ones and rescans the directory.
    fn batch_fixture(
        files: &[(&str, &[u8])],
    ) -> (tempfile::TempDir, Vec<KeyringFileInfo>, BackupManager) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keyrings");
        std::fs::create_dir(&dir).unwrap();
        for (n, c) in files {
            std::fs::write(dir.join(n), c).unwrap();
        }
        let mut infos = scan_dir(&dir).unwrap();
        infos.sort_by(|a, b| a.name.cmp(&b.name));
        let mgr = BackupManager {
            root: tmp.path().join("backups"),
            keep: 20,
        };
        (tmp, infos, mgr)
    }

    /// Runs the batch with the keyrings dir taken from the first file.
    fn batch(
        mgr: &BackupManager,
        infos: &[KeyringFileInfo],
        live: &[CollectionInfo],
    ) -> Result<RetireBatchReport> {
        let dir = infos[0].path.parent().unwrap().to_path_buf();
        retire_files_batch(mgr, infos, &dir, live, &SecretValue::from_text("pw"))
    }

    /// Many files, one backup, all removed.
    #[test]
    fn batch_one_backup_many_files() {
        let (_t, infos, mgr) = batch_fixture(&[
            ("a.keyring", PLAIN.as_bytes()),
            ("b.keyring", PLAIN.as_bytes()),
            ("c.keyring", b"[keyring]\ndisplay-name=C\n"),
        ]);
        let r = batch(&mgr, &infos, &[]).unwrap();
        let backup = r.backup.unwrap();
        assert_eq!(backup.files.len(), 3);
        assert!(backup.files.iter().all(|f| f.encrypted));
        assert_eq!(r.removed, vec!["a", "b", "c"]);
        assert!(r.kept.is_empty());
        assert!(infos.iter().all(|i| !i.path.exists()));
        assert_eq!(std::fs::read_dir(&mgr.root).unwrap().count(), 1);
    }

    /// Live and binary files are kept and excluded; with nothing left no backup is made.
    #[test]
    fn batch_excludes_live_and_binary() {
        let mut bin = crate::backup::KEYRING_MAGIC.to_vec();
        bin.extend_from_slice(b"payload");
        let (_t, infos, mgr) = batch_fixture(&[
            ("bin.keyring", &bin),
            ("live.keyring", PLAIN.as_bytes()),
            ("ok.keyring", PLAIN.as_bytes()),
        ]);
        let live = [coll("/org/freedesktop/secrets/collection/live")];
        let r = batch(&mgr, &infos, &live).unwrap();
        assert_eq!(r.removed, vec!["ok"]);
        assert_eq!(r.backup.unwrap().files.len(), 1);
        let kept: Vec<_> = r.kept.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(kept, vec!["bin", "live"]);
        assert!(infos[0].path.exists() && infos[1].path.exists());

        let only: Vec<_> = infos[..2].to_vec();
        let (_t2, _i2, mgr2) = batch_fixture(&[]);
        let r = batch(&mgr2, &only, &live).unwrap();
        assert!(r.backup.is_none() && r.removed.is_empty());
        assert_eq!(r.kept.len(), 2);
        assert!(!mgr2.root.exists());
    }

    /// A file changed since the scan is kept, the others are retired.
    #[test]
    fn batch_keeps_changed_file() {
        let (_t, infos, mgr) = batch_fixture(&[
            ("a.keyring", PLAIN.as_bytes()),
            ("b.keyring", PLAIN.as_bytes()),
        ]);
        std::fs::write(&infos[1].path, format!("{PLAIN}extra=1\n")).unwrap();
        let r = batch(&mgr, &infos, &[]).unwrap();
        assert_eq!(r.removed, vec!["a"]);
        assert_eq!(r.kept.len(), 1);
        assert_eq!(r.kept[0].0, "b");
        assert!(r.kept[0].1.contains("File changed since scan"));
        assert!(infos[1].path.exists());
    }

    /// The same file listed twice is retired once (first entry wins).
    #[test]
    fn batch_dedupes_by_path() {
        let (_t, infos, mgr) = batch_fixture(&[("a.keyring", PLAIN.as_bytes())]);
        let twice = vec![infos[0].clone(), infos[0].clone()];
        let r = batch(&mgr, &twice, &[]).unwrap();
        assert_eq!(r.removed, vec!["a"]);
        assert!(r.kept.is_empty(), "{:?}", r.kept);
        assert_eq!(r.backup.unwrap().files.len(), 1);
    }

    /// A failing backup removes nothing; empty input is refused.
    #[test]
    fn batch_backup_failure_removes_nothing() {
        let (tmp, infos, _m) = batch_fixture(&[
            ("a.keyring", PLAIN.as_bytes()),
            ("b.keyring", PLAIN.as_bytes()),
        ]);
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let mgr = BackupManager {
            root: blocker.join("sub"),
            keep: 20,
        };
        assert!(batch(&mgr, &infos, &[]).is_err());
        assert!(infos.iter().all(|i| i.path.exists()));

        let dir = infos[0].path.parent().unwrap().to_path_buf();
        let r = retire_files_batch(&mgr, &[], &dir, &[], &SecretValue::from_text("pw"));
        assert!(matches!(r, Err(KringError::InvalidInput(m)) if m == "No files to retire"));
    }
}
