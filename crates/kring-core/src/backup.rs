//! Backups of keyring files, with age encryption for plaintext keyrings.

use crate::error::{KringError, Result};
use crate::model::SecretValue;
use age::secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::{parse_borrowed, well_known::Rfc3339};

/// Magic header of a binary gnome-keyring file.
pub const KEYRING_MAGIC: &[u8] = b"GnomeKeyring\n\r\0\n";
/// Number of backups kept after pruning.
pub const BACKUP_KEEP: usize = 20;
/// Name of the manifest file inside each backup directory.
const MANIFEST_NAME: &str = "manifest.json";
/// Extension of keyring files.
const KEYRING_EXT: &str = "keyring";
/// Suffix of a backup directory still being written.
const TMP_SUFFIX: &str = ".tmp";
/// Timestamp format used in backup directory names.
const DIR_TIME_FORMAT: &str = "[year][month][day]-[hour][minute][second]";

/// One file stored in a backup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFile {
    /// Path of the file that was backed up.
    pub original: PathBuf,
    /// Path of the copy inside the backup directory.
    pub stored: PathBuf,
    /// Hex SHA-256 of the original bytes.
    pub sha256: String,
    /// Whether the stored copy is age-encrypted.
    pub encrypted: bool,
}

/// Manifest and location of one backup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupInfo {
    /// Backup directory.
    pub dir: PathBuf,
    /// Sanitized reason the backup was made.
    pub reason: String,
    /// Creation time, RFC 3339 UTC.
    pub created: String,
    /// Files in the backup.
    pub files: Vec<BackupFile>,
}

/// Creates, lists and prunes backups under a root directory.
#[derive(Clone, Debug)]
pub struct BackupManager {
    /// Backups root directory.
    pub root: PathBuf,
    /// Number of backups to keep.
    pub keep: usize,
}

/// Returns true if `bytes` is not a binary keyring (i.e. plaintext).
pub fn is_plaintext_keyring(bytes: &[u8]) -> bool {
    !bytes.starts_with(KEYRING_MAGIC)
}

/// Lists all `*.keyring` files plus `default` in `dir`, sorted.
///
/// A missing directory yields an empty list.
pub fn keyring_backup_set(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| io_err(dir, e))? {
        let path = entry.map_err(|e| io_err(dir, e))?.path();
        let is_keyring = path.extension().is_some_and(|e| e == KEYRING_EXT);
        let is_default = path.file_name().is_some_and(|n| n == "default");
        if path.is_file() && (is_keyring || is_default) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Builds an I/O error carrying the path.
fn io_err(path: &Path, e: impl std::fmt::Display) -> KringError {
    KringError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    }
}

/// Keeps only `[a-z0-9-]` of the lowercased reason.
fn sanitize_reason(reason: &str) -> String {
    reason
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
        .collect()
}

/// Creates a directory (and parents) with mode 0700.
fn mkdir_private(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| io_err(path, e))
}

/// Writes a file with mode 0600, failing if it already exists.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| io_err(path, e))?;
    f.write_all(bytes).map_err(|e| io_err(path, e))
}

/// Encrypts `plain` with an age scrypt passphrase.
fn encrypt_age(plain: &[u8], passphrase: &SecretString, path: &Path) -> Result<Vec<u8>> {
    let encryptor = age::Encryptor::with_user_passphrase(passphrase.clone());
    let mut out = Vec::new();
    let mut w = encryptor
        .wrap_output(&mut out)
        .map_err(|e| io_err(path, e))?;
    w.write_all(plain).map_err(|e| io_err(path, e))?;
    w.finish().map_err(|e| io_err(path, e))?;
    Ok(out)
}

/// Reads the manifest of a backup directory, if valid.
fn read_manifest(dir: &Path) -> Option<BackupInfo> {
    let bytes = fs::read(dir.join(MANIFEST_NAME)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

impl BackupManager {
    /// Creates a backup of `files`, encrypting plaintext keyrings with `passphrase`.
    ///
    /// Nothing is written if a source is missing or a passphrase is needed but absent.
    /// The backup is written to a temporary directory and renamed when complete.
    pub fn create(
        &self,
        reason: &str,
        files: &[PathBuf],
        passphrase: Option<&SecretValue>,
    ) -> Result<BackupInfo> {
        // Read everything and validate before touching the filesystem.
        let mut sources = Vec::new();
        for path in files {
            let bytes = fs::read(path).map_err(|e| io_err(path, e))?;
            let is_keyring = path.extension().is_some_and(|e| e == KEYRING_EXT);
            sources.push((path, is_keyring && is_plaintext_keyring(&bytes), bytes));
        }
        let secret = if sources.iter().any(|s| s.1) {
            let pass = passphrase.ok_or(KringError::PassphraseRequired)?;
            let text = pass
                .as_text()
                .ok_or_else(|| KringError::InvalidInput("passphrase is not valid UTF-8".into()))?;
            Some(SecretString::from(text.to_string()))
        } else {
            None
        };

        let now = OffsetDateTime::now_utc();
        let fmt = parse_borrowed::<2>(DIR_TIME_FORMAT).map_err(|e| io_err(&self.root, e))?;
        let stamp = now.format(&fmt).map_err(|e| io_err(&self.root, e))?;
        let created = now.format(&Rfc3339).map_err(|e| io_err(&self.root, e))?;
        let reason = sanitize_reason(reason);

        mkdir_private(&self.root)?;
        let base = format!("{stamp}-{reason}");
        let mut final_dir = self.root.join(&base);
        let mut n = 2;
        while final_dir.exists() {
            final_dir = self.root.join(format!("{base}-{n}"));
            n += 1;
        }
        let mut tmp_name = final_dir.clone().into_os_string();
        tmp_name.push(TMP_SUFFIX);
        let tmp_dir = PathBuf::from(tmp_name);

        let info = self.write_backup(&tmp_dir, &final_dir, &reason, created, &sources, secret);
        let info = match info {
            Ok(info) => info,
            Err(e) => {
                let _ = fs::remove_dir_all(&tmp_dir);
                return Err(e);
            }
        };
        if let Err(e) = fs::rename(&tmp_dir, &final_dir) {
            let _ = fs::remove_dir_all(&tmp_dir);
            return Err(io_err(&final_dir, e));
        }
        self.prune()?;
        Ok(info)
    }

    /// Writes the files and manifest into `tmp_dir`; stored paths point into `final_dir`.
    fn write_backup(
        &self,
        tmp_dir: &Path,
        final_dir: &Path,
        reason: &str,
        created: String,
        sources: &[(&PathBuf, bool, Vec<u8>)],
        secret: Option<SecretString>,
    ) -> Result<BackupInfo> {
        mkdir_private(tmp_dir)?;
        let mut entries = Vec::new();
        for (path, encrypt, bytes) in sources {
            let name = path
                .file_name()
                .ok_or_else(|| KringError::InvalidInput(format!("bad path {}", path.display())))?
                .to_string_lossy()
                .into_owned();
            let (stored_name, data) = match (encrypt, &secret) {
                (true, Some(pass)) => (format!("{name}.age"), encrypt_age(bytes, pass, path)?),
                _ => (name, bytes.clone()),
            };
            write_private(&tmp_dir.join(&stored_name), &data)?;
            entries.push(BackupFile {
                original: (*path).clone(),
                stored: final_dir.join(&stored_name),
                sha256: hex::encode(Sha256::digest(bytes)),
                encrypted: *encrypt,
            });
        }
        let info = BackupInfo {
            dir: final_dir.to_path_buf(),
            reason: reason.to_string(),
            created,
            files: entries,
        };
        let json = serde_json::to_vec_pretty(&info)
            .map_err(|e| io_err(&tmp_dir.join(MANIFEST_NAME), e))?;
        write_private(&tmp_dir.join(MANIFEST_NAME), &json)?;
        Ok(info)
    }

    /// Returns backup directories that have a manifest, oldest first.
    fn backup_dirs(&self) -> Result<Vec<PathBuf>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut dirs = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|e| io_err(&self.root, e))? {
            let path = entry.map_err(|e| io_err(&self.root, e))?.path();
            let is_tmp = path.to_string_lossy().ends_with(TMP_SUFFIX);
            if path.is_dir() && !is_tmp && path.join(MANIFEST_NAME).is_file() {
                dirs.push(path);
            }
        }
        dirs.sort();
        Ok(dirs)
    }

    /// Removes the oldest backups beyond `keep`.
    fn prune(&self) -> Result<()> {
        let dirs = self.backup_dirs()?;
        let excess = dirs.len().saturating_sub(self.keep);
        for dir in dirs.iter().take(excess) {
            fs::remove_dir_all(dir).map_err(|e| io_err(dir, e))?;
        }
        Ok(())
    }

    /// Lists backups, newest first; directories without a valid manifest are ignored.
    pub fn list(&self) -> Result<Vec<BackupInfo>> {
        let mut out: Vec<BackupInfo> = self
            .backup_dirs()?
            .iter()
            .filter_map(|d| read_manifest(d))
            .collect();
        out.reverse();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    /// Builds a manager over a temp root plus a temp source dir.
    fn setup(keep: usize) -> (tempfile::TempDir, BackupManager, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir(&src).unwrap();
        let mgr = BackupManager {
            root: tmp.path().join("backups"),
            keep,
        };
        (tmp, mgr, src)
    }

    /// Writes a binary keyring file.
    fn binary_file(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        let mut b = KEYRING_MAGIC.to_vec();
        b.extend_from_slice(b"payload");
        fs::write(&p, b).unwrap();
        p
    }

    /// Backup dir and files have private modes.
    #[test]
    fn backup_dir_is_0700() {
        let (_t, mgr, src) = setup(20);
        let f = binary_file(&src, "a.keyring");
        let info = mgr.create("test", &[f], None).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&mgr.root), 0o700);
        assert_eq!(mode(&info.dir), 0o700);
        assert_eq!(mode(&info.files[0].stored), 0o600);
        assert_eq!(mode(&info.dir.join(MANIFEST_NAME)), 0o600);
    }

    /// Binary keyrings are stored verbatim.
    #[test]
    fn binary_keyring_copied_verbatim() {
        let (_t, mgr, src) = setup(20);
        let f = binary_file(&src, "a.keyring");
        let orig = fs::read(&f).unwrap();
        let info = mgr.create("Weird Reason!", &[f], None).unwrap();
        assert_eq!(info.reason, "weirdreason");
        assert!(!info.files[0].encrypted);
        assert_eq!(fs::read(&info.files[0].stored).unwrap(), orig);
        assert_eq!(info.files[0].sha256, hex::encode(Sha256::digest(&orig)));
        assert_eq!(mgr.list().unwrap(), vec![info]);
    }

    /// Plaintext without passphrase fails and writes nothing.
    #[test]
    fn plaintext_requires_passphrase() {
        let (_t, mgr, src) = setup(20);
        let bin = binary_file(&src, "a.keyring");
        let plain = src.join("b.keyring");
        fs::write(&plain, "[keyring]\ndisplay-name=x\n").unwrap();
        let err = mgr.create("t", &[bin, plain], None).unwrap_err();
        assert!(matches!(err, KringError::PassphraseRequired));
        let leftover = if mgr.root.exists() {
            fs::read_dir(&mgr.root).unwrap().count()
        } else {
            0
        };
        assert_eq!(leftover, 0);
    }

    /// Plaintext keyrings are age-encrypted and decrypt back.
    #[test]
    fn plaintext_encrypted_with_age() {
        let (_t, mgr, src) = setup(20);
        let plain = src.join("b.keyring");
        let original = b"[keyring]\ndisplay-name=x\n";
        fs::write(&plain, original).unwrap();
        let pass = SecretValue::from_text("hunter2");
        let info = mgr.create("t", &[plain], Some(&pass)).unwrap();
        let file = &info.files[0];
        assert!(file.encrypted);
        assert_eq!(file.stored.file_name().unwrap(), "b.keyring.age");
        assert_eq!(file.sha256, hex::encode(Sha256::digest(original)));

        let enc = fs::read(&file.stored).unwrap();
        let dec = age::Decryptor::new(&enc[..]).unwrap();
        let id = age::scrypt::Identity::new(SecretString::from("hunter2".to_string()));
        let mut r = dec.decrypt(std::iter::once(&id as _)).unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, original);
    }

    /// Non-UTF-8 passphrase is rejected before writing.
    #[test]
    fn non_utf8_passphrase_rejected() {
        let (_t, mgr, src) = setup(20);
        let plain = src.join("b.keyring");
        fs::write(&plain, "[keyring]\n").unwrap();
        let pass = SecretValue::new(vec![0xff, 0xfe], "application/octet-stream");
        let err = mgr.create("t", &[plain], Some(&pass)).unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
        assert!(!mgr.root.exists());
    }

    /// A missing source yields an Io error naming the path.
    #[test]
    fn missing_source_is_io_error() {
        let (_t, mgr, src) = setup(20);
        let missing = src.join("nope.keyring");
        match mgr.create("t", std::slice::from_ref(&missing), None) {
            Err(KringError::Io { path, .. }) => assert_eq!(path, missing),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Only the newest `keep` backups remain, even within the same second.
    #[test]
    fn prunes_to_keep() {
        let (_t, mgr, src) = setup(2);
        let f = binary_file(&src, "a.keyring");
        let first = mgr.create("t", std::slice::from_ref(&f), None).unwrap();
        let second = mgr.create("t", std::slice::from_ref(&f), None).unwrap();
        let third = mgr.create("t", &[f], None).unwrap();
        let listed = mgr.list().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].dir, third.dir);
        assert_eq!(listed[1].dir, second.dir);
        assert!(!first.dir.exists());
    }

    /// Dirs without a manifest are ignored and never pruned.
    #[test]
    fn list_ignores_dirs_without_manifest() {
        let (_t, mgr, src) = setup(1);
        let f = binary_file(&src, "a.keyring");
        mgr.create("t", &[f], None).unwrap();
        let junk = mgr.root.join("junk");
        fs::create_dir(&junk).unwrap();
        assert_eq!(mgr.list().unwrap().len(), 1);
        assert!(junk.exists());
    }

    /// The backup set has keyring files and default, sorted; missing dir is empty.
    #[test]
    fn backup_set_selects_keyrings_and_default() {
        let (_t, _mgr, src) = setup(1);
        for n in ["b.keyring", "a.keyring", "default", "other.txt"] {
            fs::write(src.join(n), "x").unwrap();
        }
        let set = keyring_backup_set(&src).unwrap();
        let names: Vec<_> = set
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["a.keyring", "b.keyring", "default"]);
        assert!(keyring_backup_set(&src.join("missing")).unwrap().is_empty());
    }

    /// Magic detection.
    #[test]
    fn plaintext_detection() {
        assert!(!is_plaintext_keyring(KEYRING_MAGIC));
        assert!(is_plaintext_keyring(b"[keyring]"));
    }
}
