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
use zeroize::Zeroizing;

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
    /// Creation counter, one more than the highest existing backup; orders
    /// backups made within the same `created` instant (0 in older manifests).
    #[serde(default)]
    pub seq: u32,
    /// Set when the backup was written but older backups could not be pruned.
    #[serde(skip)]
    pub prune_warning: Option<String>,
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

/// Manifest header fields of a backup being written.
struct Header<'a> {
    /// Sanitized reason.
    reason: &'a str,
    /// Creation time, RFC 3339 UTC.
    created: String,
    /// Creation counter.
    seq: u32,
}

impl BackupManager {
    /// Creates a backup of `files`, encrypting plaintext keyrings with `passphrase`.
    ///
    /// Nothing is written if a source is missing or a passphrase is needed but absent.
    /// The backup is written to a temporary directory and renamed when complete.
    /// Pruning old backups is best-effort: a failure is reported in
    /// [`BackupInfo::prune_warning`] and does not fail the call.
    pub fn create(
        &self,
        reason: &str,
        files: &[PathBuf],
        passphrase: Option<&SecretValue>,
    ) -> Result<BackupInfo> {
        // Read everything and validate before touching the filesystem.
        let mut sources = Vec::new();
        for path in files {
            let bytes = Zeroizing::new(fs::read(path).map_err(|e| io_err(path, e))?);
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
        let seq = self.next_seq()?;
        let mut tmp_name = final_dir.clone().into_os_string();
        tmp_name.push(TMP_SUFFIX);
        let tmp_dir = PathBuf::from(tmp_name);

        let header = Header {
            reason: &reason,
            created,
            seq,
        };
        let info = self.write_backup(&tmp_dir, &final_dir, header, &sources, secret);
        let mut info = match info {
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
        if let Err(e) = self.prune() {
            info.prune_warning = Some(e.to_string());
        }
        Ok(info)
    }

    /// Returns the seq for a new backup: one more than the highest existing one.
    fn next_seq(&self) -> Result<u32> {
        let max = self.backups()?.iter().map(|(_, i)| i.seq).max();
        Ok(max.map_or(1, |m| m.saturating_add(1)))
    }

    /// Writes the files and manifest into `tmp_dir`; stored paths point into `final_dir`.
    fn write_backup(
        &self,
        tmp_dir: &Path,
        final_dir: &Path,
        header: Header<'_>,
        sources: &[(&PathBuf, bool, Zeroizing<Vec<u8>>)],
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
            let (stored_name, encrypted) = match (encrypt, &secret) {
                (true, Some(pass)) => {
                    (format!("{name}.age"), Some(encrypt_age(bytes, pass, path)?))
                }
                _ => (name, None),
            };
            // Binary keyrings are written straight from the zeroized source buffer.
            let data: &[u8] = encrypted.as_deref().unwrap_or(bytes);
            write_private(&tmp_dir.join(&stored_name), data)?;
            entries.push(BackupFile {
                original: (*path).clone(),
                stored: final_dir.join(&stored_name),
                sha256: hex::encode(Sha256::digest(bytes.as_slice())),
                encrypted: *encrypt,
            });
        }
        let info = BackupInfo {
            dir: final_dir.to_path_buf(),
            reason: header.reason.to_string(),
            created: header.created,
            files: entries,
            seq: header.seq,
            prune_warning: None,
        };
        let json = serde_json::to_vec_pretty(&info)
            .map_err(|e| io_err(&tmp_dir.join(MANIFEST_NAME), e))?;
        write_private(&tmp_dir.join(MANIFEST_NAME), &json)?;
        Ok(info)
    }

    /// Returns backup directories with a valid manifest, oldest first.
    ///
    /// Order is the manifest `created` instant, then `seq` (never the dir name,
    /// whose reason suffix would reorder backups made within the same second).
    /// Directories without a valid manifest or timestamp are left out, so they
    /// are never pruned.
    fn backups(&self) -> Result<Vec<(PathBuf, BackupInfo)>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut found = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|e| io_err(&self.root, e))? {
            let path = entry.map_err(|e| io_err(&self.root, e))?.path();
            let is_tmp = path.to_string_lossy().ends_with(TMP_SUFFIX);
            if !path.is_dir() || is_tmp {
                continue;
            }
            let Some(info) = read_manifest(&path) else {
                continue;
            };
            let Ok(created) = OffsetDateTime::parse(&info.created, &Rfc3339) else {
                continue;
            };
            found.push((created, path, info));
        }
        found.sort_by_key(|(created, _, info)| (*created, info.seq));
        Ok(found.into_iter().map(|(_, p, i)| (p, i)).collect())
    }

    /// Removes the oldest backups beyond `keep`.
    fn prune(&self) -> Result<()> {
        let backups = self.backups()?;
        let excess = backups.len().saturating_sub(self.keep);
        for (dir, _) in backups.iter().take(excess) {
            fs::remove_dir_all(dir).map_err(|e| io_err(dir, e))?;
        }
        Ok(())
    }

    /// Lists backups, newest first; directories without a valid manifest are ignored.
    pub fn list(&self) -> Result<Vec<BackupInfo>> {
        let mut out: Vec<BackupInfo> = self.backups()?.into_iter().map(|(_, i)| i).collect();
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

    /// Backups made in a row with different reasons are pruned oldest-first.
    #[test]
    fn prunes_oldest_first_across_reasons() {
        let (_t, mgr, src) = setup(2);
        let f = binary_file(&src, "a.keyring");
        let first = mgr.create("zzz", std::slice::from_ref(&f), None).unwrap();
        let second = mgr.create("aaa", std::slice::from_ref(&f), None).unwrap();
        let third = mgr.create("mmm", &[f], None).unwrap();
        assert!(first.seq < second.seq && second.seq < third.seq);
        let listed: Vec<_> = mgr.list().unwrap().into_iter().map(|i| i.dir).collect();
        assert_eq!(listed, [third.dir, second.dir]);
        assert!(!first.dir.exists());
    }

    /// Writes a hand-made backup dir named `name` with the given manifest fields.
    fn fake_backup(mgr: &BackupManager, name: &str, created: &str, seq: u32) -> PathBuf {
        let dir = mgr.root.join(name);
        fs::create_dir_all(&dir).unwrap();
        let info = BackupInfo {
            dir: dir.clone(),
            reason: "r".into(),
            created: created.into(),
            files: vec![],
            seq,
            prune_warning: None,
        };
        fs::write(dir.join(MANIFEST_NAME), serde_json::to_vec(&info).unwrap()).unwrap();
        dir
    }

    /// Order comes from the manifest (created, then seq), not from the dir name.
    #[test]
    fn prune_orders_by_manifest_not_name() {
        let (_t, mgr, _src) = setup(1);
        let same = "2026-11-15T10:00:00Z";
        // Same second: the dir names sort opposite to the creation order.
        let oldest = fake_backup(&mgr, "20261115-100000-zzz", same, 1);
        let middle = fake_backup(&mgr, "20261115-100000-mmm", same, 2);
        let newest = fake_backup(&mgr, "20261115-100000-aaa", same, 3);
        // An earlier second always sorts first, whatever its seq.
        let earlier = fake_backup(&mgr, "20261115-095959-zzz", "2026-11-15T09:59:59.5Z", 9);
        mgr.prune().unwrap();
        assert!(newest.exists());
        for gone in [oldest, middle, earlier] {
            assert!(!gone.exists(), "{}", gone.display());
        }
    }

    /// Manifests without `seq` (older backups) still load, with seq 0.
    #[test]
    fn manifest_without_seq_defaults_to_zero() {
        let json = r#"{"dir":"/b/x","reason":"r","created":"2026-11-15T10:00:00Z","files":[]}"#;
        let info: BackupInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.seq, 0);
    }

    /// A prune failure keeps the new backup and reports a warning instead of failing.
    #[test]
    fn prune_failure_is_a_warning() {
        let (_t, mgr, src) = setup(1);
        let f = binary_file(&src, "a.keyring");
        let first = mgr.create("t", std::slice::from_ref(&f), None).unwrap();
        assert!(first.prune_warning.is_none());
        // Files inside a read-only directory cannot be unlinked, so pruning fails.
        fs::set_permissions(&first.dir, fs::Permissions::from_mode(0o500)).unwrap();
        let second = mgr.create("t", &[f], None);
        fs::set_permissions(&first.dir, fs::Permissions::from_mode(0o700)).unwrap();
        let second = second.unwrap();
        assert!(second.dir.is_dir());
        let warning = second.prune_warning.expect("prune warning expected");
        assert!(
            warning.contains(&first.dir.display().to_string()),
            "{warning}"
        );
        assert!(first.dir.exists());
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
