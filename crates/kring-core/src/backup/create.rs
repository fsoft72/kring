//! Creation, listing and pruning of backups.

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
    /// Backup directories removed by the pruning that followed this backup.
    #[serde(skip)]
    pub pruned: Vec<PathBuf>,
}

/// One file to back up, with an explicit sensitivity flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupSource {
    /// File to back up.
    pub path: PathBuf,
    /// True when the content is secret in clear (e.g. an unencrypted private
    /// key): the stored copy is then always age-encrypted.
    pub sensitive: bool,
}

impl BackupSource {
    /// A file stored verbatim, except a plaintext `*.keyring` (no binary magic), which is age-encrypted.
    pub fn plain(path: PathBuf) -> Self {
        Self {
            path,
            sensitive: false,
        }
    }

    /// A file whose stored copy is always age-encrypted.
    pub fn sensitive(path: PathBuf) -> Self {
        Self {
            path,
            sensitive: true,
        }
    }
}

/// One in-memory content to back up (never written to disk in clear).
///
/// Used for data that has no file of its own, such as a gpg key export. The
/// backup manifest records `original` as the source path; since that path is
/// not a real file, the backup counts as holding the only copy and is never
/// pruned (see [`BackupManager::prune_into`]).
#[derive(Clone, Debug)]
pub struct MemoryEntry {
    /// File name of the copy in the backup (a plain name, e.g. `<fpr>.secret.asc`).
    pub name: String,
    /// Informational source path recorded in the manifest (must be unique per backup).
    pub original: PathBuf,
    /// Content to back up.
    pub bytes: Zeroizing<Vec<u8>>,
    /// True when the content is secret in clear: the stored copy is then
    /// always age-encrypted.
    pub sensitive: bool,
}

/// One content ready to be written into a backup.
struct Prepared {
    /// Source path recorded in the manifest.
    original: PathBuf,
    /// File name of the copy (before the `.age` suffix).
    name: String,
    /// Whether the copy is age-encrypted.
    encrypt: bool,
    /// Content.
    bytes: Zeroizing<Vec<u8>>,
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
pub(crate) fn io_err(path: &Path, e: impl std::fmt::Display) -> KringError {
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
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| io_err(path, e))?;
    f.write_all(bytes).map_err(|e| io_err(path, e))
}

/// scrypt work factor (log2 N) used for every age file kring writes.
///
/// Fixed instead of age's per-machine calibration: calibration measured under
/// load (or on a slower machine) could pick a lower limit at decryption than
/// the factor used at encryption, and age then refuses the file.
pub(crate) const SCRYPT_WORK_FACTOR: u8 = 18;

/// Highest scrypt work factor accepted when decrypting (age's usual ceiling),
/// so files written by kring or by age elsewhere always decrypt.
pub(crate) const SCRYPT_MAX_WORK_FACTOR: u8 = 22;
const _: () = assert!(SCRYPT_MAX_WORK_FACTOR >= SCRYPT_WORK_FACTOR);

/// Builds the age scrypt identity used to decrypt kring files, with a fixed
/// maximum work factor instead of one calibrated on the current machine load.
pub(crate) fn age_identity(passphrase: SecretString) -> age::scrypt::Identity {
    let mut identity = age::scrypt::Identity::new(passphrase);
    identity.set_max_work_factor(SCRYPT_MAX_WORK_FACTOR);
    identity
}

/// Encrypts `plain` with an age scrypt passphrase at [`SCRYPT_WORK_FACTOR`].
pub(crate) fn encrypt_age(plain: &[u8], passphrase: &SecretString, path: &Path) -> Result<Vec<u8>> {
    let mut recipient = age::scrypt::Recipient::new(passphrase.clone());
    recipient.set_work_factor(SCRYPT_WORK_FACTOR);
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|e| io_err(path, e))?;
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

/// Returns true when a backup may hold the only copy of some data: one of its
/// originals no longer exists (or cannot be checked), e.g. a retired plaintext
/// file or the file of a deleted collection. Such backups are never pruned.
fn is_pinned(info: &BackupInfo) -> bool {
    info.files
        .iter()
        .any(|f| fs::symlink_metadata(&f.original).is_err())
}

/// Refuses memory entries whose names are not plain, distinct file names, or
/// whose originals are not distinct.
fn check_memory_entries(entries: &[MemoryEntry]) -> Result<()> {
    for (i, entry) in entries.iter().enumerate() {
        let name = entry.name.as_str();
        let plain = !name.is_empty()
            && name != "."
            && name != ".."
            && name != MANIFEST_NAME
            && !name.contains('/')
            && !name.contains('\0');
        if !plain {
            return Err(KringError::InvalidInput(format!(
                "Invalid backup entry name {name:?}"
            )));
        }
        let rest = &entries[i + 1..];
        if rest
            .iter()
            .any(|e| e.name == entry.name || e.original == entry.original)
        {
            return Err(KringError::InvalidInput(format!(
                "Duplicate backup entry {name:?}"
            )));
        }
    }
    Ok(())
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
    /// A `*.keyring` file without the binary magic is plaintext and stored
    /// age-encrypted; every other file is stored verbatim (use
    /// [`BackupManager::create_with`] to mark other files as sensitive).
    ///
    /// Nothing is written if a source is missing or a passphrase is needed but absent.
    /// The backup is written to a temporary directory and renamed when complete.
    /// Old backups are then pruned (see [`BackupManager::prune_into`]): the
    /// removed directories are listed in [`BackupInfo::pruned`], and a failure
    /// is reported in [`BackupInfo::prune_warning`] without failing the call.
    pub fn create(
        &self,
        reason: &str,
        files: &[PathBuf],
        passphrase: Option<&SecretValue>,
    ) -> Result<BackupInfo> {
        let mut info = self.create_unpruned(reason, files, passphrase)?;
        self.prune_into(&[], &mut info);
        Ok(info)
    }

    /// Like [`BackupManager::create`], with an explicit sensitivity flag per file.
    ///
    /// A sensitive source is always age-encrypted with `passphrase`; any other
    /// source follows the `.keyring` plaintext rule of [`BackupManager::create`].
    /// A sensitive or plaintext source without a passphrase fails with
    /// `PassphraseRequired` before anything is written. The manifest marks
    /// every encrypted copy with `encrypted: true`.
    pub fn create_with(
        &self,
        reason: &str,
        files: &[BackupSource],
        passphrase: Option<&SecretValue>,
    ) -> Result<BackupInfo> {
        let mut info = self.create_sources_unpruned(reason, files, passphrase)?;
        self.prune_into(&[], &mut info);
        Ok(info)
    }

    /// Creates a backup of in-memory `entries`, pruning old backups afterwards.
    ///
    /// Sensitive entries are age-encrypted with `passphrase` (missing:
    /// `PassphraseRequired`, before anything is written); other entries are
    /// stored verbatim. Entry names must be plain, distinct file names (not
    /// the manifest name) and originals distinct, else `InvalidInput`. Nothing
    /// is ever written in clear outside the stored copies of non-sensitive entries.
    pub fn create_from_memory(
        &self,
        reason: &str,
        entries: &[MemoryEntry],
        passphrase: Option<&SecretValue>,
    ) -> Result<BackupInfo> {
        check_memory_entries(entries)?;
        let prepared = entries
            .iter()
            .map(|e| Prepared {
                original: e.original.clone(),
                name: e.name.clone(),
                encrypt: e.sensitive,
                bytes: e.bytes.clone(),
            })
            .collect();
        let mut info = self.create_prepared(reason, prepared, passphrase)?;
        self.prune_into(&[], &mut info);
        Ok(info)
    }

    /// Like [`BackupManager::create`], but never prunes old backups.
    pub(crate) fn create_unpruned(
        &self,
        reason: &str,
        files: &[PathBuf],
        passphrase: Option<&SecretValue>,
    ) -> Result<BackupInfo> {
        let sources: Vec<BackupSource> = files.iter().cloned().map(BackupSource::plain).collect();
        self.create_sources_unpruned(reason, &sources, passphrase)
    }

    /// Writes one backup of `files` without pruning (shared by the file `create*` methods).
    fn create_sources_unpruned(
        &self,
        reason: &str,
        files: &[BackupSource],
        passphrase: Option<&SecretValue>,
    ) -> Result<BackupInfo> {
        // Read everything and validate before touching the filesystem.
        let mut prepared = Vec::new();
        for source in files {
            let path = &source.path;
            let bytes = Zeroizing::new(fs::read(path).map_err(|e| io_err(path, e))?);
            let is_keyring = path.extension().is_some_and(|e| e == KEYRING_EXT);
            let encrypt = source.sensitive || (is_keyring && is_plaintext_keyring(&bytes));
            let name = path
                .file_name()
                .ok_or_else(|| KringError::InvalidInput(format!("bad path {}", path.display())))?
                .to_string_lossy()
                .into_owned();
            prepared.push(Prepared {
                original: path.clone(),
                name,
                encrypt,
                bytes,
            });
        }
        self.create_prepared(reason, prepared, passphrase)
    }

    /// Writes one backup of prepared contents without pruning.
    fn create_prepared(
        &self,
        reason: &str,
        sources: Vec<Prepared>,
        passphrase: Option<&SecretValue>,
    ) -> Result<BackupInfo> {
        let secret = if sources.iter().any(|s| s.encrypt) {
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
        Ok(info)
    }

    /// Prunes old backups (sparing `exempt`) and records the outcome on `info`.
    ///
    /// Removed directories go to [`BackupInfo::pruned`]; a failure goes to
    /// [`BackupInfo::prune_warning`].
    pub(crate) fn prune_into(&self, exempt: &[PathBuf], info: &mut BackupInfo) {
        if let Err(e) = self.prune(exempt, &mut info.pruned) {
            info.prune_warning = Some(e.to_string());
        }
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
        sources: &[Prepared],
        secret: Option<SecretString>,
    ) -> Result<BackupInfo> {
        mkdir_private(tmp_dir)?;
        let mut entries = Vec::new();
        for source in sources {
            let (stored_name, encrypted) = match (source.encrypt, &secret) {
                (true, Some(pass)) => (
                    format!("{}.age", source.name),
                    Some(encrypt_age(&source.bytes, pass, &source.original)?),
                ),
                _ => (source.name.clone(), None),
            };
            // Binary keyrings are written straight from the zeroized source buffer.
            let data: &[u8] = encrypted.as_deref().unwrap_or(&source.bytes);
            write_private(&tmp_dir.join(&stored_name), data)?;
            entries.push(BackupFile {
                original: source.original.clone(),
                stored: final_dir.join(&stored_name),
                sha256: hex::encode(Sha256::digest(source.bytes.as_slice())),
                encrypted: source.encrypt,
            });
        }
        let info = BackupInfo {
            dir: final_dir.to_path_buf(),
            reason: header.reason.to_string(),
            created: header.created,
            files: entries,
            seq: header.seq,
            prune_warning: None,
            pruned: Vec::new(),
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
    /// are never pruned. `BackupInfo::dir` is the directory actually scanned.
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
            let Some(mut info) = read_manifest(&path) else {
                continue;
            };
            // The directory is where the manifest was found, never what it claims.
            info.dir = path.clone();
            let Ok(created) = OffsetDateTime::parse(&info.created, &Rfc3339) else {
                continue;
            };
            found.push((created, path, info));
        }
        found.sort_by_key(|(created, _, info)| (*created, info.seq));
        Ok(found.into_iter().map(|(_, p, i)| (p, i)).collect())
    }

    /// Removes the oldest prunable backups beyond `keep`, pushing each removed dir to `removed`.
    ///
    /// Pinned backups (see [`is_pinned`]) and `exempt` directories are never
    /// removed and do not count toward `keep`.
    fn prune(&self, exempt: &[PathBuf], removed: &mut Vec<PathBuf>) -> Result<()> {
        let prunable: Vec<PathBuf> = self
            .backups()?
            .into_iter()
            .filter(|(dir, info)| !exempt.contains(dir) && !is_pinned(info))
            .map(|(dir, _)| dir)
            .collect();
        let excess = prunable.len().saturating_sub(self.keep);
        for dir in prunable.into_iter().take(excess) {
            fs::remove_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
            removed.push(dir);
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
        let id = age_identity(SecretString::from("hunter2".to_string()));
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
            pruned: Vec::new(),
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
        let mut removed = Vec::new();
        mgr.prune(&[], &mut removed).unwrap();
        assert!(newest.exists());
        assert_eq!(removed.len(), 3);
        for gone in [oldest, middle, earlier] {
            assert!(!gone.exists(), "{}", gone.display());
        }
    }

    /// Backups whose original file is gone (retired, deleted) are never pruned
    /// and do not count toward `keep`.
    #[test]
    fn backups_of_missing_originals_are_pinned() {
        let (_t, mgr, src) = setup(20);
        let retired = src.join("old.keyring");
        fs::write(&retired, "[keyring]\n").unwrap();
        let pass = SecretValue::from_text("hunter2");
        let pinned = mgr.create(
            "retire-plaintext",
            std::slice::from_ref(&retired),
            Some(&pass),
        );
        let pinned = pinned.unwrap();
        fs::remove_file(&retired).unwrap();
        let f = binary_file(&src, "a.keyring");
        let mut first_seq = None;
        for _ in 0..25 {
            let info = mgr.create("t", std::slice::from_ref(&f), None).unwrap();
            first_seq.get_or_insert(info.seq);
        }
        let listed = mgr.list().unwrap();
        assert_eq!(listed.len(), 21);
        assert_eq!(listed.last().unwrap().seq, pinned.seq);
        assert!(pinned.dir.join(MANIFEST_NAME).exists());
        // Names can be reused within a second, so the oldest is checked by seq.
        assert!(listed.iter().all(|i| Some(i.seq) != first_seq));
    }

    /// The directories removed by pruning are reported on the new backup.
    #[test]
    fn pruned_dirs_are_reported() {
        let (_t, mgr, src) = setup(2);
        let f = binary_file(&src, "a.keyring");
        let first = mgr.create("t", std::slice::from_ref(&f), None).unwrap();
        let second = mgr.create("t", std::slice::from_ref(&f), None).unwrap();
        assert!(first.pruned.is_empty() && second.pruned.is_empty());
        let third = mgr.create("t", &[f], None).unwrap();
        assert_eq!(third.pruned, [first.dir]);
    }

    /// Exempt directories are neither removed nor counted.
    #[test]
    fn exempt_dirs_survive_prune() {
        let (_t, mgr, src) = setup(1);
        let f = binary_file(&src, "a.keyring");
        let first = mgr
            .create_unpruned("t", std::slice::from_ref(&f), None)
            .unwrap();
        let second = mgr
            .create_unpruned("t", std::slice::from_ref(&f), None)
            .unwrap();
        let third = mgr.create_unpruned("t", &[f], None).unwrap();
        let mut removed = Vec::new();
        mgr.prune(std::slice::from_ref(&first.dir), &mut removed)
            .unwrap();
        assert_eq!(removed, [second.dir]);
        assert!(first.dir.exists() && third.dir.exists());
    }

    /// A manifest claiming another directory is listed under its real one.
    #[test]
    fn list_uses_real_dir_not_manifest_dir() {
        let (_t, mgr, _src) = setup(20);
        let real = fake_backup(&mgr, "20261115-100000-r", "2026-11-15T10:00:00Z", 1);
        let mut info = read_manifest(&real).unwrap();
        info.dir = PathBuf::from("/elsewhere");
        fs::write(real.join(MANIFEST_NAME), serde_json::to_vec(&info).unwrap()).unwrap();
        assert_eq!(mgr.list().unwrap()[0].dir, real);
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

    /// A sensitive file is age-encrypted even without the `.keyring` extension.
    #[test]
    fn sensitive_file_is_encrypted() {
        let (_t, mgr, src) = setup(20);
        let key = src.join("id_test");
        let original = b"-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n";
        fs::write(&key, original).unwrap();
        let public = src.join("id_test.pub");
        fs::write(&public, b"ssh-ed25519 AAAA test\n").unwrap();
        let pass = SecretValue::from_text("hunter2");
        let sources = [
            BackupSource::sensitive(key.clone()),
            BackupSource::plain(public.clone()),
        ];
        let info = mgr.create_with("t", &sources, Some(&pass)).unwrap();
        let (k, p) = (&info.files[0], &info.files[1]);
        assert!(k.encrypted && !p.encrypted);
        assert_eq!(k.stored.file_name().unwrap(), "id_test.age");
        assert_eq!(k.sha256, hex::encode(Sha256::digest(original)));
        assert_eq!(fs::read(&p.stored).unwrap(), fs::read(&public).unwrap());
        let enc = fs::read(&k.stored).unwrap();
        assert!(!enc.windows(6).any(|w| w == b"secret"));
        let dec = age::Decryptor::new(&enc[..]).unwrap();
        let id = age_identity(SecretString::from("hunter2".to_string()));
        let mut r = dec.decrypt(std::iter::once(&id as _)).unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, original);
        assert_eq!(mgr.list().unwrap(), vec![info]);
    }

    /// A sensitive file without a passphrase fails and writes nothing.
    #[test]
    fn sensitive_requires_passphrase() {
        let (_t, mgr, src) = setup(20);
        let key = src.join("id_test");
        fs::write(&key, b"secret").unwrap();
        let err = mgr
            .create_with("t", &[BackupSource::sensitive(key)], None)
            .unwrap_err();
        assert!(matches!(err, KringError::PassphraseRequired));
        assert!(!mgr.root.exists());
    }

    /// Non-sensitive sources keep the `.keyring` plaintext rule of `create`.
    #[test]
    fn plain_sources_keep_keyring_rule() {
        let (_t, mgr, src) = setup(20);
        let bin = binary_file(&src, "a.keyring");
        let plain = src.join("b.keyring");
        fs::write(&plain, "[keyring]\n").unwrap();
        let other = src.join("notes");
        fs::write(&other, "[keyring]\n").unwrap();
        let pass = SecretValue::from_text("hunter2");
        let sources = [
            BackupSource::plain(bin),
            BackupSource::plain(plain),
            BackupSource::plain(other),
        ];
        let info = mgr.create_with("t", &sources, Some(&pass)).unwrap();
        let flags: Vec<bool> = info.files.iter().map(|f| f.encrypted).collect();
        assert_eq!(flags, [false, true, false]);
    }

    /// A memory entry named `name` with `bytes`, its original below `/nonexistent`.
    fn memory(name: &str, bytes: &[u8], sensitive: bool) -> MemoryEntry {
        MemoryEntry {
            name: name.into(),
            original: PathBuf::from("/nonexistent/kring-test").join(name),
            bytes: Zeroizing::new(bytes.to_vec()),
            sensitive,
        }
    }

    /// Memory entries are stored like files: sensitive ones age-encrypted, others verbatim.
    #[test]
    fn memory_entries_are_backed_up() {
        let (_t, mgr, _src) = setup(20);
        let secret = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nsecret\n";
        let entries = [
            memory("k.public.asc", b"public", false),
            memory("k.secret.asc", secret, true),
        ];
        let pass = SecretValue::from_text("hunter2");
        let info = mgr
            .create_from_memory("delete-gpg-key", &entries, Some(&pass))
            .unwrap();
        assert_eq!(info.reason, "delete-gpg-key");
        let (p, k) = (&info.files[0], &info.files[1]);
        assert_eq!(p.original, entries[0].original);
        assert!(!p.encrypted && k.encrypted);
        assert_eq!(fs::read(&p.stored).unwrap(), b"public");
        assert_eq!(k.stored.file_name().unwrap(), "k.secret.asc.age");
        assert_eq!(k.sha256, hex::encode(Sha256::digest(secret)));
        let stored = fs::read(&k.stored).unwrap();
        assert!(!stored.windows(6).any(|w| w == b"secret"));
        let got = crate::backup::read_backup_file(&info, k, Some(&pass)).unwrap();
        assert_eq!(got.as_slice(), secret);
        assert_eq!(mgr.list().unwrap(), vec![info]);
    }

    /// A sensitive memory entry without a passphrase fails and writes nothing.
    #[test]
    fn memory_sensitive_requires_passphrase() {
        let (_t, mgr, _src) = setup(20);
        let entries = [memory("k.secret.asc", b"secret", true)];
        let err = mgr.create_from_memory("t", &entries, None).unwrap_err();
        assert!(matches!(err, KringError::PassphraseRequired));
        assert!(!mgr.root.exists());
    }

    /// Bad or duplicate entry names and duplicate originals are refused before writing.
    #[test]
    fn memory_entry_names_are_checked() {
        let (_t, mgr, _src) = setup(20);
        for bad in ["", ".", "..", "a/b", MANIFEST_NAME, "a\0b"] {
            let r = mgr.create_from_memory("t", &[memory(bad, b"x", false)], None);
            assert!(matches!(r, Err(KringError::InvalidInput(_))), "{bad:?}");
        }
        let twice = [memory("a", b"x", false), memory("a", b"y", false)];
        let r = mgr.create_from_memory("t", &twice, None);
        assert!(matches!(r, Err(KringError::InvalidInput(_))));
        let mut same_original = [memory("a", b"x", false), memory("b", b"y", false)];
        same_original[1].original = same_original[0].original.clone();
        let r = mgr.create_from_memory("t", &same_original, None);
        assert!(matches!(r, Err(KringError::InvalidInput(_))));
        assert!(!mgr.root.exists());
    }

    /// Memory backups have no real original, so they are pinned and never pruned.
    #[test]
    fn memory_backups_are_pinned() {
        let (_t, mgr, src) = setup(1);
        let pinned = mgr
            .create_from_memory("t", &[memory("k.public.asc", b"public", false)], None)
            .unwrap();
        let f = binary_file(&src, "a.keyring");
        for _ in 0..3 {
            mgr.create("t", std::slice::from_ref(&f), None).unwrap();
        }
        assert!(pinned.dir.join(MANIFEST_NAME).exists());
        assert_eq!(mgr.list().unwrap().len(), 2);
    }

    /// Magic detection.
    #[test]
    fn plaintext_detection() {
        assert!(!is_plaintext_keyring(KEYRING_MAGIC));
        assert!(is_plaintext_keyring(b"[keyring]"));
    }
    /// Every age file uses the fixed work factor, so decryption never depends
    /// on how fast or loaded the machine is.
    #[test]
    fn age_files_use_fixed_work_factor() {
        let pass = SecretString::from("hunter2".to_string());
        let enc = encrypt_age(b"plain", &pass, Path::new("x")).unwrap();
        let header = String::from_utf8_lossy(&enc[..enc.len().min(200)]).to_string();
        let stanza = header
            .lines()
            .find(|l| l.starts_with("-> scrypt "))
            .unwrap();
        assert_eq!(
            stanza.split(' ').nth(3),
            Some(SCRYPT_WORK_FACTOR.to_string().as_str())
        );
    }
}
