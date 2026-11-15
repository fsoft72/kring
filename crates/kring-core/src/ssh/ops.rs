//! Operations on SSH key files: generate, import, export, change passphrase, delete.
//!
//! Every file is read without following symlinks and with a size bound. New
//! files are written via a temporary sibling and hard linked into place, so an
//! existing file is never overwritten; only [`change_passphrase`] replaces a
//! private key (atomic rename, after a verified backup). Destructive
//! operations only act on a key exactly as [`scan_keys`] reports it now.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use super::scan::{MAX_KEY_FILE_BYTES, SshAlgorithm, SshKeyInfo, classify_private, scan_keys};
use crate::backup::{BackupInfo, BackupManager, BackupSource, io_err};
use crate::error::{KringError, Result};
use crate::keyring_file::retire::verify_backup_entry;
use crate::model::SecretValue;

/// Error message for a wrong key passphrase (shared with the UI, which reopens the dialog).
pub const MSG_WRONG_KEY_PASSPHRASE: &str = "Wrong key passphrase";
/// Error message for an encrypted key used without its passphrase.
pub const MSG_KEY_PASSPHRASE_REQUIRED: &str = "Key passphrase required";
/// File names in `~/.ssh` that are never SSH keys and never touched.
pub const RESERVED_NAMES: [&str; 7] = [
    "authorized_keys",
    "authorized_keys2",
    "known_hosts",
    "known_hosts.old",
    "config",
    "environment",
    "rc",
];
/// RSA modulus sizes offered for new keys.
pub const RSA_BITS: [u32; 2] = [3072, 4096];
/// Longest accepted key name (leaves room for `.pub` and temp suffixes).
const MAX_NAME_LEN: usize = 200;
/// Suffix of public key files.
const PUBLIC_SUFFIX: &str = ".pub";
/// Suffix of temporary files written by kring.
const TMP_SUFFIX: &str = ".kring-tmp";
/// Mode of private key files.
const PRIVATE_MODE: u32 = 0o600;
/// Mode of public key files.
const PUBLIC_MODE: u32 = 0o644;
/// Mode of a newly created key directory.
const DIR_MODE: u32 = 0o700;
/// Backup reason of [`delete_key`].
const DELETE_REASON: &str = "delete-ssh-key";
/// Backup reason of [`change_passphrase`].
const CHANGE_REASON: &str = "change-ssh-passphrase";
/// Message for an invalid key name.
const MSG_BAD_NAME: &str =
    "Invalid key name: use letters, digits, '.', '_' and '-' (not a reserved file name)";
/// Message for a target that is not a key listed in the directory.
const MSG_NOT_LISTED: &str = "Not an SSH key in the key directory";
/// Message for a key that changed since it was scanned.
const MSG_STALE: &str = "Key changed since scan, rescan first";
/// Message for an operation refused on a legacy-format key.
const MSG_LEGACY: &str = "Legacy PEM keys are read-only; convert with ssh-keygen first";
/// Message for removing a passphrase without explicit confirmation.
const MSG_CONFIRM_UNENCRYPTED: &str = "Removing the passphrase must be confirmed explicitly";
/// Message for an empty new passphrase.
const MSG_EMPTY_PASSPHRASE: &str = "Passphrase is empty";

/// Counter making temporary file names unique within the process.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A key to generate with [`generate_key`].
#[derive(Clone, Debug)]
pub struct NewKey {
    /// File name of the private key (see [`valid_key_name`]); the public key gets `.pub`.
    pub name: String,
    /// One of `Ed25519`, `EcdsaP256`, `EcdsaP384`, `Rsa`.
    pub algorithm: SshAlgorithm,
    /// RSA modulus size, one of [`RSA_BITS`]; ignored for other algorithms.
    pub rsa_bits: u32,
    /// Key comment (single line, may be empty).
    pub comment: String,
    /// Passphrase protecting the private key; `None` leaves it unencrypted.
    pub passphrase: Option<SecretValue>,
}

/// Returns true if `name` may be used as a key file name.
///
/// Allowed: 1 to 200 characters from `[A-Za-z0-9._-]`, not starting with `-`,
/// not `.` or `..`, not ending with `.pub` or kring's temp suffix, and not one
/// of [`RESERVED_NAMES`].
pub fn valid_key_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return false;
    }
    if name == "." || name == ".." || name.starts_with('-') {
        return false;
    }
    if name.ends_with(PUBLIC_SUFFIX) || name.ends_with(TMP_SUFFIX) {
        return false;
    }
    if RESERVED_NAMES.contains(&name) {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Generates a new key pair `<name>` (0600) and `<name>.pub` (0644) in `dir`.
///
/// The name must pass [`valid_key_name`] and neither file may exist. `dir` is
/// created (0700) when missing, its parent must exist. Randomness comes from
/// the operating system. With a passphrase the private key is encrypted in
/// the OpenSSH format (bcrypt KDF, AES-256-CTR); the comment is kept in the
/// `.pub` and inside the private key.
pub fn generate_key(dir: &Path, key: &NewKey) -> Result<SshKeyInfo> {
    check_new_name(dir, &key.name)?;
    check_comment(&key.comment)?;
    let passphrase = key.passphrase.as_ref().map(non_empty).transpose()?;
    let mut private = random_key(&key.algorithm, key.rsa_bits)?;
    private.set_comment(key.comment.as_str());
    let public_line = public_line(private.public_key())?;
    let private = match passphrase {
        Some(pass) => private.encrypt(&mut OsRng, pass).map_err(key_err)?,
        None => private,
    };
    let pem = private.to_openssh(LineEnding::LF).map_err(key_err)?;
    ensure_dir(dir)?;
    write_pair(dir, &key.name, pem.as_bytes(), public_line.as_bytes())?;
    find_key(dir, &key.name)
}

/// Imports the OpenSSH private key `source` into `dir` as `name` (default: the source file name).
///
/// The source must be a regular file (no symlink) that parses as an OpenSSH
/// private key; legacy PEM keys are refused. The private key is copied
/// verbatim (0600). The public key is `<source>.pub` when that file holds the
/// same key, else it is derived from the private key (0644). Existing files
/// in `dir` are never overwritten.
pub fn import_key(dir: &Path, source: &Path, name: Option<&str>) -> Result<SshKeyInfo> {
    let name = match name {
        Some(name) => name.to_string(),
        None => source
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid(MSG_BAD_NAME))?
            .to_string(),
    };
    check_new_name(dir, &name)?;
    let bytes = read_bounded(source)?;
    if classify(source, &bytes).is_some_and(|p| p.legacy) {
        return Err(invalid(MSG_LEGACY));
    }
    let private = parse_private(&bytes)?;
    let public_line = match sibling_public(source, private.public_key()) {
        Some(line) => line,
        None => public_line(private.public_key())?,
    };
    ensure_dir(dir)?;
    write_pair(dir, &name, &bytes, public_line.as_bytes())?;
    find_key(dir, &name)
}

/// Returns the public key of `info` as one OpenSSH line (no newline).
///
/// The `.pub` is used when it holds the same key as the private file (it
/// carries the comment); otherwise the public part of an OpenSSH private key
/// wins. A legacy key needs its `.pub`.
pub fn export_public(info: &SshKeyInfo) -> Result<String> {
    let from_private = match (&info.private_path, info.legacy_format) {
        (Some(path), false) => Some(parse_private(&read_bounded(path)?)?.public_key().clone()),
        _ => None,
    };
    let from_pub = match &info.public_path {
        Some(path) => Some(parse_public(&read_bounded(path)?)?),
        None => None,
    };
    let key = match (from_private, from_pub) {
        (Some(private), Some(public)) if public.key_data() == private.key_data() => public,
        (Some(private), _) => private,
        (None, Some(public)) => public,
        (None, None) => return Err(invalid("No public key available")),
    };
    key.to_openssh().map_err(key_err)
}

/// Writes a copy of the private key of `info` to `dest` (new file, 0600).
///
/// Without `new_passphrase` the file is copied verbatim (an encrypted key
/// stays encrypted with its current passphrase, `passphrase` is unused).
/// With `new_passphrase` the copy is encrypted with it: an encrypted key is
/// first decrypted with `passphrase` (missing: `MSG_KEY_PASSPHRASE_REQUIRED`,
/// wrong: `MSG_WRONG_KEY_PASSPHRASE`). Legacy keys and an existing `dest`
/// are refused.
pub fn export_private(
    info: &SshKeyInfo,
    dest: &Path,
    passphrase: Option<&SecretValue>,
    new_passphrase: Option<&SecretValue>,
) -> Result<()> {
    if info.legacy_format {
        return Err(invalid(MSG_LEGACY));
    }
    let path = info
        .private_path
        .as_ref()
        .ok_or_else(|| invalid("No private key"))?;
    if fs::symlink_metadata(dest).is_ok() {
        return Err(exists_err(dest));
    }
    let bytes = read_bounded(path)?;
    let key = parse_private(&bytes)?;
    let out = match new_passphrase {
        None => bytes,
        Some(new) => {
            let new = non_empty(new)?;
            let clear = decrypt_if_needed(&key, passphrase)?;
            let encrypted = clear.encrypt(&mut OsRng, new).map_err(key_err)?;
            let pem = encrypted.to_openssh(LineEnding::LF).map_err(key_err)?;
            Zeroizing::new(pem.as_bytes().to_vec())
        }
    };
    write_new(dest, &out, PRIVATE_MODE)
}

/// Changes (or removes) the passphrase of the private key of `info` in `dir`.
///
/// `info` must match the current scan of `dir` and be an OpenSSH key. The
/// old passphrase is checked first (missing: `MSG_KEY_PASSPHRASE_REQUIRED`,
/// wrong: `MSG_WRONG_KEY_PASSPHRASE`, nothing written). `new = None` removes
/// the encryption and is refused unless `allow_unencrypted` is set. Then the
/// current file is backed up (reason `change-ssh-passphrase`; an unencrypted
/// key is sensitive, so `backup_passphrase` is required and the copy is
/// age-encrypted), the manifest is verified, and the private file is replaced
/// atomically if it is still unchanged. The `.pub` is not modified.
pub fn change_passphrase(
    manager: &BackupManager,
    dir: &Path,
    info: &SshKeyInfo,
    old: Option<&SecretValue>,
    new: Option<&SecretValue>,
    allow_unencrypted: bool,
    backup_passphrase: Option<&SecretValue>,
) -> Result<BackupInfo> {
    if new.is_none() && !allow_unencrypted {
        return Err(invalid(MSG_CONFIRM_UNENCRYPTED));
    }
    if info.legacy_format {
        return Err(invalid(MSG_LEGACY));
    }
    let new = new.map(non_empty).transpose()?;
    check_target(dir, info)?;
    let path = info
        .private_path
        .as_ref()
        .ok_or_else(|| invalid("No private key"))?;
    let bytes = read_bounded(path)?;
    let key = parse_private(&bytes)?;
    if key.fingerprint(HashAlg::Sha256).to_string() != info.fingerprint {
        return Err(invalid(MSG_STALE));
    }
    if !key.is_encrypted() && new.is_none() {
        return Err(invalid("The key has no passphrase"));
    }
    let clear = decrypt_if_needed(&key, old)?;
    let replacement = match new {
        Some(pass) => clear.encrypt(&mut OsRng, pass).map_err(key_err)?,
        None => clear,
    };
    let pem = replacement.to_openssh(LineEnding::LF).map_err(key_err)?;

    let digest = sha256_hex(&bytes);
    let sensitive = !key.is_encrypted();
    let source = BackupSource {
        path: path.clone(),
        sensitive,
    };
    let backup = manager.create_with(CHANGE_REASON, &[source], backup_passphrase)?;
    verify_backup_entry(&backup, path, &digest, sensitive)?;
    check_unchanged(path, &digest)?;
    replace_file(path, pem.as_bytes())?;
    Ok(backup)
}

/// Deletes the key files of `info` in `dir` after a verified backup.
///
/// `info` must match the current scan of `dir`. The private and public files
/// are backed up together (reason `delete-ssh-key`); an unencrypted private
/// key (OpenSSH or legacy) is sensitive: `backup_passphrase` is then required
/// and the copy is age-encrypted. The files are removed only after the
/// manifest lists each with the sha256 of the bytes read before the backup
/// (encrypted when sensitive) and the files are still unchanged.
pub fn delete_key(
    manager: &BackupManager,
    dir: &Path,
    info: &SshKeyInfo,
    backup_passphrase: Option<&SecretValue>,
) -> Result<BackupInfo> {
    check_target(dir, info)?;
    // (path, sensitive, sha256 of the bytes read now)
    let mut files: Vec<(PathBuf, bool, String)> = Vec::new();
    if let Some(path) = &info.private_path {
        let bytes = read_bounded(path)?;
        let probe = classify(path, &bytes).ok_or_else(|| invalid(MSG_STALE))?;
        let fingerprint = probe
            .public
            .as_ref()
            .map(|k| k.fingerprint(HashAlg::Sha256).to_string());
        if probe.legacy != info.legacy_format || fingerprint.is_some_and(|f| f != info.fingerprint)
        {
            return Err(invalid(MSG_STALE));
        }
        files.push((path.clone(), !probe.encrypted, sha256_hex(&bytes)));
    }
    if let Some(path) = &info.public_path {
        let bytes = read_bounded(path)?;
        parse_public(&bytes)?;
        files.push((path.clone(), false, sha256_hex(&bytes)));
    }
    let sources: Vec<BackupSource> = files
        .iter()
        .map(|(path, sensitive, _)| BackupSource {
            path: path.clone(),
            sensitive: *sensitive,
        })
        .collect();
    let backup = manager.create_with(DELETE_REASON, &sources, backup_passphrase)?;
    for (path, sensitive, digest) in &files {
        verify_backup_entry(&backup, path, digest, *sensitive)?;
    }
    for (path, _, digest) in &files {
        check_unchanged(path, digest)?;
    }
    for (path, _, _) in &files {
        fs::remove_file(path).map_err(|e| io_err(path, e))?;
    }
    Ok(backup)
}

/// Builds an `InvalidInput` error.
fn invalid(msg: &str) -> KringError {
    KringError::InvalidInput(msg.to_string())
}

/// Error for a destination that already exists.
fn exists_err(path: &Path) -> KringError {
    KringError::InvalidInput(format!("{} already exists", path.display()))
}

/// Maps an `ssh-key` error that is not about a passphrase.
fn key_err(e: ssh_key::Error) -> KringError {
    KringError::InvalidInput(format!("SSH key error: {e}"))
}

/// Maps a decryption error: a failed integrity check means a wrong passphrase.
fn decrypt_err(e: ssh_key::Error) -> KringError {
    match e {
        // The checkints (or the AEAD tag) do not match: wrong passphrase.
        ssh_key::Error::Crypto => invalid(MSG_WRONG_KEY_PASSPHRASE),
        other => KringError::InvalidInput(format!("Cannot decrypt the key: {other}")),
    }
}

/// Hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Returns the passphrase bytes, refusing an empty passphrase.
fn non_empty(pass: &SecretValue) -> Result<&[u8]> {
    if pass.is_empty() {
        return Err(invalid(MSG_EMPTY_PASSPHRASE));
    }
    Ok(pass.as_bytes())
}

/// Refuses comments that would break the one-line `.pub` format.
fn check_comment(comment: &str) -> Result<()> {
    if comment.chars().any(char::is_control) {
        return Err(invalid("The comment must be a single line"));
    }
    Ok(())
}

/// Fails unless `name` is valid and neither `<name>` nor `<name>.pub` exists in `dir`.
fn check_new_name(dir: &Path, name: &str) -> Result<()> {
    if !valid_key_name(name) {
        return Err(invalid(MSG_BAD_NAME));
    }
    for path in [dir.join(name), public_path(dir, name)] {
        if fs::symlink_metadata(&path).is_ok() {
            return Err(exists_err(&path));
        }
    }
    Ok(())
}

/// Path of the public key file of `name` in `dir`.
fn public_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}{PUBLIC_SUFFIX}"))
}

/// Fails unless `info` is exactly what a scan of `dir` reports now for its name.
///
/// This confines every destructive operation to regular key files directly
/// inside `dir` (the scanner ignores symlinks and non-key files) and detects
/// a stale `info`. Reserved names are refused even if they hold a key.
fn check_target(dir: &Path, info: &SshKeyInfo) -> Result<()> {
    if RESERVED_NAMES.contains(&info.name.as_str()) {
        return Err(invalid(MSG_NOT_LISTED));
    }
    match scan_keys(dir)?.into_iter().find(|k| k.name == info.name) {
        Some(current) if current == *info => Ok(()),
        Some(_) => Err(invalid(MSG_STALE)),
        None => Err(invalid(MSG_NOT_LISTED)),
    }
}

/// Fails unless the file at `path` still has the sha256 `digest`.
fn check_unchanged(path: &Path, digest: &str) -> Result<()> {
    let bytes = read_bounded(path)?;
    if sha256_hex(&bytes) != digest {
        return Err(invalid(MSG_STALE));
    }
    Ok(())
}

/// Reads a key file: no symlink, regular file, at most 64 KiB.
fn read_bounded(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                return KringError::InvalidInput(format!("{} is a symbolic link", path.display()));
            }
            io_err(path, e)
        })?;
    let meta = file.metadata().map_err(|e| io_err(path, e))?;
    if !meta.is_file() {
        return Err(KringError::InvalidInput(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_err(path, e))?;
    if bytes.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(KringError::InvalidInput(format!(
            "{} is too large for a key file",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Classifies key bytes with the scanner rules; `None` when not a private key.
fn classify(path: &Path, bytes: &[u8]) -> Option<super::scan::PrivateProbe> {
    classify_private(path, std::str::from_utf8(bytes).ok()?)
}

/// Parses an OpenSSH private key.
fn parse_private(bytes: &[u8]) -> Result<PrivateKey> {
    PrivateKey::from_openssh(bytes).map_err(|_| invalid("Not an OpenSSH private key"))
}

/// Parses an OpenSSH public key line.
fn parse_public(bytes: &[u8]) -> Result<PublicKey> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("Not an OpenSSH public key"))?;
    PublicKey::from_openssh(text.trim()).map_err(|_| invalid("Not an OpenSSH public key"))
}

/// Returns `key` decrypted with `passphrase`, or a clone when it is not encrypted.
fn decrypt_if_needed(key: &PrivateKey, passphrase: Option<&SecretValue>) -> Result<PrivateKey> {
    if !key.is_encrypted() {
        return Ok(key.clone());
    }
    let pass = passphrase.ok_or_else(|| invalid(MSG_KEY_PASSPHRASE_REQUIRED))?;
    key.decrypt(pass.as_bytes()).map_err(decrypt_err)
}

/// The `.pub` file content (one line plus newline) for `key`.
fn public_line(key: &PublicKey) -> Result<String> {
    Ok(format!("{}\n", key.to_openssh().map_err(key_err)?))
}

/// The content of `<source>.pub` when it holds the same key as `public`.
fn sibling_public(source: &Path, public: &PublicKey) -> Option<String> {
    let mut name = source.file_name()?.to_os_string();
    name.push(PUBLIC_SUFFIX);
    let bytes = read_bounded(&source.with_file_name(name)).ok()?;
    let parsed = parse_public(&bytes).ok()?;
    if parsed.key_data() != public.key_data() {
        return None;
    }
    let text = std::str::from_utf8(&bytes).ok()?.trim();
    Some(format!("{text}\n"))
}

/// Generates an unencrypted key of a supported algorithm.
fn random_key(algorithm: &SshAlgorithm, rsa_bits: u32) -> Result<PrivateKey> {
    let ecdsa = |curve| Algorithm::Ecdsa { curve };
    let generated = match algorithm {
        SshAlgorithm::Ed25519 => PrivateKey::random(&mut OsRng, Algorithm::Ed25519),
        SshAlgorithm::EcdsaP256 => PrivateKey::random(&mut OsRng, ecdsa(EcdsaCurve::NistP256)),
        SshAlgorithm::EcdsaP384 => PrivateKey::random(&mut OsRng, ecdsa(EcdsaCurve::NistP384)),
        SshAlgorithm::Rsa => {
            if !RSA_BITS.contains(&rsa_bits) {
                return Err(invalid("RSA keys must have 3072 or 4096 bits"));
            }
            RsaKeypair::random(&mut OsRng, rsa_bits as usize)
                .and_then(|pair| PrivateKey::new(KeypairData::from(pair), ""))
        }
        other => {
            return Err(KringError::InvalidInput(format!(
                "Cannot generate {other:?} keys"
            )));
        }
    };
    generated.map_err(key_err)
}

/// Creates `dir` (mode 0700, parent must exist) unless it is already a directory.
fn ensure_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .mode(DIR_MODE)
        .create(dir)
        .map_err(|e| io_err(dir, e))
}

/// Writes `<name>` (0600) and `<name>.pub` (0644) as new files.
///
/// If the public file cannot be written, the private file just created is removed again.
fn write_pair(dir: &Path, name: &str, private: &[u8], public: &[u8]) -> Result<()> {
    let private_path = dir.join(name);
    write_new(&private_path, private, PRIVATE_MODE)?;
    if let Err(e) = write_new(&public_path(dir, name), public, PUBLIC_MODE) {
        let _ = fs::remove_file(&private_path);
        return Err(e);
    }
    Ok(())
}

/// Returns a unique temporary sibling path of `path`.
fn temp_sibling(path: &Path) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    path.with_file_name(format!(".{name}.{pid}-{n}{TMP_SUFFIX}"))
}

/// Creates `path` (must not exist) with exactly `mode`, writes `bytes` and syncs.
///
/// If writing fails after the file was created, it is removed again.
fn create_file(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    // The umask may have cleared bits of `mode`: set it exactly.
    let written = file
        .set_permissions(fs::Permissions::from_mode(mode))
        .and_then(|_| file.write_all(bytes))
        .and_then(|_| file.sync_all());
    if let Err(e) = written {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// Writes `bytes` to the new file `path` without ever overwriting an existing file.
///
/// The data goes to a temporary sibling first and is hard linked into place.
/// If the file system cannot hard link, `path` is written directly with
/// `create_new`.
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let tmp = temp_sibling(path);
    create_file(&tmp, bytes, mode).map_err(|e| io_err(&tmp, e))?;
    let linked = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    let fallback = match linked {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(exists_err(path)),
        Err(_) => create_file(path, bytes, mode),
    };
    match fallback {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(exists_err(path)),
        Err(e) => Err(io_err(path, e)),
    }
}

/// Replaces `path` atomically with `bytes` (0600) via a temporary sibling and rename.
fn replace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = temp_sibling(path);
    create_file(&tmp, bytes, PRIVATE_MODE).map_err(|e| io_err(&tmp, e))?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(io_err(path, e));
    }
    Ok(())
}

/// Finds the key `name` in a fresh scan of `dir`.
fn find_key(dir: &Path, name: &str) -> Result<SshKeyInfo> {
    scan_keys(dir)?
        .into_iter()
        .find(|k| k.name == name)
        .ok_or_else(|| invalid("The written key is not recognised by the scanner"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Key names follow the allowed alphabet and skip reserved and special names.
    #[test]
    fn key_name_validation() {
        for ok in ["id_ed25519", "work-key", "a.b_c-1", "x", ".hidden"] {
            assert!(valid_key_name(ok), "{ok}");
        }
        let long = "a".repeat(MAX_NAME_LEN + 1);
        let bad = [
            "",
            ".",
            "..",
            "-rf",
            "a/b",
            "../x",
            "a b",
            "naïve",
            "k.pub",
            "k.kring-tmp",
            &long,
        ];
        for name in bad {
            assert!(!valid_key_name(name), "{name}");
        }
        for reserved in RESERVED_NAMES {
            assert!(!valid_key_name(reserved), "{reserved}");
        }
    }

    /// A failed checkint (wrong passphrase) maps to the shared message; others keep theirs.
    #[test]
    fn decrypt_error_mapping() {
        match decrypt_err(ssh_key::Error::Crypto) {
            KringError::InvalidInput(msg) => assert_eq!(msg, MSG_WRONG_KEY_PASSPHRASE),
            other => panic!("{other:?}"),
        }
        match decrypt_err(ssh_key::Error::FormatEncoding) {
            KringError::InvalidInput(msg) => {
                assert!(msg.starts_with("Cannot decrypt the key: "), "{msg}");
                assert_ne!(msg, MSG_WRONG_KEY_PASSPHRASE);
            }
            other => panic!("{other:?}"),
        }
    }

    /// A temp sibling stays in the same directory and is unique.
    #[test]
    fn temp_siblings_are_unique() {
        let a = temp_sibling(Path::new("/d/key"));
        let b = temp_sibling(Path::new("/d/key"));
        assert_ne!(a, b);
        assert_eq!(a.parent(), Some(Path::new("/d")));
        assert!(a.to_string_lossy().ends_with(TMP_SUFFIX));
    }
}
