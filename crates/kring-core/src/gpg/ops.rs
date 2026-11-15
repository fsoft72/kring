//! GnuPG key operations: create, import, export, change passphrase, delete.
//!
//! Every operation addresses keys by their full fingerprint and passes it after
//! `--`, so no argument is ever taken for an option. Passphrases travel only over
//! the runner's pipes (loopback pinentry). Destructive operations first back the
//! key up: the armored public export, and for secret keys the armored secret
//! export, which is always age-encrypted in the backup (an unprotected key exports
//! in clear). The exports are staged in a private directory below the backup root
//! and removed afterwards; the backup is read back and checked before gpg is
//! asked to change or delete anything. Because the staged originals are removed,
//! these backups count as holding the only copy and are never pruned.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::colons::GpgKey;
use super::list_keys;
use super::runner::{
    GpgOutput, GpgRunner, MAX_OUTPUT, MSG_PASSPHRASE_NEWLINE, Reply, TIMEOUT_DEFAULT,
    TIMEOUT_KEYGEN,
};
use crate::backup::{BackupInfo, BackupManager, BackupSource, io_err, read_backup_file};
use crate::error::{KringError, Result};
use crate::keyring_file::retire::verify_backup_entry;
use crate::model::SecretValue;
use crate::transfer::archive::write_new_private;

/// Error message for a wrong key passphrase (shared with the UI, which reopens the dialog).
pub const MSG_WRONG_GPG_PASSPHRASE: &str = "Wrong GPG key passphrase";

/// Error message for a protected key used without its passphrase.
pub const MSG_GPG_PASSPHRASE_REQUIRED: &str = "GPG key passphrase required";

/// Error message when gpg-agent refuses loopback passphrase entry.
pub const MSG_LOOPBACK_REFUSED: &str = "gpg-agent refuses loopback passphrase entry, which kring \
     needs to pass passphrases without a pinentry window: add 'allow-loopback-pinentry' to \
     gpg-agent.conf (and remove 'no-allow-loopback-pinentry'), then run 'gpgconf --kill gpg-agent'";

/// Error message for a key whose primary secret is an offline stub or on a smartcard.
pub const MSG_PRIMARY_SECRET_UNAVAILABLE: &str = "The primary secret key is not stored on this \
     computer (offline stub or smartcard): not supported";

/// Message for primary and subkeys that are not protected alike.
const MSG_MIXED_PROTECTION: &str = "The primary key and its subkeys are not protected alike: \
     change their passphrases with gpg directly";

/// Message for an empty new passphrase.
const MSG_EMPTY_PASSPHRASE: &str = "Passphrase is empty";

/// Message for a key that changed while it was backed up.
const MSG_STALE: &str = "The key changed during the backup, nothing was changed";

/// Message for input without any OpenPGP key.
const MSG_NO_KEYS: &str = "No OpenPGP keys found in the data";

/// Backup reason of [`delete_key`].
const DELETE_REASON: &str = "delete-gpg-key";

/// Backup reason of [`change_passphrase`].
const CHANGE_REASON: &str = "change-gpg-passphrase";

/// libgpg-error code of a wrong passphrase (`GPG_ERR_BAD_PASSPHRASE`).
const GPG_ERR_BAD_PASSPHRASE: u32 = 11;

/// libgpg-error code of a missing passphrase (`GPG_ERR_NO_PASSPHRASE`).
const GPG_ERR_NO_PASSPHRASE: u32 = 177;

/// Mask selecting the error code from a libgpg-error value (the source is above it).
const GPG_ERR_CODE_MASK: u32 = 0xFFFF;

/// `ERROR` status location written when the agent refuses loopback pinentry.
const LOOPBACK_LOCATION: &str = "set_pinentry_mode";

/// Status prompt for a passphrase on the command fd.
const PROMPT_PASSPHRASE: &str = "GET_HIDDEN passphrase.enter";

/// Prefix of every status prompt.
const PROMPT_PREFIX: &str = "GET_";

/// Most passphrase prompts answered during one `--passwd` (old, new, per subkey).
const MAX_PROMPTS: usize = 6;

/// First line of an armored public key export.
const PUBLIC_ARMOR: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

/// First line of an armored secret key export.
const SECRET_ARMOR: &[u8] = b"-----BEGIN PGP PRIVATE KEY BLOCK-----";

/// Longest accepted user id in bytes.
const MAX_UID_LEN: usize = 256;

/// Longest accepted expiration value.
const MAX_EXPIRE_LEN: usize = 32;

/// Expiration value for keys that never expire.
const NEVER: &str = "never";

/// Prefix of the staging directories below the backup root.
const STAGING_PREFIX: &str = ".gpg-export-";

/// Suffix of the staging directories (the backup scanner skips it).
const STAGING_SUFFIX: &str = ".tmp";

/// Mode of staging directories.
const STAGING_DIR_MODE: u32 = 0o700;

/// Mode of staged export files.
const STAGING_FILE_MODE: u32 = 0o600;

/// Agent KEYINFO type of a key stored on disk.
const KEYINFO_DISK: &str = "D";

/// Agent KEYINFO protection flag of a passphrase protected key.
const KEYINFO_PROTECTED: &str = "P";

/// Agent KEYINFO protection flag of an unprotected key.
const KEYINFO_CLEAR: &str = "C";

/// Counter making staging directory names unique within the process.
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Algorithms offered for new keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpgAlgo {
    /// Ed25519 signing primary key with a Curve25519 (cv25519) encryption subkey.
    #[default]
    Ed25519Cv25519,
    /// RSA 3072 primary key and encryption subkey.
    Rsa3072,
    /// RSA 4096 primary key and encryption subkey.
    Rsa4096,
}

impl GpgAlgo {
    /// All algorithms, default first.
    pub const ALL: [GpgAlgo; 3] = [Self::Ed25519Cv25519, Self::Rsa3072, Self::Rsa4096];

    /// gpg algorithm name of the primary (certify and sign) key.
    fn primary(self) -> &'static str {
        match self {
            Self::Ed25519Cv25519 => "ed25519",
            Self::Rsa3072 => "rsa3072",
            Self::Rsa4096 => "rsa4096",
        }
    }

    /// gpg algorithm name of the encryption subkey.
    fn encryption(self) -> &'static str {
        match self {
            Self::Ed25519Cv25519 => "cv25519",
            Self::Rsa3072 => "rsa3072",
            Self::Rsa4096 => "rsa4096",
        }
    }
}

/// Outcome of [`import_keys`], from gpg's `IMPORT_OK` and `IMPORT_RES` status lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Keys new to the keyring.
    pub imported: u32,
    /// Keys that were already present without changes.
    pub unchanged: u32,
    /// Secret keys imported.
    pub secret_imported: u32,
    /// Keys that could not be imported.
    pub not_imported: u32,
    /// Fingerprints of the keys imported, updated or unchanged, in gpg's order.
    pub fingerprints: Vec<String>,
}

/// Generates a key: a primary certify/sign key for `uid`, then an encryption subkey.
///
/// `expire` is gpg's expiration syntax (`2y`, `6m`, `30d`, `2030-01-01`, `never`;
/// `None` means never) and applies to both keys. `passphrase` protects both keys;
/// `None` leaves them unprotected. Returns the new key as listed by gpg.
pub fn create_key(
    runner: &GpgRunner,
    uid: &str,
    algo: GpgAlgo,
    expire: Option<&str>,
    passphrase: Option<&SecretValue>,
) -> Result<GpgKey> {
    check_uid(uid)?;
    let expire = check_expire(expire)?;
    let unprotected = SecretValue::from_text("");
    let pass = passphrase.unwrap_or(&unprotected);
    check_line(pass)?;
    let out = runner.run(
        [
            "--quick-gen-key",
            "--",
            uid,
            algo.primary(),
            "cert,sign",
            expire,
        ],
        None,
        Some(pass),
        TIMEOUT_KEYGEN,
    )?;
    if let Some(e) = passphrase_error(&out, true) {
        return Err(e);
    }
    let fpr = created_fingerprint(&out).ok_or_else(|| failed("key generation", &out))?;
    if !out.success() {
        return Err(failed("key generation", &out));
    }
    let sub = runner.run(
        [
            "--quick-add-key",
            "--",
            &fpr,
            algo.encryption(),
            "encr",
            expire,
        ],
        None,
        Some(pass),
        TIMEOUT_KEYGEN,
    )?;
    if !sub.success() || !sub.has_status("KEY_CREATED") {
        let detail = passphrase_error(&sub, true).unwrap_or_else(|| failed("subkey", &sub));
        return Err(KringError::Gpg(format!(
            "key {fpr} was created, but adding its encryption subkey failed: {detail}"
        )));
    }
    require_key(runner, &fpr)
}

/// Imports armored or binary OpenPGP keys (public and secret).
///
/// Fails with `InvalidInput` for empty input, input over [`MAX_OUTPUT`] or input
/// without any key, and with [`KringError::Gpg`] when gpg reports no result.
pub fn import_keys(runner: &GpgRunner, data: &[u8]) -> Result<ImportReport> {
    if data.is_empty() {
        return Err(invalid(MSG_NO_KEYS));
    }
    if data.len() > MAX_OUTPUT {
        return Err(invalid("The key data is too large"));
    }
    let out = runner.run(["--import"], Some(data), None, TIMEOUT_DEFAULT)?;
    if let Some(e) = passphrase_error(&out, false) {
        return Err(e);
    }
    let (considered, report) = parse_import(&out).ok_or_else(|| failed("import", &out))?;
    if considered == 0 {
        return Err(invalid(MSG_NO_KEYS));
    }
    Ok(report)
}

/// Returns the armored public key `fpr` (full fingerprint).
///
/// An unknown key is `NotFound`.
pub fn export_public(runner: &GpgRunner, fpr: &str) -> Result<String> {
    let fpr = check_fingerprint(fpr)?;
    let out = runner.run(
        ["--armor", "--export", "--", fpr.as_str()],
        None,
        None,
        TIMEOUT_DEFAULT,
    )?;
    if !out.success() {
        return Err(failed("public key export", &out));
    }
    let text = String::from_utf8(out.stdout.to_vec())
        .map_err(|_| KringError::Gpg("public key export is not text".into()))?;
    if !text.starts_with(PUBLIC_ARMOR) {
        return Err(KringError::NotFound(format!("No GPG key {fpr}")));
    }
    Ok(text)
}

/// Writes the armored secret key `fpr` (with its subkeys) to the new file `dest` (0600).
///
/// gpg protects the export with the key passphrase, which `passphrase` must be
/// (missing: `MSG_GPG_PASSPHRASE_REQUIRED`, wrong: `MSG_WRONG_GPG_PASSPHRASE`);
/// an unprotected key exports in clear. An existing `dest` is refused.
pub fn export_secret(
    runner: &GpgRunner,
    fpr: &str,
    dest: &Path,
    passphrase: Option<&SecretValue>,
) -> Result<()> {
    let fpr = check_fingerprint(fpr)?;
    if fs::symlink_metadata(dest).is_ok() {
        return Err(invalid(&format!("{} already exists", dest.display())));
    }
    let armored = secret_export(runner, &fpr, passphrase)?;
    write_new_private(dest, &armored)
}

/// Changes the passphrase of the secret key `fpr` and all its subkeys to `new`.
///
/// The primary secret must be on disk (`MSG_PRIMARY_SECRET_UNAVAILABLE`) and
/// primary and subkeys protected alike. A protected key needs `old` (missing:
/// `MSG_GPG_PASSPHRASE_REQUIRED`, wrong: `MSG_WRONG_GPG_PASSPHRASE`); for an
/// unprotected key `old` is ignored. First the public and secret exports are
/// backed up (reason `change-gpg-passphrase`, the secret export age-encrypted
/// with `backup_passphrase`, which is required) and the backup is verified;
/// then gpg `--passwd` is driven over the command fd, answering its passphrase
/// prompts with the old passphrase first (protected keys only), then the new one.
pub fn change_passphrase(
    runner: &GpgRunner,
    manager: &BackupManager,
    fpr: &str,
    old: Option<&SecretValue>,
    new: &SecretValue,
    backup_passphrase: Option<&SecretValue>,
) -> Result<BackupInfo> {
    let fpr = check_fingerprint(fpr)?;
    if new.is_empty() {
        return Err(invalid(MSG_EMPTY_PASSPHRASE));
    }
    check_line(new)?;
    if let Some(old) = old {
        check_line(old)?;
    }
    if backup_passphrase.is_none() {
        return Err(KringError::PassphraseRequired);
    }
    let key = require_key(runner, &fpr)?;
    if !key.secret {
        return Err(invalid("The key has no secret part"));
    }
    if !key.primary_secret {
        return Err(invalid(MSG_PRIMARY_SECRET_UNAVAILABLE));
    }
    let old = match is_protected(runner, &key)? {
        true => Some(old.ok_or_else(|| invalid(MSG_GPG_PASSPHRASE_REQUIRED))?),
        false => None,
    };
    let backup = backup_key(runner, manager, &key, CHANGE_REASON, old, backup_passphrase)?;
    let out = passwd(runner, &fpr, old, new)?;
    if let Some(e) = passphrase_error(&out, true) {
        return Err(e);
    }
    if !out.success() || !out.has_status("SUCCESS") {
        return Err(failed("passphrase change", &out));
    }
    Ok(backup)
}

/// Deletes the key `fpr` (secret and public) after a verified backup.
///
/// The public export is always backed up in clear. A key with a secret part
/// needs its primary secret on disk (`MSG_PRIMARY_SECRET_UNAVAILABLE`); its
/// secret export (protected with the key passphrase `passphrase_for_backup`,
/// missing: `MSG_GPG_PASSPHRASE_REQUIRED`, wrong: `MSG_WRONG_GPG_PASSPHRASE`)
/// is age-encrypted with `backup_passphrase`, which is then required. Reason
/// `delete-gpg-key`. The key is deleted by full fingerprint only after the
/// backup was read back and the key is still the one backed up.
pub fn delete_key(
    runner: &GpgRunner,
    manager: &BackupManager,
    fpr: &str,
    passphrase_for_backup: Option<&SecretValue>,
    backup_passphrase: Option<&SecretValue>,
) -> Result<BackupInfo> {
    let fpr = check_fingerprint(fpr)?;
    let key = require_key(runner, &fpr)?;
    if key.secret && !key.primary_secret {
        return Err(invalid(MSG_PRIMARY_SECRET_UNAVAILABLE));
    }
    if key.secret && backup_passphrase.is_none() {
        return Err(KringError::PassphraseRequired);
    }
    let backup = backup_key(
        runner,
        manager,
        &key,
        DELETE_REASON,
        passphrase_for_backup,
        backup_passphrase,
    )?;
    let now = require_key(runner, &fpr)?;
    if now != key {
        return Err(invalid(MSG_STALE));
    }
    let out = runner.run(
        [
            "--yes",
            "--delete-secret-and-public-key",
            "--",
            fpr.as_str(),
        ],
        None,
        None,
        TIMEOUT_DEFAULT,
    )?;
    if let Some(e) = passphrase_error(&out, false) {
        return Err(e);
    }
    if !out.success() {
        return Err(failed("key deletion", &out));
    }
    if find_key(runner, &fpr)?.is_some() {
        return Err(KringError::Gpg(format!(
            "key {fpr} is still listed after deletion"
        )));
    }
    Ok(backup)
}

/// The key `fpr` as listed now, if any.
fn find_key(runner: &GpgRunner, fpr: &str) -> Result<Option<GpgKey>> {
    Ok(list_keys(runner)?
        .into_iter()
        .find(|k| k.fingerprint == fpr))
}

/// The key `fpr` as listed now; `NotFound` when absent.
fn require_key(runner: &GpgRunner, fpr: &str) -> Result<GpgKey> {
    find_key(runner, fpr)?.ok_or_else(|| KringError::NotFound(format!("No GPG key {fpr}")))
}

/// Exports the armored secret key `fpr` into a zeroizing buffer.
///
/// gpg never answers this from the agent's passphrase cache, so success proves
/// that `passphrase` unlocks every secret key (or that they are unprotected).
fn secret_export(
    runner: &GpgRunner,
    fpr: &str,
    passphrase: Option<&SecretValue>,
) -> Result<Zeroizing<Vec<u8>>> {
    let out = runner.run(
        ["--armor", "--export-secret-keys", "--", fpr],
        None,
        passphrase,
        TIMEOUT_DEFAULT,
    )?;
    if let Some(e) = passphrase_error(&out, passphrase.is_some()) {
        return Err(e);
    }
    if out.success() && out.stdout.is_empty() {
        return Err(KringError::NotFound(format!("No GPG secret key {fpr}")));
    }
    if !out.success() || !out.stdout.starts_with(SECRET_ARMOR) {
        return Err(failed("secret key export", &out));
    }
    Ok(out.stdout)
}

/// Backs up the exports of `key` and verifies the backup; returns it.
///
/// The public export is stored in clear, the secret export (when the key has a
/// secret part, unlocked with `key_passphrase`) is sensitive and age-encrypted
/// with `backup_passphrase`. Each copy is then read back from the backup and
/// checked against the sha256 of the exported bytes.
fn backup_key(
    runner: &GpgRunner,
    manager: &BackupManager,
    key: &GpgKey,
    reason: &str,
    key_passphrase: Option<&SecretValue>,
    backup_passphrase: Option<&SecretValue>,
) -> Result<BackupInfo> {
    let fpr = key.fingerprint.as_str();
    let public = export_public(runner, fpr)?;
    let secret = match key.secret {
        true => Some(secret_export(runner, fpr, key_passphrase)?),
        false => None,
    };
    let staging = Staging::new(&manager.root)?;
    // (staged path, sensitive, sha256 of the exported bytes)
    let mut files: Vec<(PathBuf, bool, String)> = Vec::new();
    let path = staging.write(&format!("{fpr}.public.asc"), public.as_bytes())?;
    files.push((path, false, sha256_hex(public.as_bytes())));
    if let Some(secret) = &secret {
        let path = staging.write(&format!("{fpr}.secret.asc"), secret)?;
        files.push((path, true, sha256_hex(secret)));
    }
    let sources: Vec<BackupSource> = files
        .iter()
        .map(|(path, sensitive, _)| BackupSource {
            path: path.clone(),
            sensitive: *sensitive,
        })
        .collect();
    let backup = manager.create_with(reason, &sources, backup_passphrase)?;
    for (path, sensitive, digest) in &files {
        verify_backup_entry(&backup, path, digest, *sensitive)?;
        let entry = backup
            .files
            .iter()
            .find(|f| &f.original == path)
            .ok_or_else(|| invalid("Backup does not list the key export, key kept"))?;
        // Decrypts age copies and checks the sha256 again, from the stored file.
        read_backup_file(&backup, entry, backup_passphrase)?;
    }
    Ok(backup)
}

/// Runs `gpg --passwd` for `fpr`, answering passphrase prompts over the command fd.
///
/// The first prompt gets `old` when the key is protected; every other prompt
/// gets `new` (gpg asks once per unprotected key, and after the old passphrase
/// of a protected key only once for the new one). Any other prompt, or more
/// than [`MAX_PROMPTS`] passphrase prompts, closes the command fd so gpg fails.
fn passwd(
    runner: &GpgRunner,
    fpr: &str,
    old: Option<&SecretValue>,
    new: &SecretValue,
) -> Result<GpgOutput> {
    let mut prompts = 0;
    let mut responder = |line: &str| {
        if line == PROMPT_PASSPHRASE {
            prompts += 1;
            return passwd_answer(prompts, old, new);
        }
        if line.starts_with(PROMPT_PREFIX) {
            return Reply::Close;
        }
        Reply::Ignore
    };
    runner.run_interactive(["--passwd", "--", fpr], &mut responder, TIMEOUT_DEFAULT)
}

/// The answer to the `n`th (1-based) passphrase prompt of `--passwd`.
fn passwd_answer<'a>(n: usize, old: Option<&'a SecretValue>, new: &'a SecretValue) -> Reply<'a> {
    if n > MAX_PROMPTS {
        return Reply::Close;
    }
    match (n, old) {
        (1, Some(old)) => Reply::Answer(old),
        _ => Reply::Answer(new),
    }
}

/// True when the secret keys of `key` are passphrase protected, per gpg-agent.
///
/// Asks the agent (`KEYINFO --list`) for the protection of the primary key and
/// of every subkey stored on disk; they must agree (`MSG_MIXED_PROTECTION`).
fn is_protected(runner: &GpgRunner, key: &GpgKey) -> Result<bool> {
    let out = runner.agent_commands(&["KEYINFO --list"], TIMEOUT_DEFAULT)?;
    if !out.success() {
        return Err(failed("gpg-agent key query", &out));
    }
    let infos = parse_keyinfo(&out.stdout)?;
    let protection = |grip: &str| {
        infos
            .iter()
            .find(|i| !grip.is_empty() && i.grip == grip && i.kind == KEYINFO_DISK)
            .map(|i| i.protection.as_str())
    };
    let primary = protection(&key.keygrip).ok_or_else(|| {
        KringError::Gpg(format!(
            "gpg-agent does not hold the secret key {}",
            key.fingerprint
        ))
    })?;
    let subkeys: Vec<&str> = key
        .subkeys
        .iter()
        .filter_map(|s| protection(&s.keygrip))
        .collect();
    if subkeys.iter().any(|p| *p != primary) {
        return Err(invalid(MSG_MIXED_PROTECTION));
    }
    match primary {
        KEYINFO_PROTECTED => Ok(true),
        KEYINFO_CLEAR => Ok(false),
        _ => Err(invalid(MSG_MIXED_PROTECTION)),
    }
}

/// One `S KEYINFO` line of gpg-agent.
#[derive(Debug, PartialEq, Eq)]
struct KeyInfo {
    /// Keygrip (upper case hex).
    grip: String,
    /// Storage type: `D` disk, `T` smartcard, `X` unknown.
    kind: String,
    /// Protection: `P` protected, `C` clear, `-` unknown.
    protection: String,
}

/// Parses gpg-connect-agent's `KEYINFO --list` output; an `ERR` line is an error.
///
/// Line format: `S KEYINFO <grip> <type> <serial> <idstr> <cached> <protection> ...`.
fn parse_keyinfo(stdout: &[u8]) -> Result<Vec<KeyInfo>> {
    let text = String::from_utf8_lossy(stdout);
    let mut infos = Vec::new();
    for line in text.lines() {
        if line.starts_with("ERR") {
            return Err(KringError::Gpg(format!("gpg-agent: {line}")));
        }
        let Some(rest) = line.strip_prefix("S KEYINFO ") else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let [grip, kind, _serial, _idstr, _cached, protection, ..] = fields.as_slice() else {
            continue;
        };
        infos.push(KeyInfo {
            grip: grip.to_ascii_uppercase(),
            kind: kind.to_string(),
            protection: protection.to_string(),
        });
    }
    Ok(infos)
}

/// Maps passphrase related status lines to the shared error messages.
///
/// Loopback refused by the agent: `MSG_LOOPBACK_REFUSED`; `BAD_PASSPHRASE` or an
/// `ERROR` with code `GPG_ERR_BAD_PASSPHRASE`: `MSG_WRONG_GPG_PASSPHRASE`;
/// `MISSING_PASSPHRASE`, code `GPG_ERR_NO_PASSPHRASE`, or a failed run that
/// needed a passphrase none was given for: `MSG_GPG_PASSPHRASE_REQUIRED`.
fn passphrase_error(out: &GpgOutput, passphrase_given: bool) -> Option<KringError> {
    let errors: Vec<(String, u32)> = out
        .status_args("ERROR")
        .iter()
        .filter_map(|args| {
            let mut parts = args.split_whitespace();
            let location = parts.next()?.to_string();
            let code = parts.next()?.parse::<u32>().ok()?;
            Some((location, code & GPG_ERR_CODE_MASK))
        })
        .collect();
    if loopback_refused(out) {
        return Some(invalid(MSG_LOOPBACK_REFUSED));
    }
    let has_code = |code: u32| errors.iter().any(|(_, c)| *c == code);
    if out.has_status("BAD_PASSPHRASE") || has_code(GPG_ERR_BAD_PASSPHRASE) {
        return Some(invalid(MSG_WRONG_GPG_PASSPHRASE));
    }
    if out.has_status("MISSING_PASSPHRASE") || has_code(GPG_ERR_NO_PASSPHRASE) {
        return Some(invalid(MSG_GPG_PASSPHRASE_REQUIRED));
    }
    if !out.success() && !passphrase_given && out.has_status("NEED_PASSPHRASE") {
        return Some(invalid(MSG_GPG_PASSPHRASE_REQUIRED));
    }
    None
}

/// True when gpg reported that the agent refused loopback pinentry.
///
/// gpg then fails every command that talks to the agent, listings included.
pub(super) fn loopback_refused(out: &GpgOutput) -> bool {
    out.status_args("ERROR")
        .iter()
        .any(|args| args.split_whitespace().next() == Some(LOOPBACK_LOCATION))
}

/// Parses `IMPORT_RES` (last one wins) and `IMPORT_OK` lines into a report.
///
/// Returns the number of keys gpg considered with the report, or `None` without
/// an `IMPORT_RES` line. `IMPORT_RES` fields: count, no_user_id, imported,
/// imported_rsa, unchanged, n_uids, n_subk, n_sigs, n_revoc, sec_read,
/// sec_imported, sec_dups, skipped_new_keys, not_imported, skipped_v3_keys.
fn parse_import(out: &GpgOutput) -> Option<(u32, ImportReport)> {
    let res = out.status_args("IMPORT_RES").pop()?;
    let counts: Vec<u32> = res
        .split_whitespace()
        .map(|n| n.parse().unwrap_or(0))
        .collect();
    let count = |i: usize| counts.get(i).copied().unwrap_or(0);
    let mut fingerprints: Vec<String> = Vec::new();
    for args in out.status_args("IMPORT_OK") {
        let Some(fpr) = args.split_whitespace().nth(1) else {
            continue;
        };
        let fpr = fpr.to_ascii_uppercase();
        if !fingerprints.contains(&fpr) {
            fingerprints.push(fpr);
        }
    }
    let report = ImportReport {
        imported: count(2),
        unchanged: count(4),
        secret_imported: count(10),
        not_imported: count(13),
        fingerprints,
    };
    Some((count(0), report))
}

/// The fingerprint of the primary key from a `KEY_CREATED P|B <fpr>` status line.
fn created_fingerprint(out: &GpgOutput) -> Option<String> {
    out.status_args("KEY_CREATED").iter().find_map(|args| {
        let mut parts = args.split_whitespace();
        let kind = parts.next()?;
        let fpr = parts.next()?;
        matches!(kind, "P" | "B").then(|| fpr.to_ascii_uppercase())
    })
}

/// Normalizes a full fingerprint: 40 (v4) or 64 (v5) hex digits, upper case.
fn check_fingerprint(fpr: &str) -> Result<String> {
    let valid_len = fpr.len() == 40 || fpr.len() == 64;
    if !valid_len || !fpr.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(
            "A full key fingerprint (40 or 64 hex digits) is required",
        ));
    }
    Ok(fpr.to_ascii_uppercase())
}

/// Refuses an empty, overlong or multi-line user id.
fn check_uid(uid: &str) -> Result<()> {
    if uid.trim().is_empty() {
        return Err(invalid("The user id is empty"));
    }
    if uid.len() > MAX_UID_LEN {
        return Err(invalid("The user id is too long"));
    }
    if uid.chars().any(char::is_control) {
        return Err(invalid("The user id must be a single line"));
    }
    Ok(())
}

/// Validates an expiration value (`None` is [`NEVER`]).
///
/// Accepts letters, digits and `-` (gpg's `2y`, `30d`, ISO dates, `never`), not
/// starting with `-`; gpg checks the meaning.
fn check_expire(expire: Option<&str>) -> Result<&str> {
    let Some(expire) = expire else {
        return Ok(NEVER);
    };
    let valid = !expire.is_empty()
        && expire.len() <= MAX_EXPIRE_LEN
        && !expire.starts_with('-')
        && expire
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !valid {
        return Err(invalid(
            "Invalid expiration: use e.g. 2y, 6m, 30d, 2030-01-01 or never",
        ));
    }
    Ok(expire)
}

/// Refuses a passphrase gpg cannot read as one line.
fn check_line(passphrase: &SecretValue) -> Result<()> {
    if passphrase.as_bytes().contains(&b'\n') {
        return Err(invalid(MSG_PASSPHRASE_NEWLINE));
    }
    Ok(())
}

/// Builds an `InvalidInput` error.
fn invalid(msg: &str) -> KringError {
    KringError::InvalidInput(msg.to_string())
}

/// The error for a gpg run that failed for another reason.
fn failed(what: &str, out: &GpgOutput) -> KringError {
    KringError::Gpg(format!(
        "{what} failed ({}): {}",
        out.status,
        out.stderr_text()
    ))
}

/// Hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A private directory below the backup root holding exports while they are backed up.
///
/// Its name ends in `.tmp`, so the backup scanner ignores it; it is removed on drop.
struct Staging {
    /// The directory (mode 0700).
    dir: PathBuf,
}

impl Staging {
    /// Creates a new, unique staging directory below `root` (created 0700 if missing).
    fn new(root: &Path) -> Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(STAGING_DIR_MODE)
            .create(root)
            .map_err(|e| io_err(root, e))?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let n = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            "{STAGING_PREFIX}{}-{n}-{nanos}{STAGING_SUFFIX}",
            std::process::id()
        );
        let dir = root.join(name);
        fs::DirBuilder::new()
            .mode(STAGING_DIR_MODE)
            .create(&dir)
            .map_err(|e| io_err(&dir, e))?;
        Ok(Self { dir })
    }

    /// Writes `bytes` to the new file `name` (mode 0600) and returns its path.
    fn write(&self, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        let path = self.dir.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(STAGING_FILE_MODE)
            .open(&path)
            .map_err(|e| io_err(&path, e))?;
        file.write_all(bytes).map_err(|e| io_err(&path, e))?;
        Ok(path)
    }
}

impl Drop for Staging {
    /// Removes the staging directory and the exports in it.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    /// A gpg output with the given exit code and status lines.
    fn output(code: i32, status: &str) -> GpgOutput {
        GpgOutput {
            status: ExitStatus::from_raw(code << 8),
            stdout: Zeroizing::new(Vec::new()),
            stderr: b"gpg: something".to_vec(),
            status_lines: status.as_bytes().to_vec(),
        }
    }

    /// Asserts that `e` is `InvalidInput(msg)`.
    fn assert_msg(e: Option<KringError>, msg: &str) {
        assert!(
            matches!(&e, Some(KringError::InvalidInput(m)) if m == msg),
            "expected {msg:?}, got {e:?}"
        );
    }

    /// Status lines and error codes map to the shared passphrase messages.
    #[test]
    fn passphrase_error_mapping() {
        let loopback = "[GNUPG:] ERROR set_pinentry_mode 67108924\n\
            [GNUPG:] ERROR export_keys.secret 67108875\n";
        assert_msg(
            passphrase_error(&output(2, loopback), true),
            MSG_LOOPBACK_REFUSED,
        );
        let bad = "[GNUPG:] ERROR keyedit.passwd 67108875\n[GNUPG:] FAILURE gpg-exit 33554433\n";
        assert_msg(
            passphrase_error(&output(2, bad), true),
            MSG_WRONG_GPG_PASSPHRASE,
        );
        let bad_status = "[GNUPG:] BAD_PASSPHRASE AAAA\n";
        assert_msg(
            passphrase_error(&output(2, bad_status), true),
            MSG_WRONG_GPG_PASSPHRASE,
        );
        let none = "[GNUPG:] ERROR export_keys.secret 67109041\n";
        assert_msg(
            passphrase_error(&output(2, none), true),
            MSG_GPG_PASSPHRASE_REQUIRED,
        );
        let missing = "[GNUPG:] MISSING_PASSPHRASE\n";
        assert_msg(
            passphrase_error(&output(2, missing), true),
            MSG_GPG_PASSPHRASE_REQUIRED,
        );
        let need = "[GNUPG:] NEED_PASSPHRASE A A 22 0\n[GNUPG:] INQUIRE_MAXLEN 100\n";
        assert_msg(
            passphrase_error(&output(2, need), false),
            MSG_GPG_PASSPHRASE_REQUIRED,
        );
        assert!(passphrase_error(&output(2, need), true).is_none());
        assert!(passphrase_error(&output(0, need), false).is_none());
        let other = "[GNUPG:] ERROR keydb_search 67108881\n[GNUPG:] ERROR x\n[GNUPG:] ERROR y z\n";
        assert!(passphrase_error(&output(2, other), true).is_none());
        assert!(passphrase_error(&output(0, ""), true).is_none());
    }

    /// Import results and fingerprints are read from the status lines.
    #[test]
    fn import_report_parsing() {
        let status = "[GNUPG:] IMPORTED 24E3 x\n\
            [GNUPG:] IMPORT_OK 1 48ae54aee314c6840eafa43f24e37e8ec1ab5b6c\n\
            [GNUPG:] IMPORT_OK 17 48AE54AEE314C6840EAFA43F24E37E8EC1AB5B6C\n\
            [GNUPG:] IMPORT_OK 0 33D3B2A8F4F45A6EC3F9B1093DFE5E9430B05224\n\
            [GNUPG:] IMPORT_OK broken\n\
            [GNUPG:] IMPORT_RES 2 0 1 0 1 0 0 0 0 1 1 0 0 3 0\n";
        let (count, report) = parse_import(&output(0, status)).unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            report,
            ImportReport {
                imported: 1,
                unchanged: 1,
                secret_imported: 1,
                not_imported: 3,
                fingerprints: vec![
                    "48AE54AEE314C6840EAFA43F24E37E8EC1AB5B6C".into(),
                    "33D3B2A8F4F45A6EC3F9B1093DFE5E9430B05224".into(),
                ],
            }
        );
        let (count, report) = parse_import(&output(2, "[GNUPG:] IMPORT_RES 0 x\n")).unwrap();
        assert_eq!(count, 0);
        assert_eq!(report, ImportReport::default());
        assert!(parse_import(&output(2, "[GNUPG:] NODATA 1\n")).is_none());
    }

    /// Only the primary `KEY_CREATED` fingerprint is taken.
    #[test]
    fn created_fingerprint_parsing() {
        let out = output(
            0,
            "[GNUPG:] KEY_CREATED S BBBB\n[GNUPG:] KEY_CREATED P aaaa\n",
        );
        assert_eq!(created_fingerprint(&out).as_deref(), Some("AAAA"));
        let both = output(0, "[GNUPG:] KEY_CREATED B cccc\n");
        assert_eq!(created_fingerprint(&both).as_deref(), Some("CCCC"));
        assert!(created_fingerprint(&output(2, "[GNUPG:] KEY_NOT_CREATED\n")).is_none());
        assert!(created_fingerprint(&output(0, "[GNUPG:] KEY_CREATED P\n")).is_none());
    }

    /// Agent KEYINFO lines are parsed; an ERR line fails.
    #[test]
    fn keyinfo_parsing() {
        let out = b"S KEYINFO 3c93fa3d198aad2323fa4b699b3a5c6dd7887669 D - - 1 P - - -\n\
            S KEYINFO 84B2 T D276 OPENPGP.1 - - - - -\n\
            S KEYINFO short D -\n\
            OK\n";
        let infos = parse_keyinfo(out).unwrap();
        assert_eq!(
            infos,
            [
                KeyInfo {
                    grip: "3C93FA3D198AAD2323FA4B699B3A5C6DD7887669".into(),
                    kind: "D".into(),
                    protection: "P".into(),
                },
                KeyInfo {
                    grip: "84B2".into(),
                    kind: "T".into(),
                    protection: "-".into(),
                },
            ]
        );
        let r = parse_keyinfo(b"ERR 67109139 No agent running\n");
        assert!(matches!(r, Err(KringError::Gpg(m)) if m.contains("No agent")));
    }

    /// Fingerprints must be full; they are upper cased.
    #[test]
    fn fingerprint_validation() {
        let v4 = "f304378ce8ceef63bb59f93cef2ca8c2f6a348dc";
        assert_eq!(check_fingerprint(v4).unwrap(), v4.to_ascii_uppercase());
        assert!(check_fingerprint(&"a".repeat(64)).is_ok());
        for bad in [
            "",
            "F2CA8C2F6A348DC",
            &"g".repeat(40),
            &format!("-{}", "a".repeat(39)),
        ] {
            assert!(check_fingerprint(bad).is_err(), "{bad}");
        }
    }

    /// User ids and expirations are checked before gpg runs.
    #[test]
    fn uid_and_expire_validation() {
        assert!(check_uid("Name <mail@example.org>").is_ok());
        assert!(check_uid("-dash").is_ok());
        assert!(check_uid("  ").is_err());
        assert!(check_uid("a\nb").is_err());
        assert!(check_uid(&"x".repeat(MAX_UID_LEN + 1)).is_err());
        assert_eq!(check_expire(None).unwrap(), "never");
        for ok in ["2y", "6m", "30d", "2030-01-01", "never", "0"] {
            assert_eq!(check_expire(Some(ok)).unwrap(), ok);
        }
        for bad in ["", "-1", "2 y", "2y;rm", &"1".repeat(MAX_EXPIRE_LEN + 1)] {
            assert!(check_expire(Some(bad)).is_err(), "{bad}");
        }
    }

    /// gpg algorithm names per choice.
    #[test]
    fn algo_names() {
        assert_eq!(GpgAlgo::default(), GpgAlgo::Ed25519Cv25519);
        let names: Vec<(&str, &str)> = GpgAlgo::ALL
            .iter()
            .map(|a| (a.primary(), a.encryption()))
            .collect();
        assert_eq!(
            names,
            [
                ("ed25519", "cv25519"),
                ("rsa3072", "rsa3072"),
                ("rsa4096", "rsa4096")
            ]
        );
    }

    /// The passwd responder answers old first only for protected keys, then new, then gives up.
    #[test]
    fn passwd_answer_order() {
        let (old, new) = (SecretValue::from_text("old"), SecretValue::from_text("new"));
        let pick = |n, old: Option<&SecretValue>| match passwd_answer(n, old, &new) {
            Reply::Answer(s) => s.as_text().unwrap().to_string(),
            Reply::Close => "close".into(),
            Reply::Ignore => "ignore".into(),
        };
        assert_eq!(pick(1, Some(&old)), "old");
        assert_eq!(pick(2, Some(&old)), "new");
        assert_eq!(pick(3, Some(&old)), "new");
        assert_eq!(pick(1, None), "new");
        assert_eq!(pick(2, None), "new");
        assert_eq!(pick(MAX_PROMPTS + 1, Some(&old)), "close");
    }

    /// Fake gpg for `--passwd`: prompts three times, then asks a yes/no question.
    const FAKE_PASSWD: &str = r#"#!/bin/sh
for i in 1 2 3; do
  echo '[GNUPG:] INQUIRE_MAXLEN 100' >&4
  echo '[GNUPG:] GET_HIDDEN passphrase.enter' >&4
  IFS= read -r a || exit 3
  printf '%s,' "$a"
done
echo '[GNUPG:] GET_BOOL keyedit.save.okay' >&4
if IFS= read -r b; then echo 'answered bool'; exit 4; fi
echo '[GNUPG:] SUCCESS keyedit.passwd' >&4
"#;

    /// `passwd` drives the command fd: old, new, new, and closes it on a yes/no prompt.
    #[test]
    fn passwd_drives_the_command_fd() {
        let dir = tempfile::tempdir().unwrap();
        let gpg = dir.path().join("gpg");
        fs::write(&gpg, FAKE_PASSWD).unwrap();
        fs::set_permissions(&gpg, fs::Permissions::from_mode(0o755)).unwrap();
        let runner = GpgRunner::new(gpg).unwrap();
        let (old, new) = (
            SecretValue::from_text("old-pass"),
            SecretValue::from_text("new-pass"),
        );
        let out = passwd(&runner, "FPR", Some(&old), &new).unwrap();
        assert!(out.success(), "{out:?}");
        assert_eq!(out.stdout.as_slice(), b"old-pass,new-pass,new-pass,");
        assert!(out.has_status("SUCCESS"));
        let out = passwd(&runner, "FPR", None, &new).unwrap();
        assert_eq!(out.stdout.as_slice(), b"new-pass,new-pass,new-pass,");
    }

    /// Staging files are private and removed with their directory.
    #[test]
    fn staging_is_private_and_cleaned_up() {
        let root = tempfile::tempdir().unwrap();
        let backups = root.path().join("backups");
        let staging = Staging::new(&backups).unwrap();
        let path = staging.write("x.asc", b"data").unwrap();
        let dir_mode = fs::metadata(&staging.dir).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            staging.write("x.asc", b"again").is_err(),
            "never overwrites"
        );
        let name = staging
            .dir
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with(STAGING_PREFIX) && name.ends_with(STAGING_SUFFIX));
        let dir = staging.dir.clone();
        drop(staging);
        assert!(!dir.exists());
        assert!(backups.exists());
    }
}
