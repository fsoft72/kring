//! Worker handlers for GPG keys in the GnuPG home ([`WorkerConfig::gnupg_home`],
//! gpg's default when unset).
//!
//! Every command locates `gpg` again (a cheap `PATH` lookup) and addresses keys
//! by full primary fingerprint, checked against a fresh listing; only the import
//! source and the export destination are paths, chosen by the user. None of
//! these commands needs a Secret Service.
//!
//! gpg missing, or an agent refusing loopback passphrase entry, is
//! [`Event::GpgUnavailable`] with the reason; a scan reports nothing else, any
//! other command adds one [`Event::Error`] with the same text. Key passphrase
//! errors are [`Event::Error`] with exactly
//! [`kring_core::gpg::MSG_GPG_PASSPHRASE_REQUIRED`] or
//! [`kring_core::gpg::MSG_WRONG_GPG_PASSPHRASE`] (the UI reopens its dialog). A
//! missing backup passphrase is answered with the passphrase-free echo of
//! [`passphrase_echo`]. Once a backup was written it is always reported, also
//! when the change that followed failed.

use std::fs;
use std::path::Path;

use kring_core::backup::BackupInfo;
use kring_core::gpg::{
    GpgKey, GpgRunner, ImportReport, MAX_OUTPUT, MSG_GPG_NOT_FOUND, MSG_LOOPBACK_REFUSED,
    change_passphrase, create_key, delete_key, export_public, export_secret, import_keys,
    list_keys,
};
use kring_core::model::SecretValue;
use kring_core::{KringError, Result};
use zeroize::Zeroizing;

use crate::worker::{Command, Emitter, Event, WorkerConfig, passphrase_echo};

/// Prefix of the error of a failed rescan after a change.
pub(crate) const MSG_RESCAN_FAILED: &str = "Cannot rescan the GPG keys";
/// Error for a key reference that is not a full fingerprint.
const MSG_BAD_FINGERPRINT: &str = "A full key fingerprint (40 or 64 hex digits) is required";
/// Lengths in hex digits of full v4 and v5 fingerprints.
const FINGERPRINT_LENGTHS: [usize; 2] = [40, 64];

/// Returns true for commands handled by this module.
pub(crate) fn is_gpg(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::ScanGpgKeys
            | Command::CreateGpgKey { .. }
            | Command::ImportGpgKeys { .. }
            | Command::ExportGpgPublic { .. }
            | Command::ExportGpgSecret { .. }
            | Command::ChangeGpgPassphrase { .. }
            | Command::DeleteGpgKey { .. }
    )
}

/// Handles one GPG command with the `gpg` found in `PATH`.
pub(crate) fn handle<N: Fn()>(out: &Emitter<N>, config: &WorkerConfig, cmd: &Command) {
    handle_with(out, config, cmd, GpgRunner::locate);
}

/// Handles one GPG command with the runner `locate` returns, bound to the
/// configured home; a failed lookup makes the area unavailable.
pub(crate) fn handle_with<N: Fn()>(
    out: &Emitter<N>,
    config: &WorkerConfig,
    cmd: &Command,
    locate: impl Fn() -> Result<GpgRunner>,
) {
    let runner = match locate() {
        Ok(runner) => runner,
        Err(e) => return unavailable(out, cmd, message(&e)),
    };
    let runner = match &config.gnupg_home {
        Some(home) => runner.with_homedir(home.clone()),
        None => runner,
    };
    if let Err(e) = run(out, config, &runner, cmd) {
        report(out, cmd, &e);
    }
}

/// Reports a failed command: a missing backup passphrase as the echo of
/// `cmd`, gpg being unusable as [`Event::GpgUnavailable`], anything else as an error.
fn report<N: Fn()>(out: &Emitter<N>, cmd: &Command, e: &KringError) {
    if matches!(e, KringError::PassphraseRequired) {
        return out.emit(passphrase_echo(cmd));
    }
    if is_unusable(e) {
        return unavailable(out, cmd, message(e));
    }
    out.error(message(e));
}

/// True when `e` says gpg cannot be used at all (missing, or loopback refused).
fn is_unusable(e: &KringError) -> bool {
    match e {
        KringError::NotFound(m) => m == MSG_GPG_NOT_FOUND,
        KringError::InvalidInput(m) => m == MSG_LOOPBACK_REFUSED,
        _ => false,
    }
}

/// Emits [`Event::GpgUnavailable`]; a command other than the scan also gets one error.
fn unavailable<N: Fn()>(out: &Emitter<N>, cmd: &Command, reason: String) {
    out.emit(Event::GpgUnavailable(reason.clone()));
    if !matches!(cmd, Command::ScanGpgKeys) {
        out.error(reason);
    }
}

/// Returns the text of an error: `InvalidInput` and `NotFound` messages as
/// they are (the shared texts), anything else with its kind.
fn message(e: &KringError) -> String {
    match e {
        KringError::InvalidInput(m) | KringError::NotFound(m) => m.clone(),
        other => other.to_string(),
    }
}

/// Builds an `InvalidInput` error.
fn invalid(message: impl Into<String>) -> KringError {
    KringError::InvalidInput(message.into())
}

/// Resolves the full primary fingerprint `fpr` (any case) in a fresh listing.
///
/// Short ids, subkey fingerprints and unknown keys are refused.
fn resolve_key(runner: &GpgRunner, fpr: &str) -> Result<GpgKey> {
    let full = FINGERPRINT_LENGTHS.contains(&fpr.len());
    if !full || !fpr.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(MSG_BAD_FINGERPRINT));
    }
    let fpr = fpr.to_ascii_uppercase();
    list_keys(runner)?
        .into_iter()
        .find(|k| k.fingerprint == fpr)
        .ok_or_else(|| invalid(format!("No GPG key with fingerprint {fpr}")))
}

/// Lists the keys and emits [`Event::GpgKeys`].
fn emit_keys<N: Fn()>(out: &Emitter<N>, runner: &GpgRunner) -> Result<()> {
    out.emit(Event::GpgKeys(list_keys(runner)?));
    Ok(())
}

/// Rescans the keys after a change, reporting a failure on its own.
fn rescan<N: Fn()>(out: &Emitter<N>, runner: &GpgRunner) {
    if let Err(e) = emit_keys(out, runner) {
        out.error(format!("{MSG_RESCAN_FAILED}: {}", message(&e)));
    }
}

/// Reports a finished change without backup: a rescan of the keys, then `Done`.
fn finish<N: Fn()>(out: &Emitter<N>, runner: &GpgRunner, done: String) {
    rescan(out, runner);
    out.emit(Event::Done(done));
}

/// Reports an operation that ran after `backup` was written: the backup
/// first, then on success a rescan and `Done`, on failure the error and a
/// rescan (gpg may have changed part of the key).
pub(crate) fn report_backed_up<N: Fn()>(
    out: &Emitter<N>,
    runner: &GpgRunner,
    backup: BackupInfo,
    result: Result<()>,
    done: String,
) {
    out.emit(Event::BackupCreated(backup));
    match result {
        Ok(()) => finish(out, runner, done),
        Err(e) => {
            out.error(message(&e));
            rescan(out, runner);
        }
    }
}

/// Executes a command with `runner`.
fn run<N: Fn()>(
    out: &Emitter<N>,
    config: &WorkerConfig,
    runner: &GpgRunner,
    cmd: &Command,
) -> Result<()> {
    match cmd {
        Command::ScanGpgKeys => emit_keys(out, runner),
        Command::CreateGpgKey {
            uid,
            algo,
            expire,
            passphrase,
        } => {
            let key = create_key(runner, uid, *algo, expire.as_deref(), passphrase.as_ref())?;
            finish(out, runner, format!("Key {} created", key.fingerprint));
            Ok(())
        }
        Command::ImportGpgKeys { path } => {
            let data = read_import(path)?;
            let report = import_keys(runner, &data)?;
            finish(out, runner, imported_message(&report));
            Ok(())
        }
        Command::ExportGpgPublic { fpr } => {
            let key = resolve_key(runner, fpr)?;
            let text = export_public(runner, &key.fingerprint)?;
            out.emit(Event::GpgPublicKey {
                fpr: key.fingerprint,
                text,
            });
            Ok(())
        }
        Command::ExportGpgSecret {
            fpr,
            dest,
            passphrase,
        } => {
            let key = resolve_key(runner, fpr)?;
            export_secret(runner, &key.fingerprint, dest, passphrase.as_ref())?;
            let done = format!("Secret key exported to {}", dest.display());
            out.emit(Event::Done(done));
            Ok(())
        }
        Command::ChangeGpgPassphrase {
            fpr,
            old,
            new,
            backup_passphrase,
        } => {
            let key = resolve_key(runner, fpr)?;
            // A missing new passphrase is refused by the core as empty.
            let empty = SecretValue::from_text("");
            let new = new.as_ref().unwrap_or(&empty);
            let (backup, result) = change_passphrase(
                runner,
                &config.backups,
                &key.fingerprint,
                old.as_ref(),
                new,
                backup_passphrase.as_ref(),
            )?;
            let done = format!("Passphrase changed, backup in {}", backup.dir.display());
            report_backed_up(out, runner, backup, result, done);
            Ok(())
        }
        Command::DeleteGpgKey {
            fpr,
            key_passphrase,
            backup_passphrase,
        } => {
            let key = resolve_key(runner, fpr)?;
            let (backup, result) = delete_key(
                runner,
                &config.backups,
                &key.fingerprint,
                key_passphrase.as_ref(),
                backup_passphrase.as_ref(),
            )?;
            let done = format!(
                "Key {} deleted, backup in {}",
                key.fingerprint,
                backup.dir.display()
            );
            report_backed_up(out, runner, backup, result, done);
            Ok(())
        }
        _ => Err(invalid("Command sent to the GPG key path")),
    }
}

/// Reads the key file `path` to import (a regular file of at most [`MAX_OUTPUT`] bytes).
///
/// The bytes may hold secret keys, so they live in a zeroizing buffer.
fn read_import(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let io = |e: std::io::Error| KringError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    };
    let meta = fs::metadata(path).map_err(io)?;
    if !meta.is_file() {
        return Err(invalid(format!("{} is not a file", path.display())));
    }
    if meta.len() > MAX_OUTPUT as u64 {
        return Err(invalid(format!("{} is too large", path.display())));
    }
    Ok(Zeroizing::new(fs::read(path).map_err(io)?))
}

/// Success message of an import, e.g. `Imported 1 key (1 secret), 0 unchanged`.
fn imported_message(report: &ImportReport) -> String {
    let noun = if report.imported == 1 { "key" } else { "keys" };
    let mut text = format!("Imported {} {noun}", report.imported);
    if report.secret_imported > 0 {
        text.push_str(&format!(" ({} secret)", report.secret_imported));
    }
    text.push_str(&format!(", {} unchanged", report.unchanged));
    if report.not_imported > 0 {
        text.push_str(&format!(", {} not imported", report.not_imported));
    }
    text
}

#[cfg(test)]
mod tests;
