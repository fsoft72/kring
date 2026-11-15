//! Worker handlers for offline features: keyring files, backups and archives.
//!
//! Keyring files are addressed by name only (`<name>.keyring` inside
//! [`WorkerConfig::keyrings_dir`]); the path is always taken from a fresh scan,
//! never from the UI. Backups are addressed by a directory that must be among
//! [`BackupManager::list`](kring_core::backup::BackupManager::list).

use std::path::{Path, PathBuf};

use kring_core::backup::{BackupFile, BackupInfo, RESTART_HINT, restore};
use kring_core::keyring_file::binary::read_binary;
use kring_core::keyring_file::textual::{OfflineItem, ParseWarning, parse_textual};
use kring_core::keyring_file::{
    KeyringFileInfo, KeyringFormat, RetireMode, retire_file, retire_mode, scan_dir,
};
use kring_core::model::{CollectionId, SecretValue};
use kring_core::provider::ProviderInfo;
use kring_core::transfer::archive::{ExportedItem, read_archive, write_archive};
use kring_core::transfer::import::import_items;
use kring_core::{KringError, MasterPasswordStore, Result, SecretStore};
use zeroize::Zeroizing;

use crate::worker::{
    Command, Emitter, Event, MSG_NO_PROVIDER, WorkerConfig, load_items, refresh, run_store_command,
};

/// Message for a file name that could escape the keyrings directory.
const MSG_BAD_NAME: &str = "Invalid keyring file name";
/// Message for a backup directory that is not among the listed backups.
const MSG_UNKNOWN_BACKUP: &str = "Unknown backup";
/// Message for a restore without files.
const MSG_NO_RESTORE_FILES: &str = "No files selected for restore";
/// Message after a plaintext file was retired.
const MSG_RETIRED: &str = "Plaintext file retired";
/// Extension of keyring files.
const KEYRING_EXTENSION: &str = "keyring";

/// Returns true for commands handled by this module.
pub(crate) fn is_offline(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::ScanFiles
            | Command::OpenFile { .. }
            | Command::ImportFile { .. }
            | Command::RetireFile { .. }
            | Command::ListBackups
            | Command::RestoreBackup { .. }
            | Command::ExportCollection { .. }
            | Command::ImportArchive { .. }
    )
}

/// Handles one offline command and reports a failure as [`Event::Error`].
///
/// `ImportFile`, `ImportArchive` and `ExportCollection` need a store (any
/// provider); the other commands work without one.
pub(crate) async fn handle<S, N>(
    out: &Emitter<N>,
    store: Option<&S>,
    provider: Option<&ProviderInfo>,
    config: &WorkerConfig,
    cmd: Command,
) where
    S: SecretStore + MasterPasswordStore,
    N: Fn(),
{
    if store.is_none() && needs_store(&cmd) {
        return out.error(MSG_NO_PROVIDER);
    }
    if let Err(e) = run(out, store, provider, config, &cmd).await {
        out.error(e.to_string());
    }
}

/// Executes an offline command.
async fn run<S, N>(
    out: &Emitter<N>,
    store: Option<&S>,
    provider: Option<&ProviderInfo>,
    config: &WorkerConfig,
    cmd: &Command,
) -> Result<()>
where
    S: SecretStore + MasterPasswordStore,
    N: Fn(),
{
    match cmd {
        Command::ScanFiles => emit_files(out, config),
        Command::OpenFile { name, password } => {
            let info = resolve_file(config, name)?;
            let Some((items, warnings)) = read_file(out, &info, password.as_ref()).await? else {
                return Ok(());
            };
            out.emit(Event::FileItems {
                name: info.name,
                items,
                warnings,
            });
            Ok(())
        }
        Command::ImportFile {
            name,
            password,
            target,
        } => {
            let store = require_store(store)?;
            let info = resolve_file(config, name)?;
            let Some((items, _)) = read_file(out, &info, password.as_ref()).await? else {
                return Ok(());
            };
            import_into(out, store, target, items).await
        }
        Command::RetireFile {
            name,
            backup_passphrase,
        } => retire(out, store, provider, config, name, backup_passphrase).await,
        Command::ListBackups => {
            out.emit(Event::Backups(config.backups.list()?));
            Ok(())
        }
        Command::RestoreBackup {
            dir,
            files,
            passphrase,
        } => restore_backup(out, config, dir, files, passphrase.as_ref(), cmd),
        Command::ExportCollection {
            collection,
            path,
            passphrase,
        } => export(out, require_store(store)?, collection, path, passphrase).await,
        Command::ImportArchive {
            path,
            passphrase,
            target,
        } => {
            let store = require_store(store)?;
            let items = read_archive(path, passphrase)?
                .into_iter()
                .map(|e| e.item)
                .collect();
            import_into(out, store, target, items).await
        }
        _ => Err(KringError::InvalidInput(
            "Store command sent to the offline path".into(),
        )),
    }
}

/// Returns true for offline commands that cannot run without a store.
fn needs_store(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::ImportFile { .. }
            | Command::ImportArchive { .. }
            | Command::ExportCollection { .. }
    )
}

/// Returns the store, or an error when no provider is running.
fn require_store<S>(store: Option<&S>) -> Result<&S> {
    store.ok_or_else(|| KringError::Unsupported(MSG_NO_PROVIDER.into()))
}

/// Builds an `InvalidInput` error.
fn invalid(message: impl Into<String>) -> KringError {
    KringError::InvalidInput(message.into())
}

/// Scans the keyrings directory and emits [`Event::Files`].
fn emit_files<N: Fn()>(out: &Emitter<N>, config: &WorkerConfig) -> Result<()> {
    out.emit(Event::Files(scan_dir(&config.keyrings_dir)?));
    Ok(())
}

/// Resolves a file name to its scanned entry in the keyrings directory.
///
/// The name must be non-empty, contain no `/` and not be `.` or `..`; the
/// entry must be the regular (non-symlink) file `<keyrings_dir>/<name>.keyring`.
fn resolve_file(config: &WorkerConfig, name: &str) -> Result<KeyringFileInfo> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(invalid(MSG_BAD_NAME));
    }
    let path = config
        .keyrings_dir
        .join(format!("{name}.{KEYRING_EXTENSION}"));
    let missing = || invalid(format!("No keyring file named '{name}'"));
    let is_file = std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_file());
    if !is_file {
        return Err(missing());
    }
    scan_dir(&config.keyrings_dir)?
        .into_iter()
        .find(|f| f.name == name && f.path == path)
        .ok_or_else(missing)
}

/// Reads the items of a keyring file.
///
/// A binary file without `password` emits [`Event::PasswordNeeded`] and
/// returns `None`; an unknown format is an error.
async fn read_file<N: Fn()>(
    out: &Emitter<N>,
    info: &KeyringFileInfo,
    password: Option<&SecretValue>,
) -> Result<Option<(Vec<OfflineItem>, Vec<ParseWarning>)>> {
    match info.format {
        KeyringFormat::Textual => {
            let bytes = Zeroizing::new(std::fs::read(&info.path).map_err(|e| KringError::Io {
                path: info.path.clone(),
                message: e.to_string(),
            })?);
            let parsed = parse_textual(&bytes)?;
            Ok(Some((parsed.items, parsed.warnings)))
        }
        KeyringFormat::BinaryV0 => {
            let Some(password) = password else {
                out.emit(Event::PasswordNeeded(info.name.clone()));
                return Ok(None);
            };
            Ok(Some((read_binary(&info.path, password).await?, Vec::new())))
        }
        KeyringFormat::Unknown => Err(invalid(format!(
            "Unknown keyring file format: {}",
            info.name
        ))),
    }
}

/// Imports items into `target`, then emits the report, the target items and the collections.
async fn import_into<S: SecretStore, N: Fn()>(
    out: &Emitter<N>,
    store: &S,
    target: &CollectionId,
    items: Vec<OfflineItem>,
) -> Result<()> {
    let report = import_items(store, target, items).await?;
    out.emit(Event::ImportDone(report));
    load_items(out, store, target).await;
    refresh(out, store).await;
    Ok(())
}

/// Retires keyring file `name`.
///
/// When the daemon serves it (a live collection decodes to the name) this is
/// the `DeleteCollection` flow with its gate and backup; otherwise the
/// plaintext file is backed up encrypted and removed. If a store exists but
/// cannot list its collections the retire is aborted.
async fn retire<S, N>(
    out: &Emitter<N>,
    store: Option<&S>,
    provider: Option<&ProviderInfo>,
    config: &WorkerConfig,
    name: &str,
    passphrase: &SecretValue,
) -> Result<()>
where
    S: SecretStore + MasterPasswordStore,
    N: Fn(),
{
    let info = resolve_file(config, name)?;
    // Without a daemon no collection is live, so no file is loaded by it.
    let live = match store {
        Some(store) => store.list_collections().await?,
        None => Vec::new(),
    };
    if let (RetireMode::DeleteLiveCollection(collection), Some(store)) =
        (retire_mode(&info, &live), store)
    {
        let delete = Command::DeleteCollection {
            collection,
            backup_passphrase: Some(passphrase.clone()),
        };
        run_store_command(out, store, provider, config, delete).await;
        return emit_files(out, config);
    }
    let backup = retire_file(
        &config.backups,
        &info,
        &config.keyrings_dir,
        &live,
        passphrase,
    )?;
    emit_backup(out, backup);
    out.emit(Event::Done(MSG_RETIRED.into()));
    emit_files(out, config)
}

/// Emits [`Event::BackupCreated`] and, if pruning failed, a warning.
fn emit_backup<N: Fn()>(out: &Emitter<N>, backup: BackupInfo) {
    let warning = backup.prune_warning.clone();
    out.emit(Event::BackupCreated(backup));
    if let Some(w) = warning {
        out.error(format!(
            "Backup created but old backups could not be pruned: {w}"
        ));
    }
}

/// Restores `files` (original paths) of the listed backup `dir`.
///
/// A passphrase needed but missing emits [`Event::PassphraseNeeded`] with `original`.
fn restore_backup<N: Fn()>(
    out: &Emitter<N>,
    config: &WorkerConfig,
    dir: &Path,
    files: &[PathBuf],
    passphrase: Option<&SecretValue>,
    original: &Command,
) -> Result<()> {
    if files.is_empty() {
        return Err(invalid(MSG_NO_RESTORE_FILES));
    }
    let backups = config.backups.list()?;
    let Some(info) = backups.iter().find(|b| b.dir == dir) else {
        return Err(invalid(MSG_UNKNOWN_BACKUP));
    };
    let mut selected: Vec<BackupFile> = Vec::with_capacity(files.len());
    for file in files {
        let Some(entry) = info.files.iter().find(|f| &f.original == file) else {
            return Err(invalid(format!("File not in backup: {}", file.display())));
        };
        selected.push(entry.clone());
    }
    let report = match restore(
        &config.backups,
        info,
        &selected,
        &config.keyrings_dir,
        passphrase,
    ) {
        Ok(report) => report,
        Err(KringError::PassphraseRequired) => {
            out.emit(Event::PassphraseNeeded(Box::new(original.clone())));
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    if let Some(pre) = report.pre_restore_backup.clone() {
        emit_backup(out, pre);
    }
    out.emit(Event::RestoreDone(report));
    out.emit(Event::Done(format!(
        "Restore complete. Restart the daemon to load it: {RESTART_HINT}"
    )));
    Ok(())
}

/// Exports every item (with its secret) of an unlocked collection to an archive.
async fn export<S: SecretStore, N: Fn()>(
    out: &Emitter<N>,
    store: &S,
    collection: &CollectionId,
    path: &Path,
    passphrase: &SecretValue,
) -> Result<()> {
    let collections = store.list_collections().await?;
    let Some(info) = collections.iter().find(|c| &c.id == collection) else {
        return Err(KringError::NotFound(collection.0.clone()));
    };
    if info.locked {
        return Err(KringError::Locked(collection.0.clone()));
    }
    let mut items = Vec::new();
    for item in store.list_items(collection).await? {
        let secret = store.read_secret(&item.id).await?;
        items.push(ExportedItem {
            collection: info.label.clone(),
            item: OfflineItem {
                label: item.label,
                attributes: item.attributes,
                secret,
                created: item.created,
                modified: item.modified,
            },
        });
    }
    write_archive(path, &items, passphrase)?;
    out.emit(Event::Done(format!(
        "Exported {} items to {}",
        items.len(),
        path.display()
    )));
    Ok(())
}

#[cfg(test)]
mod tests;
