//! Worker handlers for offline features: keyring files, backups and archives.
//!
//! Importing files and archives is planned in [`crate::worker_transfer`],
//! which reads them through [`resolve_file`] and [`read_file`].
//!
//! Keyring files are addressed by name only (`<name>.keyring` inside
//! [`WorkerConfig::keyrings_dir`]); the path is always taken from a fresh scan,
//! never from the UI. Backups are addressed by a directory that must be among
//! [`BackupManager::list`](kring_core::backup::BackupManager::list).

use std::path::{Path, PathBuf};

use kring_core::backup::{
    BackupFile, BackupInfo, RESTART_HINT, is_plaintext_keyring, keyring_backup_set, restore,
};
use kring_core::keyring_file::binary::read_binary;
use kring_core::keyring_file::textual::{OfflineItem, ParseWarning, parse_textual};
use kring_core::keyring_file::{
    DeleteBackup, KeyringFileInfo, KeyringFormat, RetireMode, delete_file, retire_file,
    retire_mode, scan_dir,
};
use kring_core::model::{CollectionId, CollectionInfo, SecretValue};
use kring_core::provider::ProviderInfo;
use kring_core::transfer::archive::{ExportedItem, write_archive};
use kring_core::{KringError, MasterPasswordStore, Result, SecretStore};
use zeroize::Zeroizing;

use crate::worker::{
    Command, Emitter, Event, MSG_NO_PROVIDER, WorkerConfig, gate, passphrase_echo, refresh,
    run_store_command,
};

/// Message for a file name that could escape the keyrings directory.
const MSG_BAD_NAME: &str = "Invalid keyring file name";
/// Message for a backup directory that is not among the listed backups.
const MSG_UNKNOWN_BACKUP: &str = "Unknown backup";
/// Message for a restore without files.
const MSG_NO_RESTORE_FILES: &str = "No files selected for restore";
/// Message for a retire request on a file that is not plaintext.
const MSG_NOT_PLAINTEXT: &str = "Only plaintext keyring files can be retired";
/// Message after a plaintext file was retired.
const MSG_RETIRED: &str = "Plaintext file retired";
/// Refusal of a delete without backup of a live keyring that holds items.
const MSG_LIVE_NEEDS_BACKUP: &str = "Loaded keyrings are always backed up before deletion";
/// Message after an empty live keyring was deleted without a backup.
const MSG_EMPTY_KEYRING_DELETED: &str = "Empty keyring deleted";
/// Extension of keyring files.
const KEYRING_EXTENSION: &str = "keyring";

/// Returns true for commands handled by this module.
pub(crate) fn is_offline(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::ScanFiles
            | Command::OpenFile { .. }
            | Command::RetireFile { .. }
            | Command::DeleteFile { .. }
            | Command::ListBackups
            | Command::RestoreBackup { .. }
            | Command::ExportCollection { .. }
    )
}

/// Handles one offline command and reports a failure as [`Event::Error`].
///
/// `ExportCollection` needs a store (any provider); the other commands work
/// without one.
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
        Command::RetireFile {
            name,
            backup_passphrase,
        } => retire(out, store, provider, config, name, backup_passphrase).await,
        Command::DeleteFile {
            name,
            backup,
            backup_passphrase,
        } => {
            let backup = match backup {
                true => DeleteBackup::With(backup_passphrase.clone()),
                false => DeleteBackup::Without,
            };
            delete(out, store, provider, config, name, backup, cmd).await
        }
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
        _ => Err(KringError::InvalidInput(
            "Store command sent to the offline path".into(),
        )),
    }
}

/// Returns true for offline commands that cannot run without a store.
fn needs_store(cmd: &Command) -> bool {
    matches!(cmd, Command::ExportCollection { .. })
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
pub(crate) fn resolve_file(config: &WorkerConfig, name: &str) -> Result<KeyringFileInfo> {
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
pub(crate) async fn read_file<N: Fn()>(
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

/// Retires plaintext keyring file `name`; any other file is refused first.
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
    // Checked before the live branch: a binary file must never reach DeleteCollection.
    if info.format == KeyringFormat::BinaryV0 || !info.plaintext {
        return Err(invalid(MSG_NOT_PLAINTEXT));
    }
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

/// Deletes keyring file `name` (any format).
///
/// The live check uses the store's collections; if a store exists but cannot
/// list them the delete is aborted. A file the daemon serves is deleted as a
/// collection (see [`delete_live`]); any other file through
/// [`delete_file`]. A backup needing a passphrase that is missing emits
/// [`Event::PassphraseNeeded`] with the echo of `original`.
async fn delete<S, N>(
    out: &Emitter<N>,
    store: Option<&S>,
    provider: Option<&ProviderInfo>,
    config: &WorkerConfig,
    name: &str,
    backup: DeleteBackup,
    original: &Command,
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
    if let (RetireMode::DeleteLiveCollection(id), Some(store)) = (retire_mode(&info, &live), store)
    {
        let Some(collection) = live.iter().find(|c| c.id == id) else {
            return Err(invalid(format!("No keyring file named '{name}'")));
        };
        let request = LiveDelete {
            collection,
            backup,
            original,
        };
        return delete_live(out, store, provider, config, request).await;
    }
    let report = match delete_file(&config.backups, &info, &config.keyrings_dir, &live, backup) {
        Ok(report) => report,
        Err(KringError::PassphraseRequired) => {
            out.emit(passphrase_echo(original));
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let done = match &report.backup {
        Some(b) => format!(
            "File {} deleted, backup in {}",
            report.removed,
            b.dir.display()
        ),
        None => format!("File {} deleted", report.removed),
    };
    if let Some(backup) = report.backup {
        emit_backup(out, backup);
    }
    out.emit(Event::Done(done));
    emit_files(out, config)
}

/// A delete request on the file of a live collection.
struct LiveDelete<'a> {
    /// The live collection, freshly listed.
    collection: &'a CollectionInfo,
    /// Backup choice of the request.
    backup: DeleteBackup,
    /// The `DeleteFile` command, echoed when a passphrase is missing.
    original: &'a Command,
}

/// Deletes the file of a live collection through the daemon.
///
/// The Plan 1 `DeleteCollection` flow (gate, backup of all keyrings) is used.
/// Without a backup only an empty collection (no items, freshly listed) is
/// deleted, still behind the write gate; otherwise the request is refused.
/// A plaintext keyring in the backup set without a passphrase emits
/// [`Event::PassphraseNeeded`] with the echo of the `DeleteFile` command.
async fn delete_live<S, N>(
    out: &Emitter<N>,
    store: &S,
    provider: Option<&ProviderInfo>,
    config: &WorkerConfig,
    request: LiveDelete<'_>,
) -> Result<()>
where
    S: SecretStore + MasterPasswordStore,
    N: Fn(),
{
    let collection = request.collection.id.clone();
    let passphrase = match request.backup {
        DeleteBackup::With(passphrase) => passphrase,
        // Fail closed: a locked keyring never counts as empty.
        DeleteBackup::Without if !is_empty_unlocked(request.collection) => {
            return Err(invalid(MSG_LIVE_NEEDS_BACKUP));
        }
        DeleteBackup::Without => {
            // Same write gate as the Plan 1 delete, without its backup.
            let gated = Command::DeleteCollection {
                collection: collection.clone(),
                backup_passphrase: None,
            };
            if !gate(out, provider, &gated) {
                return Ok(());
            }
            // TOCTOU: an item could be added between the fresh listing above
            // and this call; the Secret Service has no conditional delete, so
            // the window is kept as small as possible but cannot be closed.
            match store.delete_collection(&collection).await {
                Ok(()) => {
                    refresh(out, store).await;
                    out.emit(Event::Done(MSG_EMPTY_KEYRING_DELETED.into()));
                }
                // Reported like `run_store_command`: NotFound re-lists the collections.
                Err(e) => {
                    out.error(e.to_string());
                    if matches!(e, KringError::NotFound(_)) {
                        refresh(out, store).await;
                    }
                }
            }
            return emit_files(out, config);
        }
    };
    if passphrase.is_none() && backup_needs_passphrase(config)? {
        out.emit(passphrase_echo(request.original));
        return Ok(());
    }
    let delete = Command::DeleteCollection {
        collection,
        backup_passphrase: passphrase,
    };
    run_store_command(out, store, provider, config, delete).await;
    emit_files(out, config)
}

/// Returns true for a live keyring that may be deleted without a backup:
/// unlocked and without items (a locked keyring may hide its items).
fn is_empty_unlocked(c: &CollectionInfo) -> bool {
    !c.locked && c.item_count == 0
}

/// Returns true when the backup of all keyrings holds a plaintext keyring
/// (it is then encrypted and needs a passphrase), as `BackupManager` decides.
fn backup_needs_passphrase(config: &WorkerConfig) -> Result<bool> {
    for path in keyring_backup_set(&config.keyrings_dir)? {
        if path.extension().is_none_or(|e| e != KEYRING_EXTENSION) {
            continue;
        }
        let bytes = Zeroizing::new(std::fs::read(&path).map_err(|e| KringError::Io {
            path: path.clone(),
            message: e.to_string(),
        })?);
        if is_plaintext_keyring(&bytes) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Emits [`Event::BackupCreated`]; a prune failure travels in
/// `prune_warning` and is shown as a notice, never as an error.
pub(crate) fn emit_backup<N: Fn()>(out: &Emitter<N>, backup: BackupInfo) {
    out.emit(Event::BackupCreated(backup));
}

/// Restores `files` (original paths) of the listed backup `dir`.
///
/// A passphrase needed but missing emits [`Event::PassphraseNeeded`] with the echo of `original`.
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
            out.emit(passphrase_echo(original));
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
                secret_missing: false,
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
