//! Background worker: runs Secret Service commands off the UI thread.
//!
//! The UI sends [`Command`]s and receives [`Event`]s over std channels. The worker
//! owns a current-thread tokio runtime and exits when the command sender is dropped.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use kring_core::backup::{
    BACKUP_KEEP, BackupInfo, BackupManager, RestoreReport, keyring_backup_set,
};
use kring_core::keyring_file::KeyringFileInfo;
use kring_core::keyring_file::textual::{OfflineItem, ParseWarning};
use kring_core::model::{
    CollectionId, CollectionInfo, ItemId, ItemInfo, ItemUpdate, NewItem, SecretValue,
    decode_path_segment,
};
use kring_core::pam::{PamStatus, pam_status};
use kring_core::paths;
use kring_core::provider::ProviderInfo;
use kring_core::transfer::import::ImportReport;
use kring_core::{KringError, MasterPasswordStore, SecretStore};

use crate::worker_offline;

/// Default PAM configuration directory.
const PAM_DIR: &str = "/etc/pam.d";
/// Message used when the provider forbids an operation.
const MSG_UNSUPPORTED: &str = "Not supported on this provider";
/// Message used when no provider is running.
pub(crate) const MSG_NO_PROVIDER: &str = "No Secret Service provider running";
/// Object path prefix of Secret Service collections.
const COLLECTION_PATH_PREFIX: &str = "/org/freedesktop/secrets/collection/";
/// Name of gnome-keyring's in-memory collection (it has no keyring file).
const SESSION_COLLECTION: &str = "session";
/// Suffix of refusals to delete without a backup.
const MSG_NO_BACKUP: &str = "refusing to delete without a backup";

/// A request from the UI to the worker.
#[derive(Clone, Debug)]
pub enum Command {
    /// Re-list all collections.
    Refresh,
    /// List the items of a collection.
    LoadItems(CollectionId),
    /// Read the secret of an item.
    RevealSecret(ItemId),
    /// Create an item in a collection.
    CreateItem {
        collection: CollectionId,
        item: NewItem,
    },
    /// Apply a partial update to an item.
    UpdateItem { item: ItemId, update: ItemUpdate },
    /// Delete an item after backing up the keyrings.
    DeleteItem {
        item: ItemId,
        backup_passphrase: Option<SecretValue>,
    },
    /// Make a collection the default one.
    SetDefault(CollectionId),
    /// Lock a collection.
    Lock(CollectionId),
    /// Unlock a collection with its password.
    Unlock {
        collection: CollectionId,
        password: SecretValue,
    },
    /// Create a collection protected by a password.
    CreateCollection {
        label: String,
        password: SecretValue,
    },
    /// Change the label of a collection.
    RenameCollection {
        collection: CollectionId,
        label: String,
    },
    /// Change the password of a collection.
    ChangePassword {
        collection: CollectionId,
        old: SecretValue,
        new: SecretValue,
    },
    /// Delete a collection after backing up the keyrings.
    DeleteCollection {
        collection: CollectionId,
        backup_passphrase: Option<SecretValue>,
    },
    /// Scan the keyrings directory for `*.keyring` files.
    ScanFiles,
    /// Read the items of a keyring file offline (binary files need its password).
    OpenFile {
        name: String,
        password: Option<SecretValue>,
    },
    /// Copy the items of a keyring file into a collection.
    ImportFile {
        name: String,
        password: Option<SecretValue>,
        target: CollectionId,
    },
    /// Retire a plaintext keyring file (live ones go through `DeleteCollection`).
    RetireFile {
        name: String,
        backup_passphrase: SecretValue,
    },
    /// List the backups.
    ListBackups,
    /// Restore files (by original path) of a listed backup into the keyrings directory.
    RestoreBackup {
        dir: PathBuf,
        files: Vec<PathBuf>,
        passphrase: Option<SecretValue>,
    },
    /// Export an unlocked collection to an age-encrypted archive.
    ExportCollection {
        collection: CollectionId,
        path: PathBuf,
        passphrase: SecretValue,
    },
    /// Import the items of an archive into a collection.
    ImportArchive {
        path: PathBuf,
        passphrase: SecretValue,
        target: CollectionId,
    },
}

/// A notification from the worker to the UI.
#[derive(Clone, Debug)]
pub enum Event {
    /// The detected provider.
    Provider(ProviderInfo),
    /// No Secret Service provider is running.
    ProviderUnavailable,
    /// PAM auto-unlock status.
    Pam(PamStatus),
    /// Current list of collections.
    Collections(Vec<CollectionInfo>),
    /// Items of a collection.
    Items(CollectionId, Vec<ItemInfo>),
    /// A revealed secret.
    Secret(ItemId, SecretValue),
    /// A backup was written.
    BackupCreated(BackupInfo),
    /// A backup needs a passphrase; carries the command to resend with it.
    PassphraseNeeded(Box<Command>),
    /// Keyring files found in the keyrings directory.
    Files(Vec<KeyringFileInfo>),
    /// Items read offline from keyring file `name` (secrets are for display only).
    FileItems {
        name: String,
        items: Vec<OfflineItem>,
        warnings: Vec<ParseWarning>,
    },
    /// Binary keyring file `name` needs its password; resend the command with it.
    PasswordNeeded(String),
    /// An import finished.
    ImportDone(ImportReport),
    /// Current list of backups, newest first.
    Backups(Vec<BackupInfo>),
    /// A restore finished.
    RestoreDone(RestoreReport),
    /// An operation finished with a message.
    Done(String),
    /// An operation failed with a message.
    Error(String),
}

/// Filesystem locations used by the worker.
#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// Backup manager used before destructive operations.
    pub backups: BackupManager,
    /// Directory holding the gnome-keyring files.
    pub keyrings_dir: PathBuf,
    /// PAM configuration directory.
    pub pam_dir: PathBuf,
}

impl WorkerConfig {
    /// Builds the configuration with the real user paths.
    pub fn default_paths() -> Self {
        Self {
            backups: BackupManager {
                root: paths::backups_dir(),
                keep: BACKUP_KEEP,
            },
            keyrings_dir: paths::keyrings_dir(),
            pam_dir: PathBuf::from(PAM_DIR),
        }
    }
}

/// UI-side endpoints of the worker.
pub struct WorkerHandle {
    /// Sends commands to the worker.
    pub tx: Sender<Command>,
    /// Receives events from the worker.
    pub rx: Receiver<Event>,
}

/// Event sink that wakes the UI after each event.
pub(crate) struct Emitter<N: Fn()> {
    tx: Sender<Event>,
    notify: N,
}

impl<N: Fn()> Emitter<N> {
    /// Sends an event and calls the notify callback.
    pub(crate) fn emit(&self, event: Event) {
        // A closed receiver means the UI is gone; nothing left to report to.
        let _ = self.tx.send(event);
        (self.notify)();
    }

    /// Emits an error event.
    pub(crate) fn error(&self, message: impl Into<String>) {
        self.emit(Event::Error(message.into()));
    }
}

/// Spawns the worker thread and returns the UI endpoints.
pub fn spawn<S>(
    store: Option<Arc<S>>,
    provider: Option<ProviderInfo>,
    config: WorkerConfig,
    notify: impl Fn() + Send + 'static,
) -> WorkerHandle
where
    S: SecretStore + MasterPasswordStore + 'static,
{
    let (cmd_tx, cmd_rx) = channel::<Command>();
    let (ev_tx, ev_rx) = channel::<Event>();
    std::thread::spawn(move || {
        let out = Emitter { tx: ev_tx, notify };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let runtime = match runtime {
            Ok(rt) => rt,
            Err(e) => return out.error(format!("Cannot start worker runtime: {e}")),
        };
        let first = startup(&out, store.as_deref(), provider.as_ref(), &config);
        run_guarded(&out, &runtime, first);
        while let Ok(cmd) = cmd_rx.recv() {
            let run = handle(&out, store.as_deref(), provider.as_ref(), &config, cmd);
            run_guarded(&out, &runtime, run);
        }
    });
    WorkerHandle {
        tx: cmd_tx,
        rx: ev_rx,
    }
}

/// Runs a future to completion, reporting a panic as an error instead of killing the worker.
fn run_guarded<N: Fn()>(
    out: &Emitter<N>,
    runtime: &tokio::runtime::Runtime,
    fut: impl std::future::Future<Output = ()>,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.block_on(fut)));
    if let Err(payload) = result {
        out.error(format!("Worker crashed: {}", panic_message(&*payload)));
    }
}

/// Extracts a printable message from a panic payload.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(m) = payload.downcast_ref::<&str>() {
        return (*m).to_string();
    }
    if let Some(m) = payload.downcast_ref::<String>() {
        return m.clone();
    }
    "unknown".to_string()
}

/// Emits the initial provider, PAM and collection events.
async fn startup<S: SecretStore, N: Fn()>(
    out: &Emitter<N>,
    store: Option<&S>,
    provider: Option<&ProviderInfo>,
    config: &WorkerConfig,
) {
    match (store, provider) {
        (Some(_), Some(p)) => out.emit(Event::Provider(p.clone())),
        _ => out.emit(Event::ProviderUnavailable),
    }
    out.emit(Event::Pam(pam_status(&config.pam_dir)));
    if let Some(store) = store {
        refresh(out, store).await;
    }
}

/// Lists collections and emits them, or an error.
pub(crate) async fn refresh<S: SecretStore, N: Fn()>(out: &Emitter<N>, store: &S) {
    match store.list_collections().await {
        Ok(list) => out.emit(Event::Collections(list)),
        Err(e) => out.error(e.to_string()),
    }
}

/// Lists the items of a collection and emits them, or an error.
pub(crate) async fn load_items<S: SecretStore, N: Fn()>(
    out: &Emitter<N>,
    store: &S,
    id: &CollectionId,
) {
    match store.list_items(id).await {
        Ok(list) => out.emit(Event::Items(id.clone(), list)),
        Err(e) => out.error(e.to_string()),
    }
}

/// Returns the parent object path of an item (its collection).
fn collection_of(item: &ItemId) -> CollectionId {
    let parent = item.0.rsplit_once('/').map_or("", |(parent, _)| parent);
    CollectionId(parent.to_string())
}

/// Returns the keyring file name of a collection (`<name>` of `<name>.keyring`).
///
/// gnome-keyring names the object path after the file, escaping every byte that is
/// not alphanumeric as `_XX`: `.../collection/My_5fKeys` is stored in `My_Keys.keyring`.
/// The in-memory `session` collection yields `Ok(None)`. A path that is not a
/// collection path, a malformed escape, or a decoded name that is empty, `.`, `..`
/// or contains `/` is an error message (the delete stays refused).
fn keyring_name(collection: &CollectionId) -> Result<Option<String>, String> {
    let refuse = || {
        format!(
            "Cannot find the keyring file of {}: {MSG_NO_BACKUP}",
            collection.0
        )
    };
    let segment = collection.0.strip_prefix(COLLECTION_PATH_PREFIX);
    let Some(segment) = segment.filter(|n| !n.is_empty() && !n.contains('/')) else {
        return Err(refuse());
    };
    let name = decode_path_segment(segment).map_err(|_| refuse())?;
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(refuse());
    }
    if name == SESSION_COLLECTION {
        return Ok(None);
    }
    Ok(Some(name))
}

/// Result of the backup step before a destructive operation.
enum BackupStep {
    /// Go ahead; carries the backup directory (`None` when no backup was needed).
    Proceed(Option<PathBuf>),
    /// The command was answered (passphrase requested or error reported) and must not run.
    Stop,
}

/// Backs up all keyrings before deleting from `collection`, failing closed.
///
/// The collection's own keyring file must be part of the backup, otherwise the
/// delete is refused; the in-memory `session` collection needs no backup.
fn backup_before<N: Fn()>(
    out: &Emitter<N>,
    config: &WorkerConfig,
    collection: &CollectionId,
    reason: &str,
    passphrase: Option<&SecretValue>,
    original: &Command,
) -> BackupStep {
    let name = match keyring_name(collection) {
        Ok(Some(name)) => name,
        Ok(None) => return BackupStep::Proceed(None),
        Err(message) => {
            out.error(message);
            return BackupStep::Stop;
        }
    };
    let files = match keyring_backup_set(&config.keyrings_dir) {
        Ok(files) => files,
        Err(e) => {
            out.error(format!("Backup failed, nothing was deleted: {e}"));
            return BackupStep::Stop;
        }
    };
    let target = config.keyrings_dir.join(format!("{name}.keyring"));
    if !files.contains(&target) {
        let dir = config.keyrings_dir.display();
        out.error(format!(
            "No keyring file found for '{name}' in {dir}: {MSG_NO_BACKUP}"
        ));
        return BackupStep::Stop;
    }
    match config.backups.create(reason, &files, passphrase) {
        Ok(info) => {
            let dir = info.dir.clone();
            let warning = info.prune_warning.clone();
            out.emit(Event::BackupCreated(info));
            if let Some(w) = warning {
                out.error(format!(
                    "Backup created but old backups could not be pruned: {w}"
                ));
            }
            BackupStep::Proceed(Some(dir))
        }
        Err(KringError::PassphraseRequired) => {
            out.emit(Event::PassphraseNeeded(Box::new(original.clone())));
            BackupStep::Stop
        }
        Err(e) => {
            out.error(format!("Backup failed, nothing was deleted: {e}"));
            BackupStep::Stop
        }
    }
}

/// Builds the success message of a delete, naming the backup when one was made.
fn deleted_message(what: &str, backup: Option<&PathBuf>) -> String {
    match backup {
        Some(dir) => format!("{what} deleted, backup in {}", dir.display()),
        None => format!("{what} deleted"),
    }
}

/// Returns true if the command is allowed on this provider; otherwise emits an error.
fn gate<N: Fn()>(out: &Emitter<N>, provider: Option<&ProviderInfo>, cmd: &Command) -> bool {
    let (needs_writes, needs_master) = match cmd {
        Command::DeleteItem { .. }
        | Command::DeleteCollection { .. }
        | Command::RenameCollection { .. } => (true, false),
        Command::ChangePassword { .. } => (true, true),
        Command::CreateCollection { .. } | Command::Unlock { .. } => (false, true),
        _ => (false, false),
    };
    let allowed = match provider {
        None => !needs_writes && !needs_master,
        Some(p) => {
            (!needs_writes || p.allows_writes()) && (!needs_master || p.has_master_password_iface)
        }
    };
    if !allowed {
        out.error(MSG_UNSUPPORTED);
    }
    allowed
}

/// Handles one command and emits the resulting events.
///
/// Offline commands (files, backups, archives) are routed to [`worker_offline`].
async fn handle<S, N>(
    out: &Emitter<N>,
    store: Option<&S>,
    provider: Option<&ProviderInfo>,
    config: &WorkerConfig,
    cmd: Command,
) where
    S: SecretStore + MasterPasswordStore,
    N: Fn(),
{
    if worker_offline::is_offline(&cmd) {
        return worker_offline::handle(out, store, provider, config, cmd).await;
    }
    let Some(store) = store else {
        return out.error(MSG_NO_PROVIDER);
    };
    run_store_command(out, store, provider, config, cmd).await;
}

/// Gates and runs a store command, reporting errors (and refreshing after `NotFound`).
pub(crate) async fn run_store_command<S, N>(
    out: &Emitter<N>,
    store: &S,
    provider: Option<&ProviderInfo>,
    config: &WorkerConfig,
    cmd: Command,
) where
    S: SecretStore + MasterPasswordStore,
    N: Fn(),
{
    if !gate(out, provider, &cmd) {
        return;
    }
    match run(out, store, config, &cmd).await {
        Ok(()) => {}
        Err(e) => {
            out.error(e.to_string());
            if matches!(e, KringError::NotFound(_)) {
                refresh(out, store).await;
            }
        }
    }
}

/// Executes a gated command against the store.
///
/// Successful mutations re-list collections (and the affected items) and end
/// with an [`Event::Done`]. Returns `Ok` also when the command was answered
/// without running (backup passphrase requested or backup failed).
async fn run<S, N>(
    out: &Emitter<N>,
    store: &S,
    config: &WorkerConfig,
    cmd: &Command,
) -> kring_core::Result<()>
where
    S: SecretStore + MasterPasswordStore,
    N: Fn(),
{
    // Collection whose items are re-listed after a successful mutation.
    let mut affected: Option<CollectionId> = None;
    let done: String = match cmd {
        Command::Refresh => {
            refresh(out, store).await;
            return Ok(());
        }
        Command::LoadItems(id) => {
            load_items(out, store, id).await;
            return Ok(());
        }
        Command::RevealSecret(id) => {
            let secret = store.read_secret(id).await?;
            out.emit(Event::Secret(id.clone(), secret));
            return Ok(());
        }
        Command::CreateItem { collection, item } => {
            store.create_item(collection, item.clone()).await?;
            affected = Some(collection.clone());
            "Item created".into()
        }
        Command::UpdateItem { item, update } => {
            store.update_item(item, update.clone()).await?;
            affected = Some(collection_of(item));
            "Item updated".into()
        }
        Command::DeleteItem {
            item,
            backup_passphrase,
        } => {
            let parent = collection_of(item);
            let pass = backup_passphrase.as_ref();
            let BackupStep::Proceed(backup) =
                backup_before(out, config, &parent, "delete-item", pass, cmd)
            else {
                return Ok(());
            };
            store.delete_item(item).await?;
            affected = Some(parent);
            deleted_message("Item", backup.as_ref())
        }
        Command::SetDefault(id) => {
            store.set_alias("default", id).await?;
            "Default collection set".into()
        }
        Command::Lock(id) => {
            store.lock(id).await?;
            affected = Some(id.clone());
            "Collection locked".into()
        }
        Command::Unlock {
            collection,
            password,
        } => {
            store.unlock_with_password(collection, password).await?;
            affected = Some(collection.clone());
            "Collection unlocked".into()
        }
        Command::CreateCollection { label, password } => {
            store.create_with_password(label, password).await?;
            "Collection created".into()
        }
        Command::RenameCollection { collection, label } => {
            store.rename_collection(collection, label).await?;
            affected = Some(collection.clone());
            "Collection renamed".into()
        }
        Command::ChangePassword {
            collection,
            old,
            new,
        } => {
            store.change_password(collection, old, new).await?;
            affected = Some(collection.clone());
            "Password changed".into()
        }
        Command::DeleteCollection {
            collection,
            backup_passphrase,
        } => {
            let pass = backup_passphrase.as_ref();
            let BackupStep::Proceed(backup) =
                backup_before(out, config, collection, "delete-collection", pass, cmd)
            else {
                return Ok(());
            };
            store.delete_collection(collection).await?;
            deleted_message("Collection", backup.as_ref())
        }
        Command::ScanFiles
        | Command::OpenFile { .. }
        | Command::ImportFile { .. }
        | Command::RetireFile { .. }
        | Command::ListBackups
        | Command::RestoreBackup { .. }
        | Command::ExportCollection { .. }
        | Command::ImportArchive { .. } => {
            return Err(KringError::InvalidInput(
                "Offline command sent to the store path".into(),
            ));
        }
    };
    refresh(out, store).await;
    if let Some(id) = affected {
        load_items(out, store, &id).await;
    }
    out.emit(Event::Done(done));
    Ok(())
}

#[cfg(test)]
mod tests;
