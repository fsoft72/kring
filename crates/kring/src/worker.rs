//! Background worker: runs Secret Service commands off the UI thread.
//!
//! The UI sends [`Command`]s and receives [`Event`]s over std channels. The worker
//! owns a current-thread tokio runtime and exits when the command sender is dropped.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use kring_core::backup::{BACKUP_KEEP, BackupInfo, BackupManager, keyring_backup_set};
use kring_core::model::{
    CollectionId, CollectionInfo, ItemId, ItemInfo, ItemUpdate, NewItem, SecretValue,
    decode_path_segment,
};
use kring_core::pam::{PamStatus, pam_status};
use kring_core::paths;
use kring_core::provider::ProviderInfo;
use kring_core::{KringError, MasterPasswordStore, SecretStore};

/// Default PAM configuration directory.
const PAM_DIR: &str = "/etc/pam.d";
/// Message used when the provider forbids an operation.
const MSG_UNSUPPORTED: &str = "Not supported on this provider";
/// Message used when no provider is running.
const MSG_NO_PROVIDER: &str = "No Secret Service provider running";
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
struct Emitter<N: Fn()> {
    tx: Sender<Event>,
    notify: N,
}

impl<N: Fn()> Emitter<N> {
    /// Sends an event and calls the notify callback.
    fn emit(&self, event: Event) {
        // A closed receiver means the UI is gone; nothing left to report to.
        let _ = self.tx.send(event);
        (self.notify)();
    }

    /// Emits an error event.
    fn error(&self, message: impl Into<String>) {
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
async fn refresh<S: SecretStore, N: Fn()>(out: &Emitter<N>, store: &S) {
    match store.list_collections().await {
        Ok(list) => out.emit(Event::Collections(list)),
        Err(e) => out.error(e.to_string()),
    }
}

/// Lists the items of a collection and emits them, or an error.
async fn load_items<S: SecretStore, N: Fn()>(out: &Emitter<N>, store: &S, id: &CollectionId) {
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
    let Some(store) = store else {
        return out.error(MSG_NO_PROVIDER);
    };
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
    };
    refresh(out, store).await;
    if let Some(id) = affected {
        load_items(out, store, &id).await;
    }
    out.emit(Event::Done(done));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kring_core::backup::KEYRING_MAGIC;
    use kring_core::fake_store::FakeStore;
    use kring_core::provider::ProviderKind;

    use super::*;

    /// Label (and object path name) of the fixture collection.
    const MAIN: &str = "Main";

    /// Test fixture owning the temp dirs and the worker handle.
    struct Fixture {
        _dir: tempfile::TempDir,
        keyrings: PathBuf,
        backups: PathBuf,
        handle: WorkerHandle,
        collection: CollectionId,
    }

    /// Builds a provider of the given kind.
    fn provider(kind: ProviderKind, master: bool) -> ProviderInfo {
        ProviderInfo {
            kind,
            pid: None,
            process_name: None,
            competitors: vec![],
            has_master_password_iface: master,
        }
    }

    /// Starts a worker over a FakeStore with one unlocked collection named `Main`.
    fn fixture(provider: Option<ProviderInfo>) -> Fixture {
        fixture_with(provider, MAIN, BACKUP_KEEP)
    }

    /// Starts a worker over a FakeStore with one unlocked collection `label`, keeping `keep` backups.
    fn fixture_with(provider: Option<ProviderInfo>, label: &str, keep: usize) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let keyrings = dir.path().join("keyrings");
        let backups = dir.path().join("backups");
        let pam = dir.path().join("pam");
        for d in [&keyrings, &pam] {
            std::fs::create_dir_all(d).unwrap();
        }
        let store = FakeStore::new();
        let collection = store.add_collection(label, "pw", false);
        let config = WorkerConfig {
            backups: BackupManager {
                root: backups.clone(),
                keep,
            },
            keyrings_dir: keyrings.clone(),
            pam_dir: pam,
        };
        let handle = spawn(Some(Arc::new(store)), provider, config, || {});
        Fixture {
            _dir: dir,
            keyrings,
            backups,
            handle,
            collection,
        }
    }

    impl Fixture {
        /// Receives the next event, failing after 5 seconds.
        fn next(&self) -> Event {
            self.handle
                .rx
                .recv_timeout(Duration::from_secs(5))
                .expect("event expected")
        }

        /// Consumes the three startup events.
        fn skip_startup(&self) {
            for _ in 0..3 {
                self.next();
            }
        }

        /// Sends a command.
        fn send(&self, cmd: Command) {
            self.handle.tx.send(cmd).unwrap();
        }

        /// Asserts the next event is `Done(message)`.
        fn expect_done(&self, message: &str) {
            match self.next() {
                Event::Done(m) => assert_eq!(m, message),
                other => panic!("expected Done, got {other:?}"),
            }
        }

        /// Creates an item and returns its id, consuming the resulting events.
        fn create_item(&self) -> ItemId {
            self.send(Command::CreateItem {
                collection: self.collection.clone(),
                item: NewItem {
                    label: "site".into(),
                    attributes: Default::default(),
                    secret: SecretValue::from_text("s3cret"),
                    replace: false,
                },
            });
            assert!(matches!(self.next(), Event::Collections(_)));
            let id = match self.next() {
                Event::Items(_, items) => items[0].id.clone(),
                other => panic!("expected Items, got {other:?}"),
            };
            self.expect_done("Item created");
            id
        }
    }

    /// Writes a binary-looking `<name>.keyring` file and returns its path.
    fn write_binary_keyring(dir: &std::path::Path, name: &str) -> PathBuf {
        let mut bytes = KEYRING_MAGIC.to_vec();
        bytes.extend_from_slice(b"payload");
        let path = dir.join(format!("{name}.keyring"));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// Startup emits Provider, Pam, Collections in that order.
    #[test]
    fn starts_with_provider_and_collections() {
        let f = fixture(Some(provider(ProviderKind::GnomeKeyring, true)));
        assert!(matches!(f.next(), Event::Provider(_)));
        assert!(matches!(f.next(), Event::Pam(_)));
        match f.next() {
            Event::Collections(list) => assert_eq!(list.len(), 1),
            other => panic!("expected Collections, got {other:?}"),
        }
    }

    /// Without a store the worker reports unavailability and answers errors.
    #[test]
    fn no_provider_emits_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let config = WorkerConfig {
            backups: BackupManager {
                root: dir.path().join("b"),
                keep: BACKUP_KEEP,
            },
            keyrings_dir: dir.path().join("k"),
            pam_dir: dir.path().join("p"),
        };
        let h = spawn::<FakeStore>(None, None, config, || {});
        let next = || h.rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(next(), Event::ProviderUnavailable));
        assert!(matches!(next(), Event::Pam(_)));
        h.tx.send(Command::Refresh).unwrap();
        match next() {
            Event::Error(m) => assert_eq!(m, "No Secret Service provider running"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// The backup is created before the item is deleted and collections re-listed.
    #[test]
    fn delete_creates_backup_first() {
        let f = fixture(Some(provider(ProviderKind::GnomeKeyring, true)));
        write_binary_keyring(&f.keyrings, MAIN);
        f.skip_startup();
        let item = f.create_item();
        f.send(Command::DeleteItem {
            item,
            backup_passphrase: None,
        });
        let dir = match f.next() {
            Event::BackupCreated(info) => info.dir,
            other => panic!("expected BackupCreated, got {other:?}"),
        };
        assert!(matches!(f.next(), Event::Collections(_)));
        match f.next() {
            Event::Items(_, items) => assert!(items.is_empty()),
            other => panic!("expected Items, got {other:?}"),
        }
        f.expect_done(&format!("Item deleted, backup in {}", dir.display()));
        assert_eq!(std::fs::read_dir(&f.backups).unwrap().count(), 1);
    }

    /// Deleting is refused on a non gnome-keyring provider.
    #[test]
    fn delete_blocked_on_kwallet_provider() {
        let f = fixture(Some(provider(ProviderKind::KWallet, false)));
        f.skip_startup();
        f.send(Command::DeleteCollection {
            collection: f.collection.clone(),
            backup_passphrase: None,
        });
        match f.next() {
            Event::Error(m) => assert_eq!(m, "Not supported on this provider"),
            other => panic!("expected Error, got {other:?}"),
        }
        f.send(Command::Refresh);
        match f.next() {
            Event::Collections(list) => assert_eq!(list.len(), 1),
            other => panic!("expected Collections, got {other:?}"),
        }
    }

    /// Creating a collection needs the master password interface.
    #[test]
    fn create_collection_blocked_without_master_iface() {
        let f = fixture(Some(provider(ProviderKind::GnomeKeyring, false)));
        f.skip_startup();
        f.send(Command::CreateCollection {
            label: "x".into(),
            password: SecretValue::from_text("p"),
        });
        match f.next() {
            Event::Error(m) => assert_eq!(m, "Not supported on this provider"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// A NotFound error is reported and followed by a refresh.
    #[test]
    fn not_found_triggers_refresh() {
        let f = fixture(Some(provider(ProviderKind::GnomeKeyring, true)));
        f.skip_startup();
        f.send(Command::RevealSecret(ItemId(format!(
            "{}/missing",
            f.collection.0
        ))));
        assert!(matches!(f.next(), Event::Error(_)));
        assert!(matches!(f.next(), Event::Collections(_)));
    }

    /// A plaintext keyring needs a passphrase and the item is left in place.
    #[test]
    fn plaintext_keyring_asks_passphrase() {
        let f = fixture(Some(provider(ProviderKind::GnomeKeyring, true)));
        write_binary_keyring(&f.keyrings, MAIN);
        std::fs::write(
            f.keyrings.join("old.keyring"),
            "[keyring]\ndisplay-name=x\n",
        )
        .unwrap();
        f.skip_startup();
        let item = f.create_item();
        f.send(Command::DeleteItem {
            item,
            backup_passphrase: None,
        });
        match f.next() {
            Event::PassphraseNeeded(cmd) => assert!(matches!(*cmd, Command::DeleteItem { .. })),
            other => panic!("expected PassphraseNeeded, got {other:?}"),
        }
        f.send(Command::LoadItems(f.collection.clone()));
        match f.next() {
            Event::Items(_, items) => assert_eq!(items.len(), 1),
            other => panic!("expected Items, got {other:?}"),
        }
    }

    /// Store wrapper whose first `list_items` (or `list_collections`) call panics.
    struct PanicStore {
        inner: FakeStore,
        armed: std::sync::atomic::AtomicBool,
        /// Panic in `list_collections` instead of `list_items`.
        on_collections: bool,
    }

    impl PanicStore {
        /// Returns true (once) when the call named by `collections` must panic.
        fn fire(&self, collections: bool) -> bool {
            collections == self.on_collections
                && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl SecretStore for PanicStore {
        async fn list_collections(&self) -> kring_core::Result<Vec<CollectionInfo>> {
            if self.fire(true) {
                panic!("boom");
            }
            self.inner.list_collections().await
        }
        async fn list_items(&self, c: &CollectionId) -> kring_core::Result<Vec<ItemInfo>> {
            if self.fire(false) {
                panic!("boom");
            }
            self.inner.list_items(c).await
        }
        async fn read_secret(&self, i: &ItemId) -> kring_core::Result<SecretValue> {
            self.inner.read_secret(i).await
        }
        async fn create_item(&self, c: &CollectionId, i: NewItem) -> kring_core::Result<ItemId> {
            self.inner.create_item(c, i).await
        }
        async fn update_item(&self, i: &ItemId, u: ItemUpdate) -> kring_core::Result<()> {
            self.inner.update_item(i, u).await
        }
        async fn delete_item(&self, i: &ItemId) -> kring_core::Result<()> {
            self.inner.delete_item(i).await
        }
        async fn read_alias(&self, a: &str) -> kring_core::Result<Option<CollectionId>> {
            self.inner.read_alias(a).await
        }
        async fn set_alias(&self, a: &str, c: &CollectionId) -> kring_core::Result<()> {
            self.inner.set_alias(a, c).await
        }
        async fn lock(&self, c: &CollectionId) -> kring_core::Result<()> {
            self.inner.lock(c).await
        }
        async fn rename_collection(&self, c: &CollectionId, l: &str) -> kring_core::Result<()> {
            self.inner.rename_collection(c, l).await
        }
        async fn delete_collection(&self, c: &CollectionId) -> kring_core::Result<()> {
            self.inner.delete_collection(c).await
        }
    }

    #[async_trait::async_trait]
    impl MasterPasswordStore for PanicStore {
        async fn create_with_password(
            &self,
            l: &str,
            p: &SecretValue,
        ) -> kring_core::Result<CollectionId> {
            self.inner.create_with_password(l, p).await
        }
        async fn unlock_with_password(
            &self,
            c: &CollectionId,
            p: &SecretValue,
        ) -> kring_core::Result<()> {
            self.inner.unlock_with_password(c, p).await
        }
        async fn change_password(
            &self,
            c: &CollectionId,
            o: &SecretValue,
            n: &SecretValue,
        ) -> kring_core::Result<()> {
            self.inner.change_password(c, o, n).await
        }
    }

    /// Starts a worker over a PanicStore; returns the handle and the collection id.
    fn panic_worker(dir: &tempfile::TempDir, on_collections: bool) -> (WorkerHandle, CollectionId) {
        let config = WorkerConfig {
            backups: BackupManager {
                root: dir.path().join("b"),
                keep: BACKUP_KEEP,
            },
            keyrings_dir: dir.path().join("k"),
            pam_dir: dir.path().join("p"),
        };
        let inner = FakeStore::new();
        let id = inner.add_collection("Main", "pw", false);
        let store = PanicStore {
            inner,
            armed: std::sync::atomic::AtomicBool::new(true),
            on_collections,
        };
        let p = provider(ProviderKind::GnomeKeyring, true);
        (spawn(Some(Arc::new(store)), Some(p), config, || {}), id)
    }

    /// A panic during startup is reported and the worker keeps serving commands.
    #[test]
    fn startup_panic_reports_error_and_worker_survives() {
        let dir = tempfile::tempdir().unwrap();
        let (h, _) = panic_worker(&dir, true);
        let next = || h.rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(next(), Event::Provider(_)));
        assert!(matches!(next(), Event::Pam(_)));
        match next() {
            Event::Error(m) => assert_eq!(m, "Worker crashed: boom"),
            other => panic!("expected Error, got {other:?}"),
        }
        h.tx.send(Command::Refresh).unwrap();
        assert!(matches!(next(), Event::Collections(_)));
    }

    /// A panic in the store is reported and the worker keeps serving commands.
    #[test]
    fn store_panic_reports_error_and_worker_survives() {
        let dir = tempfile::tempdir().unwrap();
        let (h, id) = panic_worker(&dir, false);
        let next = || h.rx.recv_timeout(Duration::from_secs(5)).unwrap();
        for _ in 0..3 {
            next();
        }
        h.tx.send(Command::LoadItems(id)).unwrap();
        match next() {
            Event::Error(m) => assert_eq!(m, "Worker crashed: boom"),
            other => panic!("expected Error, got {other:?}"),
        }
        h.tx.send(Command::Refresh).unwrap();
        assert!(matches!(next(), Event::Collections(_)));
    }

    /// An unusable backups root aborts the delete and keeps the item.
    #[test]
    fn backup_failure_aborts_delete() {
        let f = fixture(Some(provider(ProviderKind::GnomeKeyring, true)));
        write_binary_keyring(&f.keyrings, MAIN);
        std::fs::write(&f.backups, "not a directory").unwrap();
        f.skip_startup();
        let item = f.create_item();
        f.send(Command::DeleteItem {
            item,
            backup_passphrase: None,
        });
        assert!(matches!(f.next(), Event::Error(_)));
        f.send(Command::LoadItems(f.collection.clone()));
        match f.next() {
            Event::Items(_, items) => assert_eq!(items.len(), 1),
            other => panic!("expected Items, got {other:?}"),
        }
    }

    /// Deleting a collection backs up first, then removes it.
    #[test]
    fn delete_collection_creates_backup_first() {
        let f = fixture(Some(provider(ProviderKind::GnomeKeyring, true)));
        write_binary_keyring(&f.keyrings, MAIN);
        f.skip_startup();
        f.send(Command::DeleteCollection {
            collection: f.collection.clone(),
            backup_passphrase: None,
        });
        let info = match f.next() {
            Event::BackupCreated(info) => info,
            other => panic!("expected BackupCreated, got {other:?}"),
        };
        assert_eq!(info.files[0].original, f.keyrings.join("Main.keyring"));
        match f.next() {
            Event::Collections(list) => assert!(list.is_empty()),
            other => panic!("expected Collections, got {other:?}"),
        }
        f.expect_done(&format!(
            "Collection deleted, backup in {}",
            info.dir.display()
        ));
    }

    /// Resending the delete with a passphrase succeeds after PassphraseNeeded.
    #[test]
    fn delete_with_passphrase_retry_succeeds() {
        let f = fixture(Some(provider(ProviderKind::GnomeKeyring, true)));
        write_binary_keyring(&f.keyrings, MAIN);
        std::fs::write(
            f.keyrings.join("old.keyring"),
            "[keyring]\ndisplay-name=x\n",
        )
        .unwrap();
        f.skip_startup();
        let item = f.create_item();
        f.send(Command::DeleteItem {
            item: item.clone(),
            backup_passphrase: None,
        });
        assert!(matches!(f.next(), Event::PassphraseNeeded(_)));
        f.send(Command::DeleteItem {
            item,
            backup_passphrase: Some(SecretValue::from_text("pass")),
        });
        assert!(matches!(f.next(), Event::BackupCreated(_)));
        assert!(matches!(f.next(), Event::Collections(_)));
        match f.next() {
            Event::Items(_, items) => assert!(items.is_empty()),
            other => panic!("expected Items, got {other:?}"),
        }
    }

    /// Without the collection's keyring file there is no backup, so nothing is deleted.
    #[test]
    fn missing_keyring_file_refuses_delete() {
        let f = fixture(Some(provider(ProviderKind::GnomeKeyring, true)));
        write_binary_keyring(&f.keyrings, "other");
        f.skip_startup();
        let item = f.create_item();
        f.send(Command::DeleteItem {
            item,
            backup_passphrase: None,
        });
        let expected = format!(
            "No keyring file found for 'Main' in {}: refusing to delete without a backup",
            f.keyrings.display()
        );
        match f.next() {
            Event::Error(m) => assert_eq!(m, expected),
            other => panic!("expected Error, got {other:?}"),
        }
        f.send(Command::DeleteCollection {
            collection: f.collection.clone(),
            backup_passphrase: None,
        });
        match f.next() {
            Event::Error(m) => assert_eq!(m, expected),
            other => panic!("expected Error, got {other:?}"),
        }
        f.send(Command::LoadItems(f.collection.clone()));
        match f.next() {
            Event::Items(_, items) => assert_eq!(items.len(), 1),
            other => panic!("expected Items, got {other:?}"),
        }
        assert!(!f.backups.exists());
    }

    /// The in-memory `session` collection has no file: it is deleted without a backup.
    #[test]
    fn session_collection_delete_skips_backup() {
        let f = fixture_with(
            Some(provider(ProviderKind::GnomeKeyring, true)),
            "session",
            BACKUP_KEEP,
        );
        f.skip_startup();
        let item = f.create_item();
        f.send(Command::DeleteItem {
            item,
            backup_passphrase: None,
        });
        assert!(matches!(f.next(), Event::Collections(_)));
        match f.next() {
            Event::Items(_, items) => assert!(items.is_empty()),
            other => panic!("expected Items, got {other:?}"),
        }
        f.expect_done("Item deleted");
        assert!(!f.backups.exists());
    }

    /// A failed prune is reported, but the backup exists so the delete proceeds.
    #[test]
    fn prune_failure_warns_and_deletes() {
        use std::os::unix::fs::PermissionsExt;
        let f = fixture_with(Some(provider(ProviderKind::GnomeKeyring, true)), MAIN, 1);
        let file = write_binary_keyring(&f.keyrings, MAIN);
        let old_mgr = BackupManager {
            root: f.backups.clone(),
            keep: 1,
        };
        let old = old_mgr.create("old", &[file], None).unwrap().dir;
        // Files inside a read-only directory cannot be unlinked, so pruning fails.
        let set_mode = |m| std::fs::set_permissions(&old, std::fs::Permissions::from_mode(m));
        set_mode(0o500).unwrap();
        f.skip_startup();
        let item = f.create_item();
        f.send(Command::DeleteItem {
            item,
            backup_passphrase: None,
        });
        let events: Vec<Event> = (0..5).map(|_| f.next()).collect();
        set_mode(0o700).unwrap();
        assert!(matches!(events[0], Event::BackupCreated(_)), "{events:?}");
        match &events[1] {
            Event::Error(m) => {
                assert!(
                    m.starts_with("Backup created but old backups could not be pruned: "),
                    "{m}"
                )
            }
            other => panic!("expected Error, got {other:?}"),
        }
        assert!(matches!(events[2], Event::Collections(_)), "{events:?}");
        match &events[3] {
            Event::Items(_, items) => assert!(items.is_empty()),
            other => panic!("expected Items, got {other:?}"),
        }
        assert!(matches!(events[4], Event::Done(_)), "{events:?}");
    }

    /// Successful mutations end with a Done message for the status bar.
    #[test]
    fn mutations_report_done() {
        let f = fixture(Some(provider(ProviderKind::GnomeKeyring, true)));
        f.skip_startup();
        f.send(Command::ChangePassword {
            collection: f.collection.clone(),
            old: SecretValue::from_text("pw"),
            new: SecretValue::from_text("pw2"),
        });
        assert!(matches!(f.next(), Event::Collections(_)));
        assert!(matches!(f.next(), Event::Items(_, _)));
        f.expect_done("Password changed");
        f.send(Command::CreateCollection {
            label: "Other".into(),
            password: SecretValue::from_text("p"),
        });
        assert!(matches!(f.next(), Event::Collections(_)));
        f.expect_done("Collection created");
    }

    /// The object path name maps to the keyring file name; `session` has none.
    #[test]
    fn keyring_name_from_collection_path() {
        let id = |p: &str| CollectionId(p.into());
        let ok = keyring_name(&id("/org/freedesktop/secrets/collection/login"));
        assert_eq!(ok, Ok(Some("login".to_string())));
        let session = keyring_name(&id("/org/freedesktop/secrets/collection/session"));
        assert_eq!(session, Ok(None));
        assert!(keyring_name(&id("/org/freedesktop/secrets/aliases/default")).is_err());
        assert!(keyring_name(&id("/org/freedesktop/secrets/collection/")).is_err());
        assert!(keyring_name(&id("/org/freedesktop/secrets/collection/a/b")).is_err());
    }

    /// Escaped object path names decode to the raw keyring file name.
    #[test]
    fn keyring_name_decodes_escapes() {
        let name = |n: &str| keyring_name(&CollectionId(format!("{COLLECTION_PATH_PREFIX}{n}")));
        assert_eq!(name("My_5fKeys"), Ok(Some("My_Keys".to_string())));
        assert_eq!(
            name("Default_5fkeyring"),
            Ok(Some("Default_keyring".to_string()))
        );
        assert_eq!(name("plain"), Ok(Some("plain".to_string())));
        assert!(name("_zz").is_err());
        assert!(name("a_2fb").is_err());
        assert!(name("_2e").is_err());
        assert!(name("_2e_2e").is_err());
    }

    /// The collection is the parent object path of the item.
    #[test]
    fn collection_of_returns_parent_path() {
        let item = ItemId("/org/freedesktop/secrets/collection/login/12".into());
        assert_eq!(
            collection_of(&item).0,
            "/org/freedesktop/secrets/collection/login"
        );
    }
}
