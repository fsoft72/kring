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

/// A request from the UI to the worker.
#[derive(Clone, Debug)]
pub enum Command {
    Refresh,
    LoadItems(CollectionId),
    RevealSecret(ItemId),
    CreateItem {
        collection: CollectionId,
        item: NewItem,
    },
    UpdateItem {
        item: ItemId,
        update: ItemUpdate,
    },
    DeleteItem {
        item: ItemId,
        backup_passphrase: Option<SecretValue>,
    },
    SetDefault(CollectionId),
    Lock(CollectionId),
    Unlock {
        collection: CollectionId,
        password: SecretValue,
    },
    CreateCollection {
        label: String,
        password: SecretValue,
    },
    RenameCollection {
        collection: CollectionId,
        label: String,
    },
    ChangePassword {
        collection: CollectionId,
        old: SecretValue,
        new: SecretValue,
    },
    DeleteCollection {
        collection: CollectionId,
        backup_passphrase: Option<SecretValue>,
    },
}

/// A notification from the worker to the UI.
#[derive(Clone, Debug)]
pub enum Event {
    Provider(ProviderInfo),
    ProviderUnavailable,
    Pam(PamStatus),
    Collections(Vec<CollectionInfo>),
    Items(CollectionId, Vec<ItemInfo>),
    Secret(ItemId, SecretValue),
    BackupCreated(BackupInfo),
    /// A backup needs a passphrase; carries the command to resend with it.
    PassphraseNeeded(Box<Command>),
    Done(String),
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
        runtime.block_on(startup(&out, store.as_deref(), provider.as_ref(), &config));
        while let Ok(cmd) = cmd_rx.recv() {
            runtime.block_on(handle(
                &out,
                store.as_deref(),
                provider.as_ref(),
                &config,
                cmd,
            ));
        }
    });
    WorkerHandle {
        tx: cmd_tx,
        rx: ev_rx,
    }
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
fn _collection_of(item: &ItemId) -> CollectionId {
    let parent = item.0.rsplit_once('/').map_or("", |(parent, _)| parent);
    CollectionId(parent.to_string())
}

/// Creates a backup of all keyrings before a destructive operation.
///
/// Returns `Ok(true)` to proceed, `Ok(false)` when the command was answered
/// (passphrase requested or error reported) and must not run.
fn backup_before<N: Fn()>(
    out: &Emitter<N>,
    config: &WorkerConfig,
    reason: &str,
    passphrase: Option<&SecretValue>,
    original: &Command,
) -> bool {
    let files = match keyring_backup_set(&config.keyrings_dir) {
        Ok(files) => files,
        Err(e) => {
            out.error(format!("Backup failed, nothing was deleted: {e}"));
            return false;
        }
    };
    if files.is_empty() {
        return true;
    }
    match config.backups.create(reason, &files, passphrase) {
        Ok(info) => {
            out.emit(Event::BackupCreated(info));
            true
        }
        Err(KringError::PassphraseRequired) => {
            out.emit(Event::PassphraseNeeded(Box::new(original.clone())));
            false
        }
        Err(e) => {
            out.error(format!("Backup failed, nothing was deleted: {e}"));
            false
        }
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
/// Returns `Ok` also when the command was answered without running (backup
/// passphrase requested or backup failed).
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
    match cmd {
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
        }
        Command::UpdateItem { item, update } => {
            store.update_item(item, update.clone()).await?;
            affected = Some(_collection_of(item));
        }
        Command::DeleteItem {
            item,
            backup_passphrase,
        } => {
            if !backup_before(out, config, "delete-item", backup_passphrase.as_ref(), cmd) {
                return Ok(());
            }
            store.delete_item(item).await?;
            affected = Some(_collection_of(item));
        }
        Command::SetDefault(id) => store.set_alias("default", id).await?,
        Command::Lock(id) => {
            store.lock(id).await?;
            affected = Some(id.clone());
        }
        Command::Unlock {
            collection,
            password,
        } => {
            store.unlock_with_password(collection, password).await?;
            affected = Some(collection.clone());
        }
        Command::CreateCollection { label, password } => {
            store.create_with_password(label, password).await?;
        }
        Command::RenameCollection { collection, label } => {
            store.rename_collection(collection, label).await?;
            affected = Some(collection.clone());
        }
        Command::ChangePassword {
            collection,
            old,
            new,
        } => {
            store.change_password(collection, old, new).await?;
            affected = Some(collection.clone());
        }
        Command::DeleteCollection {
            collection,
            backup_passphrase,
        } => {
            let pass = backup_passphrase.as_ref();
            if !backup_before(out, config, "delete-collection", pass, cmd) {
                return Ok(());
            }
            store.delete_collection(collection).await?;
        }
    }
    refresh(out, store).await;
    if let Some(id) = affected {
        load_items(out, store, &id).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kring_core::backup::KEYRING_MAGIC;
    use kring_core::fake_store::FakeStore;
    use kring_core::provider::ProviderKind;

    use super::*;

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

    /// Starts a worker over a FakeStore with one unlocked collection.
    fn fixture(provider: Option<ProviderInfo>) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let keyrings = dir.path().join("keyrings");
        let backups = dir.path().join("backups");
        let pam = dir.path().join("pam");
        for d in [&keyrings, &pam] {
            std::fs::create_dir_all(d).unwrap();
        }
        let store = FakeStore::new();
        let collection = store.add_collection("Main", "pw", false);
        let config = WorkerConfig {
            backups: BackupManager {
                root: backups.clone(),
                keep: BACKUP_KEEP,
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
            match self.next() {
                Event::Items(_, items) => items[0].id.clone(),
                other => panic!("expected Items, got {other:?}"),
            }
        }
    }

    /// Writes a binary-looking keyring file.
    fn write_binary_keyring(dir: &std::path::Path) {
        let mut bytes = KEYRING_MAGIC.to_vec();
        bytes.extend_from_slice(b"payload");
        std::fs::write(dir.join("login.keyring"), bytes).unwrap();
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
        write_binary_keyring(&f.keyrings);
        f.skip_startup();
        let item = f.create_item();
        f.send(Command::DeleteItem {
            item,
            backup_passphrase: None,
        });
        assert!(matches!(f.next(), Event::BackupCreated(_)));
        assert!(matches!(f.next(), Event::Collections(_)));
        match f.next() {
            Event::Items(_, items) => assert!(items.is_empty()),
            other => panic!("expected Items, got {other:?}"),
        }
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
}
