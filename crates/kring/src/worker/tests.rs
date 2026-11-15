//! Unit tests of the background worker.

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
        kwallet_dir: keyrings.join("kwalletd-unused"),
        ssh_dir: None,
        ssh_agent_sock: None,
        gnupg_home: Some(std::path::PathBuf::from(crate::worker::NO_GNUPG_HOME)),
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
        next_event(&self.handle, Duration::from_secs(5))
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
        kwallet_dir: dir.path().join("w"),
        ssh_dir: None,
        ssh_agent_sock: None,
        gnupg_home: Some(std::path::PathBuf::from(crate::worker::NO_GNUPG_HOME)),
    };
    let h = spawn::<FakeStore>(None, None, config, || {});
    let next = || next_event(&h, Duration::from_secs(5));
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
        kwallet_dir: dir.path().join("w"),
        ssh_dir: None,
        ssh_agent_sock: None,
        gnupg_home: Some(std::path::PathBuf::from(crate::worker::NO_GNUPG_HOME)),
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
    let next = || next_event(&h, Duration::from_secs(5));
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
    let next = || next_event(&h, Duration::from_secs(5));
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

/// Every command, also a failing or panicking one, ends with exactly one
/// `CommandFinished`, numbered from 0 in the order received; startup has none.
#[test]
fn command_finished_once_per_command_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let (h, id) = panic_worker(&dir, false);
    let raw = || h.rx.recv_timeout(Duration::from_secs(5)).unwrap();
    for _ in 0..3 {
        assert!(
            !matches!(raw(), Event::CommandFinished(_)),
            "no startup finish"
        );
    }
    h.tx.send(Command::Refresh).unwrap();
    h.tx.send(Command::LoadItems(id)).unwrap(); // panics in the store
    h.tx.send(Command::Lock(CollectionId("/nope".into())))
        .unwrap();
    h.tx.send(Command::Refresh).unwrap();
    let mut finished = Vec::new();
    while finished.len() < 4 {
        if let Event::CommandFinished(n) = raw() {
            finished.push(n);
        }
    }
    assert_eq!(finished, [0, 1, 2, 3]);
    assert!(
        h.rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "nothing after the last command"
    );
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

/// A failed prune travels in the backup event (a notice, never an Error
/// event), and the backup exists so the delete proceeds.
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
    let events: Vec<Event> = (0..4).map(|_| f.next()).collect();
    set_mode(0o700).unwrap();
    match &events[0] {
        Event::BackupCreated(info) => assert!(info.prune_warning.is_some(), "{info:?}"),
        other => panic!("expected BackupCreated, got {other:?}"),
    }
    assert!(matches!(events[1], Event::Collections(_)), "{events:?}");
    match &events[2] {
        Event::Items(_, items) => assert!(items.is_empty()),
        other => panic!("expected Items, got {other:?}"),
    }
    assert!(matches!(events[3], Event::Done(_)), "{events:?}");
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
    let ok = keyring_name(
        &id("/org/freedesktop/secrets/collection/login"),
        MSG_NO_BACKUP,
    );
    assert_eq!(ok, Ok(Some("login".to_string())));
    let session = keyring_name(
        &id("/org/freedesktop/secrets/collection/session"),
        MSG_NO_BACKUP,
    );
    assert_eq!(session, Ok(None));
    assert!(
        keyring_name(
            &id("/org/freedesktop/secrets/aliases/default"),
            MSG_NO_BACKUP
        )
        .is_err()
    );
    assert!(keyring_name(&id("/org/freedesktop/secrets/collection/"), MSG_NO_BACKUP).is_err());
    assert!(
        keyring_name(
            &id("/org/freedesktop/secrets/collection/a/b"),
            MSG_NO_BACKUP
        )
        .is_err()
    );
}

/// Escaped object path names decode to the raw keyring file name.
#[test]
fn keyring_name_decodes_escapes() {
    let name = |n: &str| {
        keyring_name(
            &CollectionId(format!("{COLLECTION_PATH_PREFIX}{n}")),
            MSG_NO_BACKUP,
        )
    };
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

/// Password of the locked keyrings of the unlock-many tests.
const MANY_PW: &str = "many-pw";

/// Starts a worker over `store` with `provider` and consumes the startup
/// events; returns the temp dir (kept alive) and the handle.
fn worker_over(
    store: Arc<FakeStore>,
    provider: Option<ProviderInfo>,
) -> (tempfile::TempDir, WorkerHandle) {
    let dir = tempfile::tempdir().unwrap();
    let config = WorkerConfig {
        backups: BackupManager {
            root: dir.path().join("b"),
            keep: BACKUP_KEEP,
        },
        keyrings_dir: dir.path().join("k"),
        pam_dir: dir.path().join("p"),
        kwallet_dir: dir.path().join("w"),
        ssh_dir: None,
        ssh_agent_sock: None,
        gnupg_home: Some(std::path::PathBuf::from(crate::worker::NO_GNUPG_HOME)),
    };
    let handle = spawn(Some(store), provider, config, || {});
    // Startup with a store: Provider, Pam, Collections.
    for _ in 0..3 {
        next_event(&handle, Duration::from_secs(5));
    }
    (dir, handle)
}

/// Three locked keyrings labelled alike: two with [`MANY_PW`], one with another password.
fn many_locked_store() -> (Arc<FakeStore>, Vec<CollectionId>) {
    let store = Arc::new(FakeStore::new());
    store.add_collection("login", "pw", false);
    let ids = vec![
        store.add_collection("Dk", MANY_PW, true),
        store.add_collection("Dk", "other-pw", true),
        store.add_collection("Dk", MANY_PW, true),
    ];
    (store, ids)
}

/// One password is tried on every keyring: a wrong one does not stop the
/// others; UnlockManyDone (named, secret free) comes before Collections and
/// the command ends with one CommandFinished.
#[test]
fn unlock_many_tries_every_keyring() {
    let (store, ids) = many_locked_store();
    let p = provider(ProviderKind::GnomeKeyring, true);
    let (_dir, h) = worker_over(store, Some(p));
    h.tx.send(Command::UnlockMany {
        collections: ids.clone(),
        password: SecretValue::from_text(MANY_PW),
    })
    .unwrap();
    let raw = || h.rx.recv_timeout(Duration::from_secs(5)).unwrap();
    match raw() {
        Event::UnlockManyDone { unlocked, failed } => {
            assert_eq!(unlocked, 2);
            assert_eq!(failed.len(), 1);
            assert_eq!(failed[0].0, ids[1]);
            assert!(failed[0].1.contains("invalid password"), "{failed:?}");
            let text = format!("{failed:?}");
            assert!(!text.contains(MANY_PW) && !text.contains("other-pw"));
        }
        other => panic!("expected UnlockManyDone, got {other:?}"),
    }
    match raw() {
        Event::Collections(list) => {
            let locked = |id: &CollectionId| list.iter().find(|c| &c.id == id).unwrap().locked;
            assert!(!locked(&ids[0]) && locked(&ids[1]) && !locked(&ids[2]));
        }
        other => panic!("expected Collections, got {other:?}"),
    }
    assert!(matches!(raw(), Event::CommandFinished(0)));
    assert!(h.rx.recv_timeout(Duration::from_millis(200)).is_err());
}

/// Without the master password interface the command is refused like Unlock.
#[test]
fn unlock_many_gated_like_unlock() {
    let (store, ids) = many_locked_store();
    let p = provider(ProviderKind::GnomeKeyring, false);
    let (_dir, h) = worker_over(store.clone(), Some(p));
    h.tx.send(Command::UnlockMany {
        collections: ids.clone(),
        password: SecretValue::from_text(MANY_PW),
    })
    .unwrap();
    match next_event(&h, Duration::from_secs(5)) {
        Event::Error(m) => assert_eq!(m, MSG_UNSUPPORTED),
        other => panic!("expected Error, got {other:?}"),
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let list = rt.block_on(store.list_collections()).unwrap();
    assert!(
        list.iter()
            .filter(|c| ids.contains(&c.id))
            .all(|c| c.locked)
    );
}

/// Unlocking many keyrings changes keyring data: it drops the pending plan.
#[test]
fn unlock_many_invalidates_plans() {
    let cmd = Command::UnlockMany {
        collections: vec![],
        password: SecretValue::from_text(MANY_PW),
    };
    assert!(crate::worker_transfer::invalidates_plan(&cmd));
}
