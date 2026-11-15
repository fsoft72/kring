//! Unit tests of the offline worker commands (FakeStore + tempdir fixture copies).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kring_core::backup::{BACKUP_KEEP, BackupManager, RESTART_HINT};
use kring_core::fake_store::FakeStore;
use kring_core::model::{
    CollectionId, CollectionInfo, ItemId, ItemInfo, ItemUpdate, NewItem, SecretValue,
};
use kring_core::provider::{ProviderInfo, ProviderKind};
use kring_core::{KringError, MasterPasswordStore, SecretStore};

use crate::worker::{Command, Event, WorkerConfig, WorkerHandle, spawn};

/// Directory of the synthetic keyring fixtures.
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kring-core/tests/fixtures/keyrings"
);
/// Textual fixture with two items.
const TEXTUAL: &str = "textual_two_items";
/// Binary fixture with two items.
const BINARY: &str = "binary_two_items";
/// Password of the binary fixture.
const BINARY_PASSWORD: &str = "fixture-pw";
/// Label (and object path name) of the main collection.
const MAIN: &str = "Main";
/// Label of the second, empty collection.
const OTHER: &str = "Other";
/// Passphrase used for backups and archives.
const PASSPHRASE: &str = "backup-pass";

/// Store wrapper whose `list_collections` fails while `fail` is set.
struct FailingStore {
    inner: FakeStore,
    fail: AtomicBool,
}

#[async_trait::async_trait]
impl SecretStore for FailingStore {
    async fn list_collections(&self) -> kring_core::Result<Vec<CollectionInfo>> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(KringError::InvalidInput("list failed".into()));
        }
        self.inner.list_collections().await
    }
    async fn list_items(&self, c: &CollectionId) -> kring_core::Result<Vec<ItemInfo>> {
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
impl MasterPasswordStore for FailingStore {
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

/// Test environment owning the temp dirs and the worker handle.
struct Env {
    dir: tempfile::TempDir,
    keyrings: PathBuf,
    backups: PathBuf,
    handle: WorkerHandle,
    main: CollectionId,
    other: CollectionId,
}

/// Builds a gnome-keyring provider (writes allowed).
fn gnome() -> Option<ProviderInfo> {
    provider(ProviderKind::GnomeKeyring)
}

/// Builds a provider of the given kind with the master password interface.
fn provider(kind: ProviderKind) -> Option<ProviderInfo> {
    Some(ProviderInfo {
        kind,
        pid: None,
        process_name: None,
        competitors: vec![],
        has_master_password_iface: true,
    })
}

/// Creates the temp dirs and copies `files` (`(fixture name, keyrings dir name)`) into keyrings.
fn dirs(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf, WorkerConfig) {
    let dir = tempfile::tempdir().unwrap();
    let keyrings = dir.path().join("keyrings");
    let pam = dir.path().join("pam");
    for d in [&keyrings, &pam] {
        std::fs::create_dir_all(d).unwrap();
    }
    for (fixture, name) in files {
        let src = Path::new(FIXTURES).join(format!("{fixture}.keyring"));
        std::fs::copy(src, keyrings.join(format!("{name}.keyring"))).unwrap();
    }
    let config = WorkerConfig {
        backups: BackupManager {
            root: dir.path().join("backups"),
            keep: BACKUP_KEEP,
        },
        keyrings_dir: keyrings.clone(),
        pam_dir: pam,
    };
    (dir, keyrings, config)
}

/// Starts a worker over a FakeStore with unlocked `Main` and `Other`, skipping startup events.
fn env(provider: Option<ProviderInfo>, files: &[(&str, &str)]) -> Env {
    let (dir, keyrings, config) = dirs(files);
    let backups = config.backups.root.clone();
    let store = FakeStore::new();
    let main = store.add_collection(MAIN, "pw", false);
    let other = store.add_collection(OTHER, "pw", false);
    let handle = spawn(Some(Arc::new(store)), provider, config, || {});
    let env = Env {
        dir,
        keyrings,
        backups,
        handle,
        main,
        other,
    };
    for _ in 0..3 {
        env.next();
    }
    env
}

impl Env {
    /// Receives the next event, failing after 10 seconds.
    fn next(&self) -> Event {
        recv(&self.handle)
    }

    /// Sends a command.
    fn send(&self, cmd: Command) {
        self.handle.tx.send(cmd).unwrap();
    }

    /// Asserts the next event is an error and returns its message.
    fn expect_error(&self) -> String {
        match self.next() {
            Event::Error(m) => m,
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Returns the path of `<name>.keyring` in the keyrings dir.
    fn keyring(&self, name: &str) -> PathBuf {
        self.keyrings.join(format!("{name}.keyring"))
    }

    /// Imports the textual fixture into `Main`, consuming the events.
    fn import_textual(&self) {
        self.send(Command::ImportFile {
            name: TEXTUAL.into(),
            password: None,
            target: self.main.clone(),
        });
        assert!(matches!(self.next(), Event::ImportDone(_)));
        assert!(matches!(self.next(), Event::Items(_, _)));
        assert!(matches!(self.next(), Event::Collections(_)));
    }
}

/// Receives the next event of a handle, failing after 10 seconds.
fn recv(handle: &WorkerHandle) -> Event {
    handle
        .rx
        .recv_timeout(Duration::from_secs(10))
        .expect("event expected")
}

/// Returns the text secret of the offline item labelled `label`.
fn secret_of(items: &[kring_core::keyring_file::textual::OfflineItem], label: &str) -> String {
    let item = items.iter().find(|i| i.label == label).unwrap();
    item.secret.as_text().unwrap().to_string()
}

/// Scanning lists the keyring files of the keyrings dir, sorted by name.
#[test]
fn scan_emits_files() {
    let e = env(gnome(), &[(TEXTUAL, TEXTUAL), (BINARY, BINARY)]);
    e.send(Command::ScanFiles);
    match e.next() {
        Event::Files(files) => {
            let names: Vec<_> = files.iter().map(|f| f.name.as_str()).collect();
            assert_eq!(names, [BINARY, TEXTUAL]);
        }
        other => panic!("expected Files, got {other:?}"),
    }
}

/// A textual file opens without a password and yields its items and secrets.
#[test]
fn open_textual_without_password() {
    let e = env(gnome(), &[(TEXTUAL, TEXTUAL)]);
    e.send(Command::OpenFile {
        name: TEXTUAL.into(),
        password: None,
    });
    match e.next() {
        Event::FileItems {
            name,
            items,
            warnings,
        } => {
            assert_eq!(name, TEXTUAL);
            assert_eq!(items.len(), 2);
            assert!(warnings.is_empty());
            assert_eq!(secret_of(&items, "First item"), "fixture-secret-1");
        }
        other => panic!("expected FileItems, got {other:?}"),
    }
}

/// A binary file asks for its password, then opens with it; a wrong one is an error.
#[test]
fn open_binary_needs_password() {
    let e = env(None, &[(BINARY, BINARY)]);
    e.send(Command::OpenFile {
        name: BINARY.into(),
        password: None,
    });
    match e.next() {
        Event::PasswordNeeded(name) => assert_eq!(name, BINARY),
        other => panic!("expected PasswordNeeded, got {other:?}"),
    }
    e.send(Command::OpenFile {
        name: BINARY.into(),
        password: Some(SecretValue::from_text("wrong")),
    });
    assert!(e.expect_error().contains("Wrong password"));
    e.send(Command::OpenFile {
        name: BINARY.into(),
        password: Some(SecretValue::from_text(BINARY_PASSWORD)),
    });
    match e.next() {
        Event::FileItems { name, items, .. } => {
            assert_eq!(name, BINARY);
            assert_eq!(secret_of(&items, "Fixture One"), "fixture-secret-1");
        }
        other => panic!("expected FileItems, got {other:?}"),
    }
}

/// Importing a file reports created items, then re-imports count duplicates.
#[test]
fn import_file_reports_counts() {
    let e = env(provider(ProviderKind::KWallet), &[(TEXTUAL, TEXTUAL)]);
    let import = || Command::ImportFile {
        name: TEXTUAL.into(),
        password: None,
        target: e.main.clone(),
    };
    e.send(import());
    match e.next() {
        Event::ImportDone(r) => assert_eq!((r.created, r.duplicates), (2, 0)),
        other => panic!("expected ImportDone, got {other:?}"),
    }
    match e.next() {
        Event::Items(id, items) => {
            assert_eq!(id, e.main);
            assert_eq!(items.len(), 2);
        }
        other => panic!("expected Items, got {other:?}"),
    }
    assert!(matches!(e.next(), Event::Collections(_)));
    e.send(import());
    match e.next() {
        Event::ImportDone(r) => assert_eq!((r.created, r.duplicates), (0, 2)),
        other => panic!("expected ImportDone, got {other:?}"),
    }
}

/// Retiring the file of a live collection deletes the collection after a backup.
#[test]
fn retire_live_file_uses_delete_collection_with_backup() {
    let e = env(gnome(), &[(TEXTUAL, MAIN)]);
    e.send(Command::RetireFile {
        name: MAIN.into(),
        backup_passphrase: SecretValue::from_text(PASSPHRASE),
    });
    let info = match e.next() {
        Event::BackupCreated(info) => info,
        other => panic!("expected BackupCreated, got {other:?}"),
    };
    assert!(info.files.iter().any(|f| f.original == e.keyring(MAIN)));
    match e.next() {
        Event::Collections(list) => assert!(list.iter().all(|c| c.id != e.main)),
        other => panic!("expected Collections, got {other:?}"),
    }
    match e.next() {
        Event::Done(m) => assert!(m.starts_with("Collection deleted, backup in"), "{m}"),
        other => panic!("expected Done, got {other:?}"),
    }
    assert!(matches!(e.next(), Event::Files(_)));
    // The file of a live collection is never unlinked by kring.
    assert!(e.keyring(MAIN).exists());
}

/// A live collection on a provider without writes is refused and the file kept.
#[test]
fn retire_live_file_refused_without_writes() {
    let e = env(provider(ProviderKind::KWallet), &[(TEXTUAL, MAIN)]);
    e.send(Command::RetireFile {
        name: MAIN.into(),
        backup_passphrase: SecretValue::from_text(PASSPHRASE),
    });
    assert_eq!(e.expect_error(), "Not supported on this provider");
    assert!(e.keyring(MAIN).exists());
    assert!(!e.backups.exists());
}

/// A plaintext file that is not live is backed up encrypted, then removed.
#[test]
fn retire_plaintext_file_backs_up_then_removes() {
    let e = env(gnome(), &[(TEXTUAL, TEXTUAL)]);
    e.send(Command::RetireFile {
        name: TEXTUAL.into(),
        backup_passphrase: SecretValue::from_text(PASSPHRASE),
    });
    match e.next() {
        Event::BackupCreated(info) => {
            assert_eq!(info.files.len(), 1);
            assert!(info.files[0].encrypted);
        }
        other => panic!("expected BackupCreated, got {other:?}"),
    }
    match e.next() {
        Event::Done(m) => assert_eq!(m, "Plaintext file retired"),
        other => panic!("expected Done, got {other:?}"),
    }
    match e.next() {
        Event::Files(files) => assert!(files.is_empty()),
        other => panic!("expected Files, got {other:?}"),
    }
    assert!(!e.keyring(TEXTUAL).exists());
}

/// Without a running daemon no file is live, so a plaintext file is retired directly.
#[test]
fn retire_without_provider_removes_file() {
    let (_dir, keyrings, config) = dirs(&[(TEXTUAL, MAIN)]);
    let h = spawn::<FakeStore>(None, None, config, || {});
    for _ in 0..2 {
        recv(&h);
    }
    h.tx.send(Command::RetireFile {
        name: MAIN.into(),
        backup_passphrase: SecretValue::from_text(PASSPHRASE),
    })
    .unwrap();
    assert!(matches!(recv(&h), Event::BackupCreated(_)));
    assert!(matches!(recv(&h), Event::Done(_)));
    assert!(matches!(recv(&h), Event::Files(_)));
    assert!(!keyrings.join("Main.keyring").exists());
}

/// If live collections cannot be listed the retire is aborted, never treated as "not live".
#[test]
fn retire_refuses_when_list_collections_fails() {
    let (dir, keyrings, config) = dirs(&[(TEXTUAL, MAIN)]);
    let inner = FakeStore::new();
    inner.add_collection(MAIN, "pw", false);
    let store = Arc::new(FailingStore {
        inner,
        fail: AtomicBool::new(false),
    });
    let h = spawn(Some(store.clone()), gnome(), config, || {});
    for _ in 0..3 {
        recv(&h);
    }
    store.fail.store(true, Ordering::SeqCst);
    h.tx.send(Command::RetireFile {
        name: MAIN.into(),
        backup_passphrase: SecretValue::from_text(PASSPHRASE),
    })
    .unwrap();
    match recv(&h) {
        Event::Error(m) => assert!(m.contains("list failed"), "{m}"),
        other => panic!("expected Error, got {other:?}"),
    }
    assert!(keyrings.join("Main.keyring").exists());
    assert!(!dir.path().join("backups").exists());
}

/// Restoring a listed backup writes the file back and reports it with the restart hint.
#[test]
fn restore_emits_report() {
    let e = env(gnome(), &[(BINARY, BINARY)]);
    let path = e.keyring(BINARY);
    let original = std::fs::read(&path).unwrap();
    let manager = BackupManager {
        root: e.backups.clone(),
        keep: BACKUP_KEEP,
    };
    let info = manager
        .create("test", std::slice::from_ref(&path), None)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    e.send(Command::ListBackups);
    match e.next() {
        Event::Backups(list) => assert_eq!(list.len(), 1),
        other => panic!("expected Backups, got {other:?}"),
    }
    e.send(Command::RestoreBackup {
        dir: info.dir.clone(),
        files: vec![path.clone()],
        passphrase: None,
    });
    match e.next() {
        Event::RestoreDone(report) => {
            assert_eq!(report.restored, std::slice::from_ref(&path));
            assert!(report.pre_restore_backup.is_none());
        }
        other => panic!("expected RestoreDone, got {other:?}"),
    }
    match e.next() {
        Event::Done(m) => assert!(m.contains(RESTART_HINT), "{m}"),
        other => panic!("expected Done, got {other:?}"),
    }
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

/// A restore of an unlisted backup dir or of a file outside its manifest is refused.
#[test]
fn restore_rejects_unknown_dir_and_files() {
    let e = env(gnome(), &[(BINARY, BINARY)]);
    let path = e.keyring(BINARY);
    let manager = BackupManager {
        root: e.backups.clone(),
        keep: BACKUP_KEEP,
    };
    let info = manager
        .create("test", std::slice::from_ref(&path), None)
        .unwrap();
    e.send(Command::RestoreBackup {
        dir: e.dir.path().join("elsewhere"),
        files: vec![path.clone()],
        passphrase: None,
    });
    assert!(e.expect_error().ends_with("Unknown backup"));
    e.send(Command::RestoreBackup {
        dir: info.dir.clone(),
        files: vec![e.keyring("other")],
        passphrase: None,
    });
    assert!(e.expect_error().contains("File not in backup"));
    e.send(Command::RestoreBackup {
        dir: info.dir,
        files: vec![],
        passphrase: None,
    });
    assert!(e.expect_error().ends_with("No files selected for restore"));
}

/// An exported collection imports into another one; a wrong passphrase imports nothing.
#[test]
fn export_then_import_archive_roundtrip() {
    let e = env(gnome(), &[(TEXTUAL, TEXTUAL)]);
    e.import_textual();
    let archive = e.dir.path().join("export.age");
    e.send(Command::ExportCollection {
        collection: e.main.clone(),
        path: archive.clone(),
        passphrase: SecretValue::from_text(PASSPHRASE),
    });
    match e.next() {
        Event::Done(m) => assert_eq!(m, format!("Exported 2 items to {}", archive.display())),
        other => panic!("expected Done, got {other:?}"),
    }
    e.send(Command::ImportArchive {
        path: archive.clone(),
        passphrase: SecretValue::from_text("wrong"),
        target: e.other.clone(),
    });
    e.expect_error();
    e.send(Command::ImportArchive {
        path: archive,
        passphrase: SecretValue::from_text(PASSPHRASE),
        target: e.other.clone(),
    });
    match e.next() {
        Event::ImportDone(r) => assert_eq!(r.created, 2),
        other => panic!("expected ImportDone, got {other:?}"),
    }
    match e.next() {
        Event::Items(id, items) => {
            assert_eq!(id, e.other);
            assert_eq!(items.len(), 2);
        }
        other => panic!("expected Items, got {other:?}"),
    }
    assert!(matches!(e.next(), Event::Collections(_)));
}

/// A locked collection cannot be exported.
#[test]
fn export_locked_collection_fails() {
    let e = env(gnome(), &[]);
    e.send(Command::Lock(e.main.clone()));
    assert!(matches!(e.next(), Event::Collections(_)));
    assert!(matches!(e.next(), Event::Items(_, _)));
    assert!(matches!(e.next(), Event::Done(_)));
    let archive = e.dir.path().join("export.age");
    e.send(Command::ExportCollection {
        collection: e.main.clone(),
        path: archive.clone(),
        passphrase: SecretValue::from_text(PASSPHRASE),
    });
    e.expect_error();
    assert!(!archive.exists());
}

/// File names with separators or dot segments, unknown names and symlinks are rejected.
#[test]
fn rejects_path_traversal_names() {
    let e = env(gnome(), &[(TEXTUAL, TEXTUAL)]);
    std::os::unix::fs::symlink(e.keyring(TEXTUAL), e.keyring("link")).unwrap();
    for name in [
        "../textual_two_items",
        "a/b",
        ".",
        "..",
        "",
        "missing",
        "link",
    ] {
        e.send(Command::OpenFile {
            name: name.into(),
            password: None,
        });
        let m = e.expect_error();
        assert!(
            m.ends_with("Invalid keyring file name") || m.contains("No keyring file named"),
            "{name}: {m}"
        );
    }
    e.send(Command::RetireFile {
        name: "../textual_two_items".into(),
        backup_passphrase: SecretValue::from_text(PASSPHRASE),
    });
    assert!(e.expect_error().ends_with("Invalid keyring file name"));
    assert!(e.keyring(TEXTUAL).exists());
}
