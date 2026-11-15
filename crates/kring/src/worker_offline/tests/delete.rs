//! Unit tests of [`Command::DeleteFile`].

use super::*;

/// Garbage (unknown format) fixture.
const GARBAGE: &str = "garbage";

/// Builds a delete command.
fn delete(name: &str, backup: bool, passphrase: Option<&str>) -> Command {
    Command::DeleteFile {
        name: name.into(),
        backup,
        backup_passphrase: passphrase.map(SecretValue::from_text),
    }
}

/// A binary file is backed up (no passphrase needed), removed and the list rescanned.
#[test]
fn delete_with_backup_removes_file() {
    let e = env(gnome(), &[(BINARY, BINARY)]);
    e.send(delete(BINARY, true, None));
    let dir = match e.next() {
        Event::BackupCreated(info) => {
            assert_eq!(info.files.len(), 1);
            assert_eq!(info.files[0].original, e.keyring(BINARY));
            assert!(!info.files[0].encrypted);
            info.dir
        }
        other => panic!("expected BackupCreated, got {other:?}"),
    };
    match e.next() {
        Event::Done(m) => assert_eq!(
            m,
            format!("File {BINARY} deleted, backup in {}", dir.display())
        ),
        other => panic!("expected Done, got {other:?}"),
    }
    match e.next() {
        Event::Files(files) => assert!(files.is_empty()),
        other => panic!("expected Files, got {other:?}"),
    }
    assert!(!e.keyring(BINARY).exists());
}

/// Without a backup the file is removed and no backup directory is created.
#[test]
fn delete_without_backup_removes_file() {
    let e = env(gnome(), &[(GARBAGE, GARBAGE)]);
    e.send(delete(GARBAGE, false, None));
    match e.next() {
        Event::Done(m) => assert_eq!(m, format!("File {GARBAGE} deleted")),
        other => panic!("expected Done, got {other:?}"),
    }
    assert!(matches!(e.next(), Event::Files(_)));
    assert!(!e.keyring(GARBAGE).exists());
    assert!(!e.backups.exists());
}

/// A plaintext file without a passphrase asks for one; the echo carries none.
#[test]
fn delete_plaintext_asks_for_passphrase() {
    let e = env(gnome(), &[(TEXTUAL, TEXTUAL)]);
    e.send(delete(TEXTUAL, true, None));
    match e.next() {
        Event::PassphraseNeeded(resend) => match *resend {
            Command::DeleteFile {
                name,
                backup,
                backup_passphrase,
            } => {
                assert_eq!(name, TEXTUAL);
                assert!(backup);
                assert!(backup_passphrase.is_none());
            }
            other => panic!("expected DeleteFile, got {other:?}"),
        },
        other => panic!("expected PassphraseNeeded, got {other:?}"),
    }
    assert!(e.keyring(TEXTUAL).exists());
    e.send(delete(TEXTUAL, true, Some(PASSPHRASE)));
    match e.next() {
        Event::BackupCreated(info) => assert!(info.files[0].encrypted),
        other => panic!("expected BackupCreated, got {other:?}"),
    }
    assert!(matches!(e.next(), Event::Done(_)));
    assert!(matches!(e.next(), Event::Files(_)));
    assert!(!e.keyring(TEXTUAL).exists());
}

/// A live keyring holding items is never deleted without a backup.
#[test]
fn delete_live_with_items_without_backup_refused() {
    let e = env(gnome(), &[(BINARY, MAIN), (TEXTUAL, TEXTUAL)]);
    e.import_textual();
    e.send(delete(MAIN, false, None));
    assert!(
        e.expect_error()
            .ends_with("Loaded keyrings are always backed up before deletion")
    );
    e.send(Command::Refresh);
    match e.next() {
        Event::Collections(list) => assert!(list.iter().any(|c| c.id == e.main)),
        other => panic!("expected Collections, got {other:?}"),
    }
    assert!(!e.backups.exists());
}

/// An empty live keyring may be deleted without a backup, through the daemon.
#[test]
fn delete_empty_live_without_backup() {
    let e = env(gnome(), &[(BINARY, MAIN)]);
    e.send(delete(MAIN, false, None));
    match e.next() {
        Event::Collections(list) => assert!(list.iter().all(|c| c.id != e.main)),
        other => panic!("expected Collections, got {other:?}"),
    }
    match e.next() {
        Event::Done(m) => assert_eq!(m, "Empty keyring deleted"),
        other => panic!("expected Done, got {other:?}"),
    }
    assert!(matches!(e.next(), Event::Files(_)));
    assert!(!e.backups.exists());
}

/// A locked live keyring never counts as empty: no backup is refused, nothing deleted.
#[test]
fn delete_locked_empty_live_without_backup_refused() {
    let (_dir, keyrings, config) = dirs(&[(BINARY, MAIN)]);
    let store = FakeStore::new();
    let main = store.add_collection(MAIN, "pw", true);
    let backups = config.backups.root.clone();
    let h = spawn(Some(Arc::new(store)), gnome(), config, || {});
    for _ in 0..3 {
        recv(&h);
    }
    h.tx.send(delete(MAIN, false, None)).unwrap();
    match recv(&h) {
        Event::Error(m) => assert!(
            m.ends_with("Loaded keyrings are always backed up before deletion"),
            "{m}"
        ),
        other => panic!("expected Error, got {other:?}"),
    }
    h.tx.send(Command::Refresh).unwrap();
    match recv(&h) {
        Event::Collections(list) => {
            let c = list.iter().find(|c| c.id == main).expect("keyring kept");
            assert!(c.locked && c.item_count == 0);
        }
        other => panic!("expected Collections, got {other:?}"),
    }
    assert!(keyrings.join("Main.keyring").exists());
    assert!(!backups.exists());
}

/// A live keyring is deleted through the daemon after a backup of all keyrings.
#[test]
fn delete_live_with_backup_uses_delete_collection() {
    let e = env(gnome(), &[(BINARY, MAIN)]);
    e.send(delete(MAIN, true, None));
    match e.next() {
        Event::BackupCreated(info) => {
            assert!(info.files.iter().any(|f| f.original == e.keyring(MAIN)));
        }
        other => panic!("expected BackupCreated, got {other:?}"),
    }
    match e.next() {
        Event::Collections(list) => assert!(list.iter().all(|c| c.id != e.main)),
        other => panic!("expected Collections, got {other:?}"),
    }
    match e.next() {
        Event::Done(m) => assert!(m.starts_with("Collection deleted, backup in"), "{m}"),
        other => panic!("expected Done, got {other:?}"),
    }
    assert!(matches!(e.next(), Event::Files(_)));
}

/// A plaintext keyring in the backup set asks for a passphrase with the DeleteFile echo.
#[test]
fn delete_live_asks_passphrase_with_delete_file_echo() {
    let e = env(gnome(), &[(BINARY, MAIN), (TEXTUAL, TEXTUAL)]);
    e.send(delete(MAIN, true, None));
    match e.next() {
        Event::PassphraseNeeded(resend) => match *resend {
            Command::DeleteFile {
                name,
                backup,
                backup_passphrase,
            } => {
                assert_eq!(name, MAIN);
                assert!(backup && backup_passphrase.is_none());
            }
            other => panic!("expected DeleteFile, got {other:?}"),
        },
        other => panic!("expected PassphraseNeeded, got {other:?}"),
    }
    assert!(!e.backups.exists());
    e.send(delete(MAIN, true, Some(PASSPHRASE)));
    match e.next() {
        Event::BackupCreated(info) => assert!(info.files.iter().any(|f| f.encrypted)),
        other => panic!("expected BackupCreated, got {other:?}"),
    }
    assert!(matches!(e.next(), Event::Collections(_)));
    assert!(matches!(e.next(), Event::Done(_)));
    assert!(matches!(e.next(), Event::Files(_)));
}

/// On a provider without writes a live keyring is refused, with or without backup.
#[test]
fn delete_live_refused_without_writes() {
    let e = env(provider(ProviderKind::KWallet), &[(BINARY, MAIN)]);
    e.send(delete(MAIN, true, None));
    assert_eq!(e.expect_error(), "Not supported on this provider");
    // The Plan 1 flow reports its error, then the files are rescanned as after a retire.
    assert!(matches!(e.next(), Event::Files(_)));
    e.send(delete(MAIN, false, None));
    assert_eq!(e.expect_error(), "Not supported on this provider");
    assert!(!e.backups.exists());
    e.send(Command::Refresh);
    match e.next() {
        Event::Collections(list) => assert!(list.iter().any(|c| c.id == e.main)),
        other => panic!("expected Collections, got {other:?}"),
    }
}

/// Names that could escape the keyrings dir, unknown names and symlinks are refused.
#[test]
fn delete_rejects_path_traversal_names() {
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
        e.send(delete(name, false, None));
        let m = e.expect_error();
        assert!(
            m.ends_with("Invalid keyring file name") || m.contains("No keyring file named"),
            "{name}: {m}"
        );
    }
    assert!(e.keyring(TEXTUAL).exists());
    assert!(e.keyring("link").exists());
}

/// If live collections cannot be listed the delete is aborted, never treated as "not live".
#[test]
fn delete_refuses_when_list_collections_fails() {
    let (dir, keyrings, config) = dirs(&[(BINARY, MAIN)]);
    let inner = FakeStore::new();
    inner.add_collection(OTHER, "pw", false);
    let store = Arc::new(FailingStore {
        inner,
        fail: AtomicBool::new(false),
    });
    let h = spawn(Some(store.clone()), gnome(), config, || {});
    for _ in 0..3 {
        recv(&h);
    }
    store.fail.store(true, Ordering::SeqCst);
    h.tx.send(delete(MAIN, false, None)).unwrap();
    match recv(&h) {
        Event::Error(m) => assert!(m.contains("list failed"), "{m}"),
        other => panic!("expected Error, got {other:?}"),
    }
    assert!(keyrings.join("Main.keyring").exists());
    assert!(!dir.path().join("backups").exists());
}

/// Without a running daemon no file is live, so the file is deleted directly.
#[test]
fn delete_without_provider_removes_file() {
    let (_dir, keyrings, config) = dirs(&[(BINARY, MAIN)]);
    let h = spawn::<FakeStore>(None, None, config, || {});
    for _ in 0..2 {
        recv(&h);
    }
    h.tx.send(delete(MAIN, false, None)).unwrap();
    assert!(matches!(recv(&h), Event::Done(_)));
    assert!(matches!(recv(&h), Event::Files(_)));
    assert!(!keyrings.join("Main.keyring").exists());
}
