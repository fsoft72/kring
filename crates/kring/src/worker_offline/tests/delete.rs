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

/// The file of a live collection is refused with the Secrets hint, nothing written.
#[test]
fn delete_live_file_refused() {
    let e = env(gnome(), &[(BINARY, MAIN)]);
    e.send(delete(MAIN, false, None));
    assert!(
        e.expect_error()
            .ends_with("Loaded by gnome-keyring: delete this keyring from Secrets")
    );
    assert!(e.keyring(MAIN).exists());
    assert!(!e.backups.exists());
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
