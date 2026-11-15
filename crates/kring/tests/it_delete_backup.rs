//! Integration test: deleting a collection holding items backs up its real
//! keyring file first; an empty one (locked or not) is deleted without a backup.
//!
//! It checks on a real gnome-keyring that the decoded collection object path name
//! (non-alphanumeric bytes are escaped as `_XX`) matches its `<name>.keyring` file,
//! which the worker requires before deleting.
//! Run only through `scripts/it-session.sh` (private bus, throwaway keyring):
//! `bash scripts/it-session.sh cargo test -p kring --test it_delete_backup -- --ignored`

mod common;

use std::time::Duration;

use kring::startup;
use kring::worker::{self, BACKUP_SKIPPED_EMPTY, Command, Event, WorkerConfig, WorkerHandle};
use kring_core::model::{CollectionId, NewItem, SecretValue, decode_path_segment};

/// Serializes the tests: they share one daemon, and a worker listing the
/// collections while another test deletes one reports `NotFound`.
static DAEMON: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Maximum time to wait for one worker event.
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);
/// Label of the collection created and deleted by the test (space and underscore
/// exercise the object path escaping).
const LABEL: &str = "kring delete_test";

/// Waits for the next event matching `pick`, failing on any worker error.
fn wait_for<T>(handle: &WorkerHandle, mut pick: impl FnMut(Event) -> Option<T>) -> T {
    loop {
        let event = handle
            .rx
            .recv_timeout(EVENT_TIMEOUT)
            .expect("worker event expected");
        if let Event::Error(e) = &event {
            panic!("worker error: {e}");
        }
        if let Some(value) = pick(event) {
            return value;
        }
    }
}

/// A worker on the private session.
struct Session {
    /// Endpoints of the worker.
    handle: WorkerHandle,
    /// The keyrings dir of the session.
    keyrings: std::path::PathBuf,
    /// Keeps the bus runtime alive while the worker uses the store.
    _connected: startup::Connected,
}

/// Spawns a worker on the private session with backups in `backups`.
fn spawn_worker(backups: std::path::PathBuf) -> Session {
    let mut connected = startup::connect();
    let store = connected.store.take();
    assert!(store.is_some(), "connect failed: {:?}", connected.error);
    let mut config = WorkerConfig::default_paths();
    config.backups.root = backups;
    config.ssh_dir = None;
    config.ssh_agent_sock = None;
    // A GnuPG home that cannot exist: no gpg command may touch ~/.gnupg.
    config.gnupg_home = Some("/nonexistent/kring-it-gnupg".into());
    let keyrings = config.keyrings_dir.clone();
    let provider = connected.provider.clone();
    let handle = worker::spawn(store, provider, config, || {});
    Session {
        handle,
        keyrings,
        _connected: connected,
    }
}

/// Creates collection `label` and returns its id once its Done arrived.
fn create_collection(handle: &WorkerHandle, label: &str) -> CollectionId {
    handle
        .tx
        .send(Command::CreateCollection {
            label: label.into(),
            password: SecretValue::from_text("pw"),
        })
        .unwrap();
    let id = wait_for(handle, |e| match e {
        Event::Collections(list) => list.into_iter().find(|c| c.label == label).map(|c| c.id),
        _ => None,
    });
    wait_for(handle, |e| matches!(e, Event::Done(_)).then_some(()));
    id
}

/// Sends `cmd` and waits for its Done.
fn run(handle: &WorkerHandle, cmd: Command) {
    handle.tx.send(cmd).unwrap();
    wait_for(handle, |e| matches!(e, Event::Done(_)).then_some(()));
}

/// A collection delete writes a backup containing the collection's keyring file.
#[test]
#[ignore]
fn delete_collection_backs_up_its_keyring_file() {
    if !common::it_guard() {
        return;
    }
    let _daemon = DAEMON.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let session = spawn_worker(dir.path().join("backups"));
    let (handle, keyrings) = (&session.handle, &session.keyrings);
    let id = create_collection(handle, LABEL);
    let segment = id.0.rsplit('/').next().unwrap();
    assert!(segment.contains("_5f"), "escaped path expected: {}", id.0);
    let name = decode_path_segment(segment).unwrap();
    let file = keyrings.join(format!("{name}.keyring"));
    assert!(file.is_file(), "{} missing", file.display());
    run(
        handle,
        Command::CreateItem {
            collection: id.clone(),
            item: NewItem {
                label: "site".into(),
                attributes: Default::default(),
                secret: SecretValue::from_text("s3cret"),
                replace: false,
            },
        },
    );

    handle
        .tx
        .send(Command::DeleteCollection {
            collection: id.clone(),
            backup_passphrase: None,
        })
        .unwrap();
    let info = wait_for(handle, |e| match e {
        Event::BackupCreated(info) => Some(info),
        _ => None,
    });
    assert!(info.files.iter().any(|f| f.original == file), "{info:?}");
    let done = wait_for(handle, |e| match e {
        Event::Done(m) => Some(m),
        _ => None,
    });
    assert!(done.starts_with("Collection deleted, backup in "), "{done}");
}

/// Empty collections, unlocked and locked (gnome-keyring reports the item
/// count of a locked collection), are deleted without any backup.
#[test]
#[ignore]
fn delete_empty_collection_skips_backup() {
    if !common::it_guard() {
        return;
    }
    let _daemon = DAEMON.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let backups = dir.path().join("backups");
    let session = spawn_worker(backups.clone());
    let handle = &session.handle;
    for (label, lock) in [("kring empty open", false), ("kring empty locked", true)] {
        let id = create_collection(handle, label);
        if lock {
            run(handle, Command::Lock(id.clone()));
        }
        handle
            .tx
            .send(Command::DeleteCollection {
                collection: id.clone(),
                backup_passphrase: None,
            })
            .unwrap();
        let mut skipped = false;
        let done = wait_for(handle, |e| match e {
            Event::BackupCreated(info) => panic!("unexpected backup: {info:?}"),
            Event::BackupSkipped { reason } => {
                assert_eq!(reason, BACKUP_SKIPPED_EMPTY);
                skipped = true;
                None
            }
            Event::Done(m) => Some(m),
            _ => None,
        });
        assert!(skipped, "{label}: BackupSkipped expected");
        assert_eq!(done, format!("{label} deleted (empty, no backup needed)"));
    }
    assert!(!backups.exists());
}
