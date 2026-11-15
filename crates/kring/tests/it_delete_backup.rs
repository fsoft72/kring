//! Integration test: deleting a collection backs up its real keyring file first.
//!
//! It checks on a real gnome-keyring that the decoded collection object path name
//! (non-alphanumeric bytes are escaped as `_XX`) matches its `<name>.keyring` file,
//! which the worker requires before deleting.
//! Run only through `scripts/it-session.sh` (private bus, throwaway keyring):
//! `bash scripts/it-session.sh cargo test -p kring --test it_delete_backup -- --ignored`

mod common;

use std::time::Duration;

use kring::startup;
use kring::worker::{self, Command, Event, WorkerConfig, WorkerHandle};
use kring_core::model::{SecretValue, decode_path_segment};

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

/// A collection delete writes a backup containing the collection's keyring file.
#[test]
#[ignore]
fn delete_collection_backs_up_its_keyring_file() {
    if !common::it_guard() {
        return;
    }
    let connected = startup::connect();
    assert!(
        connected.store.is_some(),
        "connect failed: {:?}",
        connected.error
    );
    let dir = tempfile::tempdir().unwrap();
    let mut config = WorkerConfig::default_paths();
    config.backups.root = dir.path().join("backups");
    config.ssh_dir = None;
    config.ssh_agent_sock = None;
    let keyrings = config.keyrings_dir.clone();
    let handle = worker::spawn(connected.store, connected.provider, config, || {});
    handle
        .tx
        .send(Command::CreateCollection {
            label: LABEL.into(),
            password: SecretValue::from_text("pw"),
        })
        .unwrap();
    let id = wait_for(&handle, |e| match e {
        Event::Collections(list) => list.into_iter().find(|c| c.label == LABEL).map(|c| c.id),
        _ => None,
    });
    wait_for(&handle, |e| matches!(e, Event::Done(_)).then_some(()));
    let segment = id.0.rsplit('/').next().unwrap();
    assert!(segment.contains("_5f"), "escaped path expected: {}", id.0);
    let name = decode_path_segment(segment).unwrap();
    let file = keyrings.join(format!("{name}.keyring"));
    assert!(file.is_file(), "{} missing", file.display());

    handle
        .tx
        .send(Command::DeleteCollection {
            collection: id.clone(),
            backup_passphrase: None,
        })
        .unwrap();
    let info = wait_for(&handle, |e| match e {
        Event::BackupCreated(info) => Some(info),
        _ => None,
    });
    assert!(info.files.iter().any(|f| f.original == file), "{info:?}");
    let done = wait_for(&handle, |e| match e {
        Event::Done(m) => Some(m),
        _ => None,
    });
    assert!(done.starts_with("Collection deleted, backup in "), "{done}");
}
