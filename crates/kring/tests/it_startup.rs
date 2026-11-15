//! Integration test for the startup connection and the worker on a real bus.
//!
//! Run only through `scripts/it-session.sh` (private bus, throwaway keyring):
//! `bash scripts/it-session.sh cargo test -p kring --test it_startup -- --ignored`

mod common;

use std::time::Duration;

use kring::startup;
use kring::worker::{self, Event, WorkerConfig};

/// Maximum time to wait for the worker to list the collections.
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

/// The connection made at startup keeps working inside the worker thread.
#[test]
#[ignore]
fn worker_lists_collections_over_startup_connection() {
    if !common::it_guard() {
        return;
    }
    let connected = startup::connect();
    assert!(
        connected.store.is_some(),
        "connect failed: {:?}",
        connected.error
    );
    assert!(connected.provider.is_some());
    let dir = tempfile::tempdir().unwrap();
    let mut config = WorkerConfig::default_paths();
    config.backups.root = dir.path().join("backups");
    config.ssh_dir = None;
    config.ssh_agent_sock = None;
    let handle = worker::spawn(connected.store, connected.provider, config, || {});
    loop {
        let event = handle
            .rx
            .recv_timeout(EVENT_TIMEOUT)
            .expect("worker did not list collections in time");
        match event {
            Event::Collections(list) => {
                assert!(list.iter().any(|c| c.is_login), "login collection listed");
                return;
            }
            Event::Error(e) => panic!("worker error: {e}"),
            _ => {}
        }
    }
}
