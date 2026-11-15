//! Regression test: the worker thread must shut down without panicking.
//!
//! The oo7 `Service` spawns a Tokio task in its `Drop`; dropping the backend
//! after the worker runtime is gone used to panic with "there is no reactor
//! running". Run only through `scripts/it-session.sh` (private bus, throwaway
//! keyring):
//! `bash scripts/it-session.sh cargo test -p kring --test it_shutdown -- --ignored`

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

use kring::startup;
use kring::worker::{self, Event, WorkerConfig, WorkerHandle};

/// Maximum time to wait for each worker event or for its shutdown.
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Closing the command channel stops the worker thread without a panic.
#[test]
#[ignore]
fn worker_shuts_down_without_panic() {
    if !common::it_guard() {
        return;
    }
    let panics = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&panics);
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        counter.fetch_add(1, Ordering::SeqCst);
        default_hook(info);
    }));

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
    let WorkerHandle { tx, rx } = worker::spawn(connected.store, connected.provider, config, || {});

    // Wait until the worker has started and listed the collections.
    loop {
        match rx
            .recv_timeout(EVENT_TIMEOUT)
            .expect("worker did not start")
        {
            Event::Collections(_) => break,
            Event::Error(e) => panic!("worker error: {e}"),
            _ => {}
        }
    }

    // Closing the command channel ends the worker loop; the event channel
    // disconnects once the thread has finished dropping everything.
    drop(tx);
    loop {
        match rx.recv_timeout(EVENT_TIMEOUT) {
            Ok(_) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => panic!("worker did not shut down"),
        }
    }
    assert_eq!(
        panics.load(Ordering::SeqCst),
        0,
        "worker panicked on shutdown"
    );
}
