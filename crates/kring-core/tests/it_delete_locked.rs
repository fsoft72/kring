//! Deleting a LOCKED collection through the standard Secret Service API.
//!
//! Run only through `scripts/it-session.sh` (private bus, throwaway keyring):
//! `bash scripts/it-session.sh cargo test -p kring-core --test it_delete_locked -- --ignored`

mod common;

use common::within;
use kring_core::model::{SecretValue, decode_path_segment};
use kring_core::secret_service::SecretServiceBackend;
use kring_core::{MasterPasswordStore, SecretStore};

/// A locked collection is deleted by `delete_collection` without a prompt
/// and its keyring file is removed by the daemon (each bus call bounded by the 10 s timeout of `within`).
#[tokio::test]
#[ignore]
async fn delete_locked_collection_without_prompt() {
    if !common::it_guard() {
        return;
    }
    let backend = within(SecretServiceBackend::connect()).await.unwrap();
    let pw = SecretValue::from_text("pw");
    let id = within(backend.create_with_password("kring-it-delete-locked", &pw))
        .await
        .unwrap();
    within(backend.lock(&id)).await.unwrap();
    let listed = within(backend.list_collections()).await.unwrap();
    assert!(listed.iter().any(|c| c.id == id && c.locked), "{listed:?}");

    // The keyring file of the collection (inside the throwaway XDG_DATA_HOME).
    let segment = id.0.rsplit('/').next().unwrap();
    let data = std::env::var_os("XDG_DATA_HOME").expect("XDG_DATA_HOME set by it-session");
    let file = std::path::Path::new(&data)
        .join("keyrings")
        .join(format!("{}.keyring", decode_path_segment(segment).unwrap()));
    assert!(file.exists(), "{}", file.display());

    within(backend.delete_collection(&id)).await.unwrap();

    let listed = within(backend.list_collections()).await.unwrap();
    assert!(listed.iter().all(|c| c.id != id), "{listed:?}");
    assert!(!file.exists(), "the daemon removes the keyring file");
}
