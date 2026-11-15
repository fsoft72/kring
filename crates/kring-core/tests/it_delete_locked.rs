//! Deleting a LOCKED collection through the standard Secret Service API.
//!
//! Run only through `scripts/it-session.sh` (private bus, throwaway keyring):
//! `bash scripts/it-session.sh cargo test -p kring-core --test it_delete_locked -- --ignored`

mod common;

use std::collections::BTreeMap;

use common::within;
use kring_core::model::{NewItem, SecretValue, decode_path_segment};
use kring_core::secret_service::SecretServiceBackend;
use kring_core::{MasterPasswordStore, SecretStore};

/// A locked collection holding an item still reports its item count, and
/// `delete_collection` deletes it without a prompt; the daemon removes its
/// keyring file (each bus call bounded by the 10 s timeout of `within`).
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
    // One item, so the locked listing documents what gnome-keyring reports.
    let item = NewItem {
        label: "t".into(),
        attributes: BTreeMap::from([("service".to_string(), "kring-it-delete".to_string())]),
        secret: SecretValue::from_text("s"),
        replace: false,
    };
    within(backend.create_item(&id, item)).await.unwrap();
    within(backend.lock(&id)).await.unwrap();
    let listed = within(backend.list_collections()).await.unwrap();
    let locked = listed.iter().find(|c| c.id == id).expect("listed");
    assert!(locked.locked, "{locked:?}");
    // A locked collection still reports its items (kring never relies on it:
    // a locked keyring never counts as empty).
    assert!(locked.item_count > 0, "{locked:?}");

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
