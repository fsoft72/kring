//! Integration tests for the Secret Service backend.
//!
//! Run only through `scripts/it-session.sh` (private bus, throwaway keyring):
//! `bash scripts/it-session.sh cargo test -p kring-core --test it_secret_service -- --ignored`

mod common;

use std::collections::BTreeMap;

use common::within;
use kring_core::SecretStore;
use kring_core::error::KringError;
use kring_core::model::{CollectionId, ItemUpdate, LOGIN_COLLECTION_PATH, NewItem, SecretValue};
use kring_core::secret_service::SecretServiceBackend;

/// Builds a new item with a unique `service` attribute.
fn new_item(tag: &str, secret: &str) -> NewItem {
    NewItem {
        label: "t".into(),
        attributes: BTreeMap::from([("service".to_string(), format!("kring-test-{tag}"))]),
        secret: SecretValue::from_text(secret),
        replace: false,
    }
}

/// Returns the login collection id.
fn login() -> CollectionId {
    CollectionId(LOGIN_COLLECTION_PATH.to_string())
}

/// The login collection is flagged and carries the `default` alias.
#[tokio::test]
#[ignore]
async fn lists_login_with_default_alias() {
    if !common::it_guard() {
        return;
    }
    let backend = within(SecretServiceBackend::connect()).await.unwrap();
    let collections = within(backend.list_collections()).await.unwrap();
    let login = collections
        .iter()
        .find(|c| c.id == self::login())
        .expect("login collection");
    assert!(login.is_login);
    assert!(!login.locked);
    assert!(login.aliases.iter().any(|a| a == "default"), "{login:?}");
}

/// Create, read, update and delete an item.
#[tokio::test]
#[ignore]
async fn item_crud_roundtrip() {
    if !common::it_guard() {
        return;
    }
    let backend = within(SecretServiceBackend::connect()).await.unwrap();
    let id = within(backend.create_item(&login(), new_item("crud", "s3")))
        .await
        .unwrap();

    let items = within(backend.list_items(&login())).await.unwrap();
    let info = items.iter().find(|i| i.id == id).expect("listed");
    assert_eq!(info.label, "t");
    assert_eq!(info.attributes["service"], "kring-test-crud");

    let secret = within(backend.read_secret(&id)).await.unwrap();
    assert_eq!(secret.as_text(), Some("s3"));

    let update = ItemUpdate {
        label: Some("t2".into()),
        attributes: None,
        secret: Some(SecretValue::from_text("s4")),
    };
    within(backend.update_item(&id, update)).await.unwrap();
    let items = within(backend.list_items(&login())).await.unwrap();
    assert_eq!(items.iter().find(|i| i.id == id).unwrap().label, "t2");
    let secret = within(backend.read_secret(&id)).await.unwrap();
    assert_eq!(secret.as_text(), Some("s4"));

    within(backend.delete_item(&id)).await.unwrap();
    let items = within(backend.list_items(&login())).await.unwrap();
    assert!(items.iter().all(|i| i.id != id));
}

/// Deleting an already-deleted item reports `NotFound`.
#[tokio::test]
#[ignore]
async fn deleted_item_is_not_found() {
    if !common::it_guard() {
        return;
    }
    let backend = within(SecretServiceBackend::connect()).await.unwrap();
    let id = within(backend.create_item(&login(), new_item("gone", "x")))
        .await
        .unwrap();
    within(backend.delete_item(&id)).await.unwrap();
    let err = within(backend.delete_item(&id)).await.unwrap_err();
    assert!(matches!(err, KringError::NotFound(_)), "{err:?}");
    let err = within(backend.read_secret(&id)).await.unwrap_err();
    assert!(matches!(err, KringError::NotFound(_)), "{err:?}");
}
