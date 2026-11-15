//! Integration tests for the gnome-keyring master password interface.
//!
//! Run only through `scripts/it-session.sh` (private bus, throwaway keyring):
//! `bash scripts/it-session.sh cargo test -p kring-core --test it_master_password -- --ignored`

mod common;

use common::within;
use kring_core::error::KringError;
use kring_core::model::{CollectionId, NewItem, SecretValue};
use kring_core::secret_service::SecretServiceBackend;
use kring_core::{MasterPasswordStore, SecretStore};

/// Returns the lock state of a collection as listed by the backend.
async fn is_locked(backend: &SecretServiceBackend, id: &CollectionId) -> bool {
    let collections = within(backend.list_collections()).await.unwrap();
    collections
        .iter()
        .find(|c| &c.id == id)
        .unwrap_or_else(|| panic!("collection {id:?} not listed"))
        .locked
}

/// Create, unlock (wrong and right password) and change password, all without prompts.
#[tokio::test]
#[ignore]
async fn create_unlock_change_roundtrip() {
    if !common::it_guard() {
        return;
    }
    let backend = within(SecretServiceBackend::connect()).await.unwrap();
    let pw1 = SecretValue::from_text("pw1");
    let pw2 = SecretValue::from_text("pw2");
    let wrong = SecretValue::from_text("wrong");

    let id = within(backend.create_with_password("kring-it", &pw1))
        .await
        .unwrap();
    let collections = within(backend.list_collections()).await.unwrap();
    let created = collections
        .iter()
        .find(|c| c.id == id)
        .expect("created collection is listed");
    assert_eq!(created.label, "kring-it");
    assert!(!created.locked, "a new collection starts unlocked");

    within(backend.lock(&id)).await.unwrap();
    assert!(is_locked(&backend, &id).await);

    let err = within(backend.unlock_with_password(&id, &wrong))
        .await
        .unwrap_err();
    match &err {
        KringError::Dbus { context, .. } => assert_eq!(context, "unlock"),
        other => panic!("unexpected error {other:?}"),
    }
    assert!(is_locked(&backend, &id).await);

    within(backend.unlock_with_password(&id, &pw1))
        .await
        .unwrap();
    assert!(!is_locked(&backend, &id).await);

    within(backend.change_password(&id, &pw1, &pw2))
        .await
        .unwrap();
    within(backend.lock(&id)).await.unwrap();
    assert!(is_locked(&backend, &id).await);

    let err = within(backend.unlock_with_password(&id, &pw1))
        .await
        .unwrap_err();
    assert!(matches!(err, KringError::Dbus { .. }), "{err:?}");
    within(backend.unlock_with_password(&id, &pw2))
        .await
        .unwrap();
    assert!(!is_locked(&backend, &id).await);
}

/// Changing the password with a wrong original password fails and keeps the old one.
#[tokio::test]
#[ignore]
async fn change_password_with_wrong_original_fails() {
    if !common::it_guard() {
        return;
    }
    let backend = within(SecretServiceBackend::connect()).await.unwrap();
    let pw = SecretValue::from_text("right");
    let wrong = SecretValue::from_text("wrong");
    let other = SecretValue::from_text("other");

    let id = within(backend.create_with_password("kring-it-change", &pw))
        .await
        .unwrap();
    let err = within(backend.change_password(&id, &wrong, &other))
        .await
        .unwrap_err();
    match &err {
        KringError::Dbus { context, .. } => assert_eq!(context, "change_password"),
        other => panic!("unexpected error {other:?}"),
    }
    within(backend.lock(&id)).await.unwrap();
    within(backend.unlock_with_password(&id, &pw))
        .await
        .unwrap();
    assert!(!is_locked(&backend, &id).await);
}

/// Listing the items of a locked collection works without a prompt and marks them locked.
#[tokio::test]
#[ignore]
async fn list_items_of_locked_collection() {
    if !common::it_guard() {
        return;
    }
    let backend = within(SecretServiceBackend::connect()).await.unwrap();
    let pw = SecretValue::from_text("pw");
    let id = within(backend.create_with_password("kring-it-locked-list", &pw))
        .await
        .unwrap();
    let item = NewItem {
        label: "locked-entry".into(),
        attributes: [("kring-it".to_string(), "locked-list".to_string())].into(),
        secret: SecretValue::from_text("s"),
        replace: false,
    };
    within(backend.create_item(&id, item)).await.unwrap();
    within(backend.lock(&id)).await.unwrap();
    assert!(is_locked(&backend, &id).await);

    let items = within(backend.list_items(&id)).await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].label, "locked-entry");
    assert!(items[0].locked, "items of a locked collection are locked");
}
