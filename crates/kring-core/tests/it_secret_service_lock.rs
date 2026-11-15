//! Lock test for the Secret Service backend, in its own file on purpose.
//!
//! It locks `login`, and unlocking through the standard API needs a prompt, so
//! it must run in its own session:
//! `bash scripts/it-session.sh cargo test -p kring-core --test it_secret_service_lock -- --ignored`

mod common;

use std::collections::BTreeMap;

use common::within;
use kring_core::SecretStore;
use kring_core::error::KringError;
use kring_core::model::{CollectionId, LOGIN_COLLECTION_PATH, NewItem, SecretValue};
use kring_core::secret_service::SecretServiceBackend;

/// Reading a secret from a locked collection returns `Locked` without prompting,
/// while listing its items still works and reports them locked.
#[tokio::test]
#[ignore]
async fn locked_secret_returns_locked() {
    if !common::it_guard() {
        return;
    }
    let backend = within(SecretServiceBackend::connect()).await.unwrap();
    let login = CollectionId(LOGIN_COLLECTION_PATH.to_string());
    let item = NewItem {
        label: "t".into(),
        attributes: BTreeMap::from([("service".to_string(), "kring-test-lock".to_string())]),
        secret: SecretValue::from_text("s3"),
        replace: false,
    };
    let id = within(backend.create_item(&login, item)).await.unwrap();
    within(backend.lock(&login)).await.unwrap();
    let err = within(backend.read_secret(&id)).await.unwrap_err();
    assert!(matches!(err, KringError::Locked(_)), "{err:?}");
    // Listing a locked collection still succeeds and marks every item locked.
    let items = within(backend.list_items(&login)).await.unwrap();
    assert!(items.iter().any(|i| i.id == id), "{items:?}");
    assert!(items.iter().all(|i| i.locked), "{items:?}");
}
