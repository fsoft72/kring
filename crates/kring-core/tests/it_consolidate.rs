//! End-to-end consolidation test on a throwaway gnome-keyring.
//!
//! Run only through `scripts/it-session.sh` (private bus, throwaway keyring):
//! `bash scripts/it-session.sh cargo test -p kring-core --test it_consolidate -- --ignored`

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::within;
use kring_core::model::{
    Attributes, CollectionId, CollectionInfo, GENERIC_SCHEMA, ItemInfo, LOGIN_COLLECTION_PATH,
    NewItem, SCHEMA_ATTRIBUTE, SecretValue,
};
use kring_core::paths::keyrings_dir;
use kring_core::secret_service::SecretServiceBackend;
use kring_core::transfer::consolidate::{SkipReason, plan_consolidation, snapshot_collections};
use kring_core::transfer::consolidate_apply::apply_consolidation;
use kring_core::transfer::plan::Choice;
use kring_core::{MasterPasswordStore, SecretStore};

/// Master password of the throwaway orphan collections.
const ORPHAN_PASSWORD: &str = "orphan-pw";
/// Alias that consolidation points at the target.
const DEFAULT_ALIAS: &str = "default";
/// Schema attribute set on the login items only: gnome-keyring adds it by
/// itself (asynchronously, on reload), and the orphan items are created
/// without it on purpose, so the planner must treat a missing schema as the
/// generic one.
const SCHEMA: (&str, &str) = (SCHEMA_ATTRIBUTE, GENERIC_SCHEMA);

/// Builds an attribute map from pairs.
fn attrs(pairs: &[(&str, &str)]) -> Attributes {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Builds a new item with the given label, attributes and secret text.
fn new_item(label: &str, pairs: &[(&str, &str)], secret: &str) -> NewItem {
    NewItem {
        label: label.into(),
        attributes: attrs(pairs),
        secret: SecretValue::from_text(secret),
        replace: false,
    }
}

/// Lists the `.keyring` file names of the private keyrings directory.
fn keyring_files() -> BTreeSet<String> {
    let dir: PathBuf = keyrings_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return BTreeSet::new();
    };
    entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".keyring"))
        .collect()
}

/// Finds a collection by label in a fresh listing.
async fn find_collection(backend: &SecretServiceBackend, label: &str) -> Option<CollectionInfo> {
    within(backend.list_collections())
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.label == label)
}

/// Lists the items of a collection.
async fn items_of(backend: &SecretServiceBackend, id: &CollectionId) -> Vec<ItemInfo> {
    within(backend.list_items(id)).await.unwrap()
}

/// Returns the secret text of the item with the given attribute value, if any.
async fn secret_of(
    backend: &SecretServiceBackend,
    id: &CollectionId,
    user: &str,
) -> Option<(usize, String)> {
    let items: Vec<ItemInfo> = items_of(backend, id)
        .await
        .into_iter()
        .filter(|i| i.attributes.get("user").map(String::as_str) == Some(user))
        .collect();
    let item = items.first()?;
    let secret = within(backend.read_secret(&item.id)).await.unwrap();
    Some((
        items.len(),
        String::from_utf8(secret.as_bytes().to_vec()).unwrap(),
    ))
}

/// Plans and applies a consolidation of orphans into login on a private keyring.
#[tokio::test]
#[ignore]
async fn consolidate_orphans_into_login() {
    if !common::it_guard() {
        return;
    }
    let backend = within(SecretServiceBackend::connect()).await.unwrap();
    let login = CollectionId(LOGIN_COLLECTION_PATH.to_string());
    let password = SecretValue::from_text(ORPHAN_PASSWORD);

    // Login holds the identities the orphans will clash with; only the
    // login items carry the schema.
    let alice = [("app", "kring-it"), ("user", "alice")];
    let bob = [("app", "kring-it"), ("user", "bob")];
    let login_alice = [SCHEMA, alice[0], alice[1]];
    let login_bob = [SCHEMA, bob[0], bob[1]];
    within(backend.create_item(&login, new_item("alice", &login_alice, "alice-secret")))
        .await
        .unwrap();
    within(backend.create_item(&login, new_item("bob", &login_bob, "bob-old")))
        .await
        .unwrap();

    within(backend.create_with_password("Orphan Empty", &password))
        .await
        .unwrap();
    let dup = within(backend.create_with_password("Orphan Dup", &password))
        .await
        .unwrap();
    let conflict = within(backend.create_with_password("Orphan Conflict", &password))
        .await
        .unwrap();
    let locked = within(backend.create_with_password("Orphan Locked", &password))
        .await
        .unwrap();
    within(backend.create_item(&dup, new_item("alice", &alice, "alice-secret")))
        .await
        .unwrap();
    within(backend.create_item(&conflict, new_item("bob", &bob, "bob-new")))
        .await
        .unwrap();
    within(backend.create_item(
        &locked,
        new_item(
            "carol",
            &[("app", "kring-it"), ("user", "carol")],
            "carol-secret",
        ),
    ))
    .await
    .unwrap();
    within(backend.set_alias(DEFAULT_ALIAS, &locked))
        .await
        .unwrap();
    within(backend.lock(&locked)).await.unwrap();

    let files_before = keyring_files();
    let orphan_files: BTreeSet<String> = files_before
        .iter()
        .filter(|n| n.to_lowercase().contains("orphan"))
        .cloned()
        .collect();
    assert_eq!(
        orphan_files.len(),
        4,
        "four orphan files expected, got {files_before:?}"
    );

    // Plan like the worker does.
    let collections = within(backend.list_collections()).await.unwrap();
    let snapshots = within(snapshot_collections(&backend, &collections, &login))
        .await
        .unwrap();
    let current_default = within(backend.read_alias(DEFAULT_ALIAS)).await.unwrap();
    let plan = plan_consolidation(&snapshots, &login, current_default.as_ref()).unwrap();
    assert!(plan.set_default, "default points at the locked orphan");
    assert_eq!(plan.moves.len(), 2, "dup and conflict are moved");
    assert_eq!(plan.delete_empty.len(), 1, "only the empty orphan");
    assert_eq!(plan.conflict_count, 1);
    assert!(
        plan.skipped
            .iter()
            .any(|(id, _, reason)| id == &locked && *reason == SkipReason::Locked),
        "locked orphan is skipped: {:?}",
        plan.skipped
    );

    // UseIncoming for every conflict.
    let choices: Vec<Vec<Choice>> = plan
        .moves
        .iter()
        .map(|step| vec![Choice::UseIncoming; step.plan.conflicts.len()])
        .collect();
    let mut progress = |_done: usize, _total: usize| {};
    let report = within(apply_consolidation(
        &backend,
        &plan,
        &choices,
        &mut progress,
    ))
    .await
    .unwrap();
    assert!(report.completed, "{:?}", report.outcomes);

    // Login: conflict item overwritten, duplicate not doubled.
    assert_eq!(
        secret_of(&backend, &login, "bob").await,
        Some((1, "bob-new".to_string()))
    );
    assert_eq!(
        secret_of(&backend, &login, "alice").await,
        Some((1, "alice-secret".to_string()))
    );
    assert_eq!(items_of(&backend, &login).await.len(), 2);

    // Deleted orphans are gone, the locked one is untouched.
    for label in ["Orphan Empty", "Orphan Dup", "Orphan Conflict"] {
        assert!(
            find_collection(&backend, label).await.is_none(),
            "{label} still listed"
        );
    }
    let still_there = find_collection(&backend, "Orphan Locked")
        .await
        .expect("locked orphan still listed");
    assert!(still_there.locked);
    assert_eq!(still_there.item_count, 1);

    // Default alias is login.
    let default = within(backend.read_alias(DEFAULT_ALIAS)).await.unwrap();
    assert_eq!(default, Some(login));

    // Files of deleted collections are gone; the locked one remains.
    let files_after = keyring_files();
    let remaining: BTreeSet<String> = files_after
        .iter()
        .filter(|n| n.to_lowercase().contains("orphan"))
        .cloned()
        .collect();
    assert_eq!(remaining.len(), 1, "leftover orphan files: {remaining:?}");
    assert!(
        remaining
            .iter()
            .next()
            .unwrap()
            .to_lowercase()
            .contains("locked"),
        "wrong orphan file kept: {remaining:?}"
    );
    assert_eq!(
        files_before.difference(&files_after).count(),
        3,
        "exactly three files removed: before {files_before:?}, after {files_after:?}"
    );
}
