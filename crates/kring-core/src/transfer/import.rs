//! Planning and executing the import of offline items into a collection.
//!
//! Policy: same attributes and same secret in the target is skipped as a
//! duplicate; same attributes with a different secret is skipped and reported
//! as a conflict (never overwritten); an item whose file had no secret is
//! skipped and counted (it never takes part in duplicate or conflict
//! detection, so it cannot shadow a real item); anything else is created with
//! `replace = false`. Attribute equality ignores `xdg:content-type`.

use crate::error::{KringError, Result};
use crate::keyring_file::textual::OfflineItem;
use crate::model::{Attributes, CollectionId, ItemInfo, NewItem, SecretValue};
use crate::store::SecretStore;
use crate::transfer::plan::{Action, Existing, Incoming, TransferSource, identity, plan_transfer};

/// What the import does with one incoming item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportDecision {
    /// The item is new and will be created.
    Create,
    /// An item with the same attributes and secret already exists.
    SkipDuplicate,
    /// An item with the same attributes but a different secret exists.
    SkipConflict,
    /// The item had no secret in its file.
    SkipNoSecret,
}

/// The decision for one incoming item (never carries the secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportPlanEntry {
    /// Label of the incoming item.
    pub label: String,
    /// Attributes of the incoming item.
    pub attributes: Attributes,
    /// What will happen to it.
    pub decision: ImportDecision,
}

/// Outcome of an import (never carries secrets).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Items created in the target.
    pub created: usize,
    /// Items skipped because an identical item exists.
    pub duplicates: usize,
    /// Labels of items skipped because the attributes exist with another secret.
    pub conflicts: Vec<String>,
    /// `(label, error message)` of items that failed to be created.
    pub failed: Vec<(String, String)>,
    /// Items skipped because their file had no secret for them.
    pub no_secret: usize,
}

/// Decides what to do with each incoming item, in order (pure).
///
/// Earlier incoming items that will be created count as existing for later
/// ones, so the first of two clashing incoming items wins. Items without a
/// secret are always `SkipNoSecret` and never count as existing.
pub fn plan_import(
    incoming: &[OfflineItem],
    existing: &[(ItemInfo, SecretValue)],
) -> Vec<ImportPlanEntry> {
    let incoming_items: Vec<Incoming> = incoming
        .iter()
        .enumerate()
        .map(|(index, item)| Incoming {
            source: TransferSource::Offline(index),
            label: item.label.clone(),
            attributes: item.attributes.clone(),
            secret: item.secret.clone(),
            secret_missing: item.secret_missing,
            modified: item.modified,
        })
        .collect();
    let existing_items: Vec<Existing> = existing
        .iter()
        .map(|(info, secret)| Existing {
            id: info.id.clone(),
            label: info.label.clone(),
            attributes: info.attributes.clone(),
            secret: secret.clone(),
            modified: info.modified,
        })
        .collect();
    let plan = plan_transfer(&incoming_items, &existing_items);
    incoming
        .iter()
        .zip(&plan.actions)
        .map(|(item, action)| ImportPlanEntry {
            label: item.label.clone(),
            attributes: item.attributes.clone(),
            decision: match action {
                Action::Create => ImportDecision::Create,
                Action::Duplicate { .. } | Action::SkipSameBatch => ImportDecision::SkipDuplicate,
                Action::Conflict(_) | Action::ConflictSameBatch => ImportDecision::SkipConflict,
                Action::NoSecret => ImportDecision::SkipNoSecret,
            },
        })
        .collect()
}

/// Imports `incoming` into `target`, following the policy in the module docs.
///
/// Fails with `Locked` when the target is locked and `NotFound` when it does
/// not exist. Secrets of existing items are read only when their attributes
/// match an incoming item. A failure creating one item is recorded in
/// [`ImportReport::failed`] and the import continues.
pub async fn import_items<S: SecretStore + ?Sized>(
    store: &S,
    target: &CollectionId,
    incoming: Vec<OfflineItem>,
) -> Result<ImportReport> {
    let collections = store.list_collections().await?;
    let Some(collection) = collections.iter().find(|c| &c.id == target) else {
        return Err(KringError::NotFound(target.0.clone()));
    };
    if collection.locked {
        return Err(KringError::Locked(target.0.clone()));
    }
    let incoming_attrs: Vec<Attributes> = incoming
        .iter()
        .filter(|i| !i.secret_missing)
        .map(|i| identity(&i.attributes))
        .collect();
    let mut existing = Vec::new();
    for info in store.list_items(target).await? {
        if !incoming_attrs.contains(&identity(&info.attributes)) {
            continue;
        }
        let secret = store.read_secret(&info.id).await?;
        existing.push((info, secret));
    }
    let plan = plan_import(&incoming, &existing);
    let mut report = ImportReport::default();
    for (item, entry) in incoming.into_iter().zip(plan) {
        match entry.decision {
            ImportDecision::SkipDuplicate => report.duplicates += 1,
            ImportDecision::SkipConflict => report.conflicts.push(entry.label),
            ImportDecision::SkipNoSecret => report.no_secret += 1,
            ImportDecision::Create => {
                let new_item = NewItem {
                    label: item.label,
                    attributes: item.attributes,
                    secret: item.secret,
                    replace: false,
                };
                match store.create_item(target, new_item).await {
                    Ok(_) => report.created += 1,
                    Err(e) => report.failed.push((entry.label, e.to_string())),
                }
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_store::FakeStore;
    use crate::model::{ItemId, ItemUpdate};
    use oo7::CONTENT_TYPE_ATTRIBUTE;

    /// Builds attributes from pairs.
    fn attrs(pairs: &[(&str, &str)]) -> Attributes {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Builds an incoming item with a text secret.
    fn offline(label: &str, pairs: &[(&str, &str)], secret: &str) -> OfflineItem {
        OfflineItem {
            label: label.into(),
            attributes: attrs(pairs),
            secret: SecretValue::from_text(secret),
            created: 0,
            modified: 0,
            secret_missing: false,
        }
    }

    /// Builds an existing item with its secret.
    fn existing(pairs: &[(&str, &str)], secret: &str) -> (ItemInfo, SecretValue) {
        let info = ItemInfo {
            id: ItemId("/x/1".into()),
            collection: CollectionId("/x".into()),
            label: "old".into(),
            attributes: attrs(pairs),
            locked: false,
            created: 0,
            modified: 0,
        };
        (info, SecretValue::from_text(secret))
    }

    /// Decisions only, for compact assertions.
    fn decisions(plan: &[ImportPlanEntry]) -> Vec<ImportDecision> {
        plan.iter().map(|e| e.decision).collect()
    }

    /// Seeds an item into a store collection.
    async fn seed(store: &FakeStore, c: &CollectionId, pairs: &[(&str, &str)], secret: &str) {
        let item = NewItem {
            label: "seed".into(),
            attributes: attrs(pairs),
            secret: SecretValue::from_text(secret),
            replace: false,
        };
        store.create_item(c, item).await.unwrap();
    }

    /// Duplicates and conflicts against existing items are detected.
    #[test]
    fn plan_marks_duplicates_and_conflicts() {
        let ex = [existing(&[("a", "1")], "s1"), existing(&[("a", "2")], "s2")];
        let incoming = [
            offline("dup", &[("a", "1")], "s1"),
            offline("conf", &[("a", "2")], "other"),
            offline("new", &[("a", "3")], "s3"),
        ];
        let plan = plan_import(&incoming, &ex);
        assert_eq!(
            decisions(&plan),
            [
                ImportDecision::SkipDuplicate,
                ImportDecision::SkipConflict,
                ImportDecision::Create
            ]
        );
        assert_eq!(plan[0].label, "dup");
        assert_eq!(plan[2].attributes, attrs(&[("a", "3")]));
    }

    /// Content type attribute is ignored on both sides.
    #[test]
    fn comparable_drops_content_type() {
        let a = attrs(&[("a", "1"), (CONTENT_TYPE_ATTRIBUTE, "text/plain")]);
        assert_eq!(identity(&a), attrs(&[("a", "1")]));
        let ex = [existing(
            &[("a", "1"), (CONTENT_TYPE_ATTRIBUTE, "text/plain")],
            "s",
        )];
        let plan = plan_import(&[offline("i", &[("a", "1")], "s")], &ex);
        assert_eq!(decisions(&plan), [ImportDecision::SkipDuplicate]);
        let plan = plan_import(
            &[offline(
                "i",
                &[("a", "1"), (CONTENT_TYPE_ATTRIBUTE, "x/y")],
                "t",
            )],
            &ex,
        );
        assert_eq!(decisions(&plan), [ImportDecision::SkipConflict]);
    }

    /// Within the incoming list the first item wins.
    #[test]
    fn plan_handles_duplicates_within_incoming() {
        let incoming = [
            offline("first", &[("a", "1")], "s"),
            offline("same", &[("a", "1")], "s"),
            offline("diff", &[("a", "1")], "other"),
        ];
        assert_eq!(
            decisions(&plan_import(&incoming, &[])),
            [
                ImportDecision::Create,
                ImportDecision::SkipDuplicate,
                ImportDecision::SkipConflict
            ]
        );
    }

    /// Only new items are created; the report counts the rest.
    #[tokio::test]
    async fn import_creates_only_new() {
        let store = FakeStore::new();
        let c = store.add_collection("t", "pw", false);
        seed(&store, &c, &[("a", "1")], "s1").await;
        seed(&store, &c, &[("a", "2")], "s2").await;
        seed(&store, &c, &[("z", "9")], "untouched").await;
        let incoming = vec![
            offline("dup", &[("a", "1")], "s1"),
            offline("conf", &[("a", "2")], "other"),
            offline("new", &[("a", "3")], "s3"),
        ];
        let report = import_items(&store, &c, incoming).await.unwrap();
        assert_eq!(
            report,
            ImportReport {
                created: 1,
                duplicates: 1,
                conflicts: vec!["conf".into()],
                failed: vec![],
                no_secret: 0,
            }
        );
        let items = store.list_items(&c).await.unwrap();
        assert_eq!(items.len(), 4);
        let new = items.iter().find(|i| i.label == "new").unwrap();
        assert_eq!(store.read_secret(&new.id).await.unwrap().as_bytes(), b"s3");
    }

    /// Builds an incoming item that had no secret in its file.
    fn no_secret(label: &str, pairs: &[(&str, &str)]) -> OfflineItem {
        let mut item = offline(label, pairs, "");
        item.secret_missing = true;
        item
    }

    /// Items without a secret never take part in duplicate or conflict detection.
    #[test]
    fn plan_skips_items_without_secret() {
        let ex = [existing(&[("a", "1")], "s1")];
        let incoming = [
            no_secret("empty", &[("a", "2")]),
            offline("real", &[("a", "2")], "s2"),
            no_secret("dup-attrs", &[("a", "1")]),
        ];
        assert_eq!(
            decisions(&plan_import(&incoming, &ex)),
            [
                ImportDecision::SkipNoSecret,
                ImportDecision::Create,
                ImportDecision::SkipNoSecret
            ]
        );
    }

    /// Items without a secret are skipped and counted; a real item after an
    /// empty one with the same attributes is still created.
    #[tokio::test]
    async fn import_skips_and_counts_items_without_secret() {
        let store = FakeStore::new();
        let c = store.add_collection("t", "pw", false);
        let incoming = vec![
            no_secret("empty", &[("a", "1")]),
            offline("real", &[("a", "1")], "s1"),
            no_secret("other", &[("b", "2")]),
        ];
        let report = import_items(&store, &c, incoming).await.unwrap();
        assert_eq!(
            report,
            ImportReport {
                created: 1,
                no_secret: 2,
                ..Default::default()
            }
        );
        let items = store.list_items(&c).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "real");
        assert_eq!(
            store.read_secret(&items[0].id).await.unwrap().as_bytes(),
            b"s1"
        );
    }

    /// A locked target is refused and nothing is created.
    #[tokio::test]
    async fn import_into_locked_fails() {
        let store = FakeStore::new();
        let c = store.add_collection("t", "pw", true);
        let err = import_items(&store, &c, vec![offline("n", &[("a", "1")], "s")])
            .await
            .unwrap_err();
        assert!(matches!(err, KringError::Locked(_)));
        let missing = CollectionId("/nope".into());
        let err = import_items(&store, &missing, vec![]).await.unwrap_err();
        assert!(matches!(err, KringError::NotFound(_)));
    }

    /// Store wrapper that fails `create_item` for one label.
    struct FailingStore {
        inner: FakeStore,
        fail_label: String,
    }

    #[async_trait::async_trait]
    impl SecretStore for FailingStore {
        async fn list_collections(&self) -> Result<Vec<crate::model::CollectionInfo>> {
            self.inner.list_collections().await
        }
        async fn list_items(&self, c: &CollectionId) -> Result<Vec<ItemInfo>> {
            self.inner.list_items(c).await
        }
        async fn read_secret(&self, item: &ItemId) -> Result<SecretValue> {
            self.inner.read_secret(item).await
        }
        async fn create_item(&self, c: &CollectionId, item: NewItem) -> Result<ItemId> {
            if item.label == self.fail_label {
                return Err(KringError::InvalidInput("boom".into()));
            }
            self.inner.create_item(c, item).await
        }
        async fn update_item(&self, item: &ItemId, update: ItemUpdate) -> Result<()> {
            self.inner.update_item(item, update).await
        }
        async fn delete_item(&self, item: &ItemId) -> Result<()> {
            self.inner.delete_item(item).await
        }
        async fn read_alias(&self, alias: &str) -> Result<Option<CollectionId>> {
            self.inner.read_alias(alias).await
        }
        async fn set_alias(&self, alias: &str, c: &CollectionId) -> Result<()> {
            self.inner.set_alias(alias, c).await
        }
        async fn lock(&self, c: &CollectionId) -> Result<()> {
            self.inner.lock(c).await
        }
        async fn rename_collection(&self, c: &CollectionId, label: &str) -> Result<()> {
            self.inner.rename_collection(c, label).await
        }
        async fn delete_collection(&self, c: &CollectionId) -> Result<()> {
            self.inner.delete_collection(c).await
        }
    }

    /// One failing item is recorded and the rest are still created.
    #[tokio::test]
    async fn import_continues_after_item_failure() {
        let inner = FakeStore::new();
        let c = inner.add_collection("t", "pw", false);
        let store = FailingStore {
            inner,
            fail_label: "bad".into(),
        };
        let incoming = vec![
            offline("ok1", &[("a", "1")], "s1"),
            offline("bad", &[("a", "2")], "s2"),
            offline("ok2", &[("a", "3")], "s3"),
        ];
        let report = import_items(&store, &c, incoming).await.unwrap();
        assert_eq!(report.created, 2);
        assert_eq!(
            report.failed,
            vec![("bad".to_string(), "invalid input: boom".to_string())]
        );
        assert_eq!(store.list_items(&c).await.unwrap().len(), 2);
    }
}
