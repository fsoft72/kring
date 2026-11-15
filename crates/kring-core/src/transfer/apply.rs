//! Executes a [`TransferPlan`] against a live target collection.
//!
//! Copy creates or updates items in the target. Move does the same and then
//! deletes a source item only when its content is verifiably present in the
//! target afterwards or, for a conflict kept as the target, only when the
//! target is at least as new (see [`source_safe_to_delete`]; in that case the
//! incoming secret is discarded and survives only in the pre-apply backup).
//! Move into the collection a source already lives in is refused. Only
//! [`TransferSource::Live`] sources are ever deleted; offline sources are
//! left alone (their files are retired separately). Per-item failures are
//! recorded and the run continues; a failed item never loses its source.
//! Reports carry labels and counts only, never secrets.

use crate::error::{KringError, Result};
use crate::model::{Attributes, CollectionId, ItemId, ItemUpdate, NewItem, SecretValue};
use crate::store::SecretStore;
use crate::transfer::plan::{Action, Choice, Incoming, TransferPlan, TransferSource, identity};

/// Whether source items are kept (copy) or removed after transfer (move).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferMode {
    /// Leave the sources untouched.
    Copy,
    /// Delete each live source whose content is safely in the target.
    Move,
}

/// Outcome of a transfer (labels and counts only, never secrets).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransferReport {
    /// Items created in the target.
    pub created: usize,
    /// Items identical to a target item (nothing to do).
    pub duplicates: usize,
    /// Target items overwritten with the incoming item.
    pub replaced: usize,
    /// Conflicts resolved by keeping the target item.
    pub kept_target: usize,
    /// Items skipped because the source had no secret.
    pub no_secret: usize,
    /// Items skipped because of an earlier incoming item (counts both
    /// `SkipSameBatch` and `ConflictSameBatch`).
    pub same_batch_skipped: usize,
    /// Live source items deleted (move only).
    pub source_deleted: usize,
    /// Labels of live sources kept on move because not safely transferred.
    pub source_kept: Vec<String>,
    /// `(label, error message)` of items that failed.
    pub failed: Vec<(String, String)>,
}

/// Decides whether a source item may be deleted after a move (pure).
///
/// `outcome_ok` is true when the item's content is known to be in the target:
/// the create succeeded, the update succeeded, or an identical item was
/// already created earlier in the batch. Rules per action:
///
/// - `Create`, `SkipSameBatch`: only when `outcome_ok`.
/// - `Duplicate`: always (identical content already in the target).
/// - `Conflict` with `UseIncoming`: only when `outcome_ok`.
/// - `Conflict` with `KeepTarget`: only when the target is at least as new.
///   The incoming secret is NOT in the target in that case; it survives only
///   in the pre-apply backup that callers must have taken.
/// - `NoSecret`, `ConflictSameBatch`: never.
///
/// `self_match` is true when the matched target item is the source item
/// itself (a move into its own collection); it is never safe to delete then.
pub fn source_safe_to_delete(
    action: &Action,
    choice: Option<Choice>,
    outcome_ok: bool,
    modified_incoming: u64,
    modified_existing: u64,
    self_match: bool,
) -> bool {
    if self_match {
        return false;
    }
    match action {
        Action::Create | Action::SkipSameBatch => outcome_ok,
        Action::Duplicate { .. } => true,
        Action::Conflict(_) => match choice {
            Some(Choice::UseIncoming) => outcome_ok,
            Some(Choice::KeepTarget) => modified_existing >= modified_incoming,
            None => false,
        },
        Action::NoSecret | Action::ConflictSameBatch => false,
    }
}

/// Returns the collection path of an item path (everything before the last `/`).
fn parent_collection(item: &ItemId) -> &str {
    item.0.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// Returns true when a Move would touch a source inside the target itself.
fn moves_into_own_collection(
    target: &CollectionId,
    incoming: &[Incoming],
    plan: &TransferPlan,
) -> bool {
    incoming.iter().zip(&plan.actions).any(|(item, action)| {
        let TransferSource::Live(source) = &item.source else {
            return false;
        };
        parent_collection(source) == target.0 || matched_existing(action, plan) == Some(source)
    })
}

/// Returns the target item an action matched, when it has one.
fn matched_existing<'a>(action: &'a Action, plan: &'a TransferPlan) -> Option<&'a ItemId> {
    match action {
        Action::Duplicate { existing } => Some(existing),
        Action::Conflict(index) => plan.conflicts.get(*index).map(|c| &c.existing),
        _ => None,
    }
}

/// Applies `plan` to `target`, one `choices` entry per conflict.
///
/// # Preconditions
///
/// - Callers MUST back up the source collection(s) before a Move.
/// - Callers MUST back up the target before any `UseIncoming` choice.
/// - Per the plan Global Constraints, the worker does this (Plan 3 Task 6).
///
/// Fails before any change when the choice or action counts do not match,
/// or when the target is missing or locked. Item failures go to
/// [`TransferReport::failed`] and never stop the run.
pub async fn apply_transfer<S: SecretStore + ?Sized>(
    store: &S,
    target: &CollectionId,
    incoming: &[Incoming],
    plan: &TransferPlan,
    choices: &[Choice],
    mode: TransferMode,
) -> Result<TransferReport> {
    if choices.len() != plan.conflicts.len() {
        return Err(KringError::InvalidInput(format!(
            "expected {} conflict choices, got {}",
            plan.conflicts.len(),
            choices.len()
        )));
    }
    if plan.actions.len() != incoming.len() {
        return Err(KringError::InvalidInput(
            "plan does not match the incoming items".into(),
        ));
    }
    let bad_index = plan
        .actions
        .iter()
        .any(|a| matches!(a, Action::Conflict(i) if *i >= plan.conflicts.len()));
    if bad_index {
        return Err(KringError::InvalidInput(
            "plan references a missing conflict".into(),
        ));
    }
    if mode == TransferMode::Move && moves_into_own_collection(target, incoming, plan) {
        return Err(KringError::InvalidInput(
            "Cannot move items into the collection they are in".into(),
        ));
    }
    let collections = store.list_collections().await?;
    let info = collections
        .iter()
        .find(|c| &c.id == target)
        .ok_or_else(|| KringError::NotFound(target.0.clone()))?;
    if info.locked {
        return Err(KringError::Locked(target.0.clone()));
    }
    let mut report = TransferReport::default();
    // Content created in this run, for same-batch duplicates.
    let mut created: Vec<(Attributes, SecretValue)> = Vec::new();
    for (item, action) in incoming.iter().zip(&plan.actions) {
        let mut choice = None;
        let mut outcome_ok = false;
        let (mut m_in, mut m_ex) = (item.modified, item.modified);
        match action {
            Action::Create => match create(store, target, item).await {
                Ok(()) => {
                    report.created += 1;
                    outcome_ok = true;
                    created.push((identity(&item.attributes), item.secret.clone()));
                }
                Err(e) => report.failed.push((item.label.clone(), e.to_string())),
            },
            Action::Duplicate { .. } => report.duplicates += 1,
            Action::Conflict(index) => {
                let (Some(conflict), Some(picked)) =
                    (plan.conflicts.get(*index), choices.get(*index).copied())
                else {
                    return Err(KringError::InvalidInput(
                        "plan references a missing conflict".into(),
                    ));
                };
                choice = Some(picked);
                m_in = conflict.modified_incoming;
                m_ex = conflict.modified_existing;
                match picked {
                    Choice::KeepTarget => report.kept_target += 1,
                    Choice::UseIncoming => {
                        let update = ItemUpdate {
                            label: Some(item.label.clone()),
                            attributes: None,
                            secret: Some(item.secret.clone()),
                        };
                        match store.update_item(&conflict.existing, update).await {
                            Ok(()) => {
                                report.replaced += 1;
                                outcome_ok = true;
                            }
                            Err(e) => report.failed.push((item.label.clone(), e.to_string())),
                        }
                    }
                }
            }
            Action::NoSecret => report.no_secret += 1,
            Action::SkipSameBatch => {
                report.same_batch_skipped += 1;
                let ident = identity(&item.attributes);
                outcome_ok = created
                    .iter()
                    .any(|(a, s)| *a == ident && s.as_bytes() == item.secret.as_bytes());
            }
            Action::ConflictSameBatch => report.same_batch_skipped += 1,
        }
        if mode == TransferMode::Copy {
            continue;
        }
        let TransferSource::Live(source) = &item.source else {
            continue;
        };
        let self_match = matched_existing(action, plan) == Some(source);
        if !source_safe_to_delete(action, choice, outcome_ok, m_in, m_ex, self_match) {
            report.source_kept.push(item.label.clone());
            continue;
        }
        match store.delete_item(source).await {
            Ok(()) => report.source_deleted += 1,
            Err(e) => report
                .failed
                .push((item.label.clone(), format!("source not deleted: {e}"))),
        }
    }
    Ok(report)
}

/// Creates one incoming item in the target without replacing anything.
async fn create<S: SecretStore + ?Sized>(
    store: &S,
    target: &CollectionId,
    item: &Incoming,
) -> Result<()> {
    let new = NewItem {
        label: item.label.clone(),
        attributes: item.attributes.clone(),
        secret: item.secret.clone(),
        replace: false,
    };
    store.create_item(target, new).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_store::FakeStore;
    use crate::model::{CollectionInfo, ItemId, ItemInfo};
    use crate::transfer::plan::{Existing, plan_transfer};

    /// Store wrapper whose `create_item` and `update_item` fail for one label.
    struct FailingStore(FakeStore, &'static str);

    impl FailingStore {
        /// Wraps a fresh fake store.
        fn new(bad_label: &'static str) -> Self {
            Self(FakeStore::new(), bad_label)
        }
    }

    #[async_trait::async_trait]
    impl SecretStore for FailingStore {
        async fn list_collections(&self) -> Result<Vec<CollectionInfo>> {
            self.0.list_collections().await
        }
        async fn list_items(&self, c: &CollectionId) -> Result<Vec<ItemInfo>> {
            self.0.list_items(c).await
        }
        async fn read_secret(&self, i: &ItemId) -> Result<SecretValue> {
            self.0.read_secret(i).await
        }
        async fn create_item(&self, c: &CollectionId, item: NewItem) -> Result<ItemId> {
            if item.label == self.1 {
                return Err(KringError::NotFound("injected failure".into()));
            }
            self.0.create_item(c, item).await
        }
        async fn update_item(&self, i: &ItemId, u: ItemUpdate) -> Result<()> {
            if u.label.as_deref() == Some(self.1) {
                return Err(KringError::NotFound("injected failure".into()));
            }
            self.0.update_item(i, u).await
        }
        async fn delete_item(&self, i: &ItemId) -> Result<()> {
            self.0.delete_item(i).await
        }
        async fn read_alias(&self, a: &str) -> Result<Option<CollectionId>> {
            self.0.read_alias(a).await
        }
        async fn set_alias(&self, a: &str, c: &CollectionId) -> Result<()> {
            self.0.set_alias(a, c).await
        }
        async fn lock(&self, c: &CollectionId) -> Result<()> {
            self.0.lock(c).await
        }
        async fn rename_collection(&self, c: &CollectionId, l: &str) -> Result<()> {
            self.0.rename_collection(c, l).await
        }
        async fn delete_collection(&self, c: &CollectionId) -> Result<()> {
            self.0.delete_collection(c).await
        }
    }

    /// Builds attributes from pairs.
    fn attrs(pairs: &[(&str, &str)]) -> Attributes {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Creates an item in the store and returns its id.
    async fn put(
        store: &FakeStore,
        col: &CollectionId,
        label: &str,
        pairs: &[(&str, &str)],
        secret: &str,
    ) -> ItemId {
        let new = NewItem {
            label: label.into(),
            attributes: attrs(pairs),
            secret: SecretValue::from_text(secret),
            replace: false,
        };
        store.create_item(col, new).await.unwrap()
    }

    /// Reads a live collection as incoming items with the given modified time.
    async fn live_incoming(store: &FakeStore, col: &CollectionId, modified: u64) -> Vec<Incoming> {
        let mut out = Vec::new();
        for info in store.list_items(col).await.unwrap() {
            out.push(Incoming {
                source: TransferSource::Live(info.id.clone()),
                label: info.label,
                attributes: info.attributes,
                secret: store.read_secret(&info.id).await.unwrap(),
                secret_missing: false,
                modified,
            });
        }
        out
    }

    /// Reads a target collection as existing items.
    async fn existing_of(store: &FakeStore, col: &CollectionId) -> Vec<Existing> {
        let mut out = Vec::new();
        for info in store.list_items(col).await.unwrap() {
            out.push(Existing {
                id: info.id.clone(),
                label: info.label,
                attributes: info.attributes,
                secret: store.read_secret(&info.id).await.unwrap(),
                modified: info.modified,
            });
        }
        out
    }

    /// Returns the labels of a collection, sorted.
    async fn labels(store: &FakeStore, col: &CollectionId) -> Vec<String> {
        let mut v: Vec<String> = store
            .list_items(col)
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.label)
            .collect();
        v.sort();
        v
    }

    /// Copy creates items, counts every action kind and keeps sources.
    #[tokio::test]
    async fn copy_creates_and_counts() {
        let store = FakeStore::new();
        let src = store.add_collection("src", "p", false);
        let dst = store.add_collection("dst", "p", false);
        put(&store, &src, "new", &[("a", "1")], "s1").await;
        put(&store, &src, "dup", &[("a", "2")], "s2").await;
        put(&store, &src, "clash", &[("a", "3")], "mine").await;
        put(&store, &dst, "dup", &[("a", "2")], "s2").await;
        put(&store, &dst, "clash", &[("a", "3")], "theirs").await;
        let mut incoming = live_incoming(&store, &src, 1).await;
        let mut nosecret = incoming[0].clone();
        nosecret.secret_missing = true;
        nosecret.attributes = attrs(&[("a", "9")]);
        nosecret.label = "empty".into();
        incoming.push(nosecret);
        let existing = existing_of(&store, &dst).await;
        let plan = plan_transfer(&incoming, &existing);
        let report = apply_transfer(
            &store,
            &dst,
            &incoming,
            &plan,
            &[Choice::KeepTarget],
            TransferMode::Copy,
        )
        .await
        .unwrap();
        assert_eq!(
            (
                report.created,
                report.duplicates,
                report.kept_target,
                report.no_secret
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(report.source_deleted, 0);
        assert!(report.failed.is_empty() && report.source_kept.is_empty());
        assert_eq!(labels(&store, &src).await.len(), 3);
        assert_eq!(labels(&store, &dst).await, ["clash", "dup", "new"]);
    }

    /// Move deletes exactly the sources whose content is in the target.
    #[tokio::test]
    async fn move_deletes_only_safe_sources() {
        let store = FakeStore::new();
        let src = store.add_collection("src", "p", false);
        let dst = store.add_collection("dst", "p", false);
        put(&store, &src, "create", &[("a", "1")], "s1").await;
        put(&store, &src, "dup", &[("a", "2")], "s2").await;
        put(&store, &src, "use", &[("a", "3")], "in3").await;
        put(&store, &src, "keepnew", &[("a", "4")], "in4").await;
        put(&store, &src, "same1", &[("a", "5")], "s5").await;
        put(&store, &src, "same2", &[("a", "5")], "s5").await;
        put(&store, &src, "clash1", &[("a", "6")], "s6").await;
        put(&store, &src, "clash2", &[("a", "6")], "other").await;
        put(&store, &dst, "dup", &[("a", "2")], "s2").await;
        put(&store, &dst, "use", &[("a", "3")], "old3").await;
        put(&store, &dst, "keepnew", &[("a", "4")], "old4").await;
        let mut incoming = live_incoming(&store, &src, 5).await;
        let mut nosecret = incoming[0].clone();
        nosecret.secret_missing = true;
        nosecret.attributes = attrs(&[("a", "9")]);
        nosecret.label = "nosecret".into();
        incoming.push(nosecret);
        let mut existing = existing_of(&store, &dst).await;
        // "use": target older (UseIncoming); "keepnew": target newer.
        for e in &mut existing {
            e.modified = if e.label == "use" { 1 } else { 9 };
        }
        let plan = plan_transfer(&incoming, &existing);
        assert_eq!(plan.conflicts.len(), 2);
        let choices: Vec<Choice> = plan
            .conflicts
            .iter()
            .map(|c| {
                if c.label_incoming == "use" {
                    Choice::UseIncoming
                } else {
                    Choice::KeepTarget
                }
            })
            .collect();
        let report = apply_transfer(&store, &dst, &incoming, &plan, &choices, TransferMode::Move)
            .await
            .unwrap();
        assert_eq!(report.created, 3);
        assert_eq!(report.replaced, 1);
        assert_eq!(report.duplicates, 1);
        assert_eq!(report.same_batch_skipped, 2);
        // create, dup, use, same1 (created), same2 (same batch dup), keepnew
        // (target newer): all deleted. clash1 created and deleted; clash2
        // (ConflictSameBatch) and nosecret kept.
        assert_eq!(report.source_deleted, 7);
        assert_eq!(report.source_kept, ["clash2", "nosecret"]);
        assert!(report.failed.is_empty());
        assert_eq!(labels(&store, &src).await, ["clash2"]);
    }

    /// UseIncoming overwrites label and secret of the existing item.
    #[tokio::test]
    async fn use_incoming_updates_target() {
        let store = FakeStore::new();
        let src = store.add_collection("src", "p", false);
        let dst = store.add_collection("dst", "p", false);
        put(&store, &src, "newlabel", &[("a", "1")], "newsecret").await;
        let old = put(&store, &dst, "oldlabel", &[("a", "1")], "oldsecret").await;
        let incoming = live_incoming(&store, &src, 9).await;
        let plan = plan_transfer(&incoming, &existing_of(&store, &dst).await);
        let report = apply_transfer(
            &store,
            &dst,
            &incoming,
            &plan,
            &[Choice::UseIncoming],
            TransferMode::Copy,
        )
        .await
        .unwrap();
        assert_eq!(report.replaced, 1);
        let items = store.list_items(&dst).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, old);
        assert_eq!(items[0].label, "newlabel");
        assert_eq!(
            store.read_secret(&old).await.unwrap().as_bytes(),
            b"newsecret"
        );
    }

    /// KeepTarget with an older target keeps the source on move.
    #[tokio::test]
    async fn keep_target_older_keeps_source_on_move() {
        let store = FakeStore::new();
        let src = store.add_collection("src", "p", false);
        let dst = store.add_collection("dst", "p", false);
        put(&store, &src, "mine", &[("a", "1")], "new").await;
        put(&store, &dst, "theirs", &[("a", "1")], "old").await;
        let incoming = live_incoming(&store, &src, 100).await;
        let mut existing = existing_of(&store, &dst).await;
        existing[0].modified = 1;
        let plan = plan_transfer(&incoming, &existing);
        let report = apply_transfer(
            &store,
            &dst,
            &incoming,
            &plan,
            &[Choice::KeepTarget],
            TransferMode::Move,
        )
        .await
        .unwrap();
        assert_eq!(report.kept_target, 1);
        assert_eq!(report.source_deleted, 0);
        assert_eq!(report.source_kept, ["mine"]);
        assert_eq!(labels(&store, &src).await, ["mine"]);
    }

    /// A wrong number of choices is refused before any change.
    #[tokio::test]
    async fn choices_length_mismatch_rejected() {
        let store = FakeStore::new();
        let src = store.add_collection("src", "p", false);
        let dst = store.add_collection("dst", "p", false);
        put(&store, &src, "a", &[("a", "1")], "x").await;
        put(&store, &dst, "b", &[("a", "1")], "y").await;
        let incoming = live_incoming(&store, &src, 1).await;
        let plan = plan_transfer(&incoming, &existing_of(&store, &dst).await);
        let err = apply_transfer(&store, &dst, &incoming, &plan, &[], TransferMode::Move)
            .await
            .unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
        assert_eq!(labels(&store, &src).await, ["a"]);
    }

    /// A locked target is refused with `Locked` and nothing changes.
    #[tokio::test]
    async fn locked_target_rejected() {
        let store = FakeStore::new();
        let src = store.add_collection("src", "p", false);
        let dst = store.add_collection("dst", "p", true);
        put(&store, &src, "a", &[("a", "1")], "x").await;
        let incoming = live_incoming(&store, &src, 1).await;
        let plan = plan_transfer(&incoming, &[]);
        let err = apply_transfer(&store, &dst, &incoming, &plan, &[], TransferMode::Move)
            .await
            .unwrap_err();
        assert!(matches!(err, KringError::Locked(_)));
        assert_eq!(labels(&store, &src).await, ["a"]);
    }

    /// A failed create is reported and its source is kept; others go on.
    #[tokio::test]
    async fn failed_create_keeps_source() {
        let store = FailingStore::new("bad");
        let src = store.0.add_collection("src", "p", false);
        let dst = store.0.add_collection("dst", "p", false);
        put(&store.0, &src, "bad", &[("a", "1")], "x").await;
        put(&store.0, &src, "good", &[("a", "2")], "y").await;
        let incoming = live_incoming(&store.0, &src, 1).await;
        let plan = plan_transfer(&incoming, &[]);
        let report = apply_transfer(&store, &dst, &incoming, &plan, &[], TransferMode::Move)
            .await
            .unwrap();
        assert_eq!((report.created, report.source_deleted), (1, 1));
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, "bad");
        assert_eq!(report.source_kept, ["bad"]);
        assert_eq!(labels(&store.0, &src).await, ["bad"]);
        assert_eq!(labels(&store.0, &dst).await, ["good"]);
    }

    /// A move into the collection the sources live in is refused untouched.
    #[tokio::test]
    async fn move_into_same_collection_rejected() {
        let store = FakeStore::new();
        let col = store.add_collection("col", "p", false);
        put(&store, &col, "a", &[("a", "1")], "x").await;
        let incoming = live_incoming(&store, &col, 1).await;
        let plan = plan_transfer(&incoming, &existing_of(&store, &col).await);
        let err = apply_transfer(&store, &col, &incoming, &plan, &[], TransferMode::Move)
            .await
            .unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
        assert_eq!(labels(&store, &col).await, ["a"]);
        // The parent check alone also catches it (no matched existing item).
        let plan = plan_transfer(&incoming, &[]);
        let err = apply_transfer(&store, &col, &incoming, &plan, &[], TransferMode::Move)
            .await
            .unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
        assert_eq!(labels(&store, &col).await, ["a"]);
    }

    /// A duplicate or conflict that is the source itself is never deleted.
    #[test]
    fn self_duplicate_never_deleted() {
        let dup = Action::Duplicate {
            existing: ItemId("/x".into()),
        };
        assert!(source_safe_to_delete(&dup, None, true, 1, 1, false));
        assert!(!source_safe_to_delete(&dup, None, true, 1, 1, true));
        let c = Action::Conflict(0);
        let ku = Some(Choice::UseIncoming);
        assert!(!source_safe_to_delete(&c, ku, true, 1, 1, true));
        assert!(!source_safe_to_delete(
            &c,
            Some(Choice::KeepTarget),
            true,
            1,
            9,
            true
        ));
    }

    /// The parent of an item path is its collection path.
    #[test]
    fn parent_collection_strips_last_segment() {
        let id = ItemId("/org/freedesktop/secrets/collection/login/12".into());
        assert_eq!(
            parent_collection(&id),
            "/org/freedesktop/secrets/collection/login"
        );
        assert_eq!(parent_collection(&ItemId("nosep".into())), "");
    }

    /// A failed UseIncoming update keeps the source and is reported.
    #[tokio::test]
    async fn failed_update_keeps_source() {
        let store = FailingStore::new("bad");
        let src = store.0.add_collection("src", "p", false);
        let dst = store.0.add_collection("dst", "p", false);
        put(&store.0, &src, "bad", &[("a", "1")], "new").await;
        put(&store.0, &dst, "old", &[("a", "1")], "old").await;
        let incoming = live_incoming(&store.0, &src, 9).await;
        let plan = plan_transfer(&incoming, &existing_of(&store.0, &dst).await);
        let report = apply_transfer(
            &store,
            &dst,
            &incoming,
            &plan,
            &[Choice::UseIncoming],
            TransferMode::Move,
        )
        .await
        .unwrap();
        assert_eq!((report.replaced, report.source_deleted), (0, 0));
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.source_kept, ["bad"]);
        assert_eq!(labels(&store.0, &src).await, ["bad"]);
    }

    /// A plan pointing at a missing conflict fails closed.
    #[tokio::test]
    async fn malformed_plan_index_rejected() {
        let store = FakeStore::new();
        let src = store.add_collection("src", "p", false);
        let dst = store.add_collection("dst", "p", false);
        put(&store, &src, "a", &[("a", "1")], "x").await;
        let incoming = live_incoming(&store, &src, 1).await;
        let plan = TransferPlan {
            actions: vec![Action::Conflict(3)],
            conflicts: vec![],
        };
        let err = apply_transfer(&store, &dst, &incoming, &plan, &[], TransferMode::Move)
            .await
            .unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
        assert_eq!(labels(&store, &src).await, ["a"]);
    }

    /// Every branch of the deletion decision.
    #[test]
    fn source_safe_to_delete_branches() {
        let dup = Action::Duplicate {
            existing: ItemId("/x".into()),
        };
        let conflict = Action::Conflict(0);
        let (ki, ku) = (Some(Choice::KeepTarget), Some(Choice::UseIncoming));
        assert!(source_safe_to_delete(
            &Action::Create,
            None,
            true,
            1,
            1,
            false
        ));
        assert!(!source_safe_to_delete(
            &Action::Create,
            None,
            false,
            1,
            1,
            false
        ));
        assert!(source_safe_to_delete(&dup, None, false, 1, 1, false));
        assert!(source_safe_to_delete(
            &Action::SkipSameBatch,
            None,
            true,
            1,
            1,
            false
        ));
        assert!(!source_safe_to_delete(
            &Action::SkipSameBatch,
            None,
            false,
            1,
            1,
            false
        ));
        assert!(source_safe_to_delete(&conflict, ku, true, 1, 9, false));
        assert!(!source_safe_to_delete(&conflict, ku, false, 1, 9, false));
        assert!(source_safe_to_delete(&conflict, ki, false, 5, 5, false));
        assert!(source_safe_to_delete(&conflict, ki, false, 5, 6, false));
        assert!(!source_safe_to_delete(&conflict, ki, true, 6, 5, false));
        assert!(!source_safe_to_delete(&conflict, None, true, 1, 9, false));
        assert!(!source_safe_to_delete(
            &Action::NoSecret,
            None,
            true,
            1,
            9,
            false
        ));
        assert!(!source_safe_to_delete(
            &Action::ConflictSameBatch,
            None,
            true,
            1,
            9,
            false
        ));
    }

    /// A same-batch duplicate whose original failed to create keeps its source.
    #[tokio::test]
    async fn same_batch_dup_of_failed_create_keeps_source() {
        let store = FailingStore::new("first");
        let src = store.0.add_collection("src", "p", false);
        let dst = store.0.add_collection("dst", "p", false);
        put(&store.0, &src, "first", &[("a", "1")], "s").await;
        put(&store.0, &src, "second", &[("a", "1")], "s").await;
        let incoming = live_incoming(&store.0, &src, 1).await;
        let plan = plan_transfer(&incoming, &[]);
        assert_eq!(plan.actions[1], Action::SkipSameBatch);
        let report = apply_transfer(&store, &dst, &incoming, &plan, &[], TransferMode::Move)
            .await
            .unwrap();
        assert_eq!((report.created, report.source_deleted), (0, 0));
        assert_eq!(report.source_kept, ["first", "second"]);
        assert_eq!(labels(&store.0, &src).await, ["first", "second"]);
    }

    /// Offline sources are never deleted and a locked source reports a failure.
    #[tokio::test]
    async fn offline_untouched_and_locked_source_recorded() {
        let store = FakeStore::new();
        let src = store.add_collection("src", "p", false);
        let dst = store.add_collection("dst", "p", false);
        put(&store, &src, "a", &[("a", "1")], "x").await;
        let mut incoming = live_incoming(&store, &src, 1).await;
        incoming.push(Incoming {
            source: TransferSource::Offline(0),
            label: "off".into(),
            attributes: attrs(&[("a", "2")]),
            secret: SecretValue::from_text("y"),
            secret_missing: false,
            modified: 1,
        });
        let plan = plan_transfer(&incoming, &[]);
        store.lock(&src).await.unwrap();
        let report = apply_transfer(&store, &dst, &incoming, &plan, &[], TransferMode::Move)
            .await
            .unwrap();
        assert_eq!(report.created, 2);
        assert_eq!(report.source_deleted, 0);
        assert_eq!(report.failed.len(), 1);
        assert!(report.source_kept.is_empty());
    }
}
