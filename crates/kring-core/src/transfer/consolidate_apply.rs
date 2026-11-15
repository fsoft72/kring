//! Executes a [`ConsolidationPlan`] step by step, stopping on the first error.
//!
//! Order: every move step, then for each move source the deletion of the
//! source collection (only when it is empty now), then the `delete_empty`
//! collections (re-checked empty; a non-empty one fails the run), then the
//! `default` alias. Backups are the caller's job (the worker takes one of the
//! whole keyring set before calling this).
//!
//! Every move step is re-planned against the live target and the live source
//! right before it runs, so the preview's placeholder ids never reach the
//! store and an item created by an earlier step is seen as a real duplicate or
//! conflict. User choices are matched to the re-planned conflicts by incoming
//! index. Source items are left in place (and listed in
//! [`TransferReport::source_kept`]) when they changed since the preview or
//! when they clash with the target in a conflict the user never saw. Source
//! items that disappeared since the preview are ignored.

use crate::error::{KringError, Result};
use crate::model::{Attributes, CollectionId, SecretValue};
use crate::store::SecretStore;
use crate::transfer::apply::{TransferMode, TransferReport, apply_transfer};
use crate::transfer::consolidate::{ConsolidationPlan, MoveStep, protected_reason};
use crate::transfer::plan::{
    Action, Choice, Existing, Incoming, TransferSource, identity, plan_transfer,
};

/// Alias pointed at the target at the end.
const DEFAULT_ALIAS: &str = "default";

/// Result of one consolidation step (labels only, never secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// Items of a source collection moved into the target.
    Moved {
        /// Source collection label.
        source: String,
        /// What the move did.
        report: TransferReport,
    },
    /// A move source was not deleted because items remain in it.
    Kept {
        /// Source collection label.
        source: String,
        /// Items still in the source.
        remaining: usize,
    },
    /// A collection was deleted (label).
    Deleted(String),
    /// The `default` alias now points at the target.
    DefaultSet,
    /// The step that failed; nothing after it ran.
    Failed {
        /// Step description, such as `Move Work`.
        step: String,
        /// Error message.
        error: String,
    },
}

/// Outcome of a consolidation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConsolidationReport {
    /// One entry per step run, in order; a failure is the last entry.
    pub outcomes: Vec<StepOutcome>,
    /// True when every step ran without failure.
    pub completed: bool,
}

/// A failed step: `(step description, error message)`.
type StepError = (String, String);

/// A user choice for one preview conflict.
#[derive(Clone, Copy, Debug)]
struct Pick {
    /// Incoming index of the conflict in the preview.
    incoming: usize,
    /// What the user chose.
    choice: Choice,
    /// True when the preview showed the target side as older than the
    /// incoming side (a KeepTarget then must not delete the source).
    target_older: bool,
}

/// Collects outcomes and reports progress.
struct Runner<'a> {
    /// Outcomes so far.
    outcomes: Vec<StepOutcome>,
    /// Steps done.
    done: usize,
    /// Steps planned.
    total: usize,
    /// Progress callback `(done, total)`.
    progress: &'a mut dyn FnMut(usize, usize),
}

impl Runner<'_> {
    /// Records a finished step and reports progress.
    fn step(&mut self, outcome: StepOutcome) {
        self.outcomes.push(outcome);
        self.done += 1;
        (self.progress)(self.done, self.total);
    }
}

/// Applies `plan`, with `choices[step][conflict]` for each move step's
/// conflicts in preview order.
///
/// # Preconditions
///
/// - Callers MUST back up every collection touched (target and sources)
///   before calling; this function takes no backup.
///
/// Fails with `InvalidInput`, before any change, when the shape of `choices`
/// does not match the plan, when a move source or `delete_empty` entry is
/// the target, the login, session or an alias path, or when a move step has
/// an offline (non-live) incoming item. Step failures do not
/// return `Err`: they end the run with [`StepOutcome::Failed`] and
/// `completed == false`. A move with any failed item counts as failed.
/// `progress` is called with `(0, total)` first and after every step, where
/// `total` = moves + source deletions considered + `delete_empty` + default.
pub async fn apply_consolidation<S: SecretStore + ?Sized>(
    store: &S,
    plan: &ConsolidationPlan,
    choices: &[Vec<Choice>],
    progress: &mut dyn FnMut(usize, usize),
) -> Result<ConsolidationReport> {
    let picked = index_choices(plan, choices)?;
    check_plan(plan)?;
    let total = plan.moves.len() * 2 + plan.delete_empty.len() + usize::from(plan.set_default);
    progress(0, total);
    let mut runner = Runner {
        outcomes: Vec::new(),
        done: 0,
        total,
        progress,
    };
    let completed = match run(store, plan, &picked, &mut runner).await {
        Ok(()) => true,
        Err((step, error)) => {
            runner.outcomes.push(StepOutcome::Failed { step, error });
            false
        }
    };
    Ok(ConsolidationReport {
        outcomes: runner.outcomes,
        completed,
    })
}

/// Pairs each preview conflict choice with its incoming index and the
/// preview's view of which side was newer, per move step.
fn index_choices(plan: &ConsolidationPlan, choices: &[Vec<Choice>]) -> Result<Vec<Vec<Pick>>> {
    if choices.len() != plan.moves.len() {
        return Err(KringError::InvalidInput(format!(
            "expected choices for {} move steps, got {}",
            plan.moves.len(),
            choices.len()
        )));
    }
    plan.moves
        .iter()
        .zip(choices)
        .map(|(step, picks)| {
            if picks.len() != step.plan.conflicts.len() {
                return Err(KringError::InvalidInput(format!(
                    "expected {} conflict choices for {}, got {}",
                    step.plan.conflicts.len(),
                    step.label,
                    picks.len()
                )));
            }
            Ok(step
                .plan
                .conflicts
                .iter()
                .zip(picks)
                .map(|(c, p)| Pick {
                    incoming: c.incoming,
                    choice: *p,
                    target_older: c.modified_existing < c.modified_incoming,
                })
                .collect())
        })
        .collect()
}

/// Refuses a plan that could delete the target or a protected collection,
/// or that moves offline items (consolidation moves live items only).
fn check_plan(plan: &ConsolidationPlan) -> Result<()> {
    let offline = plan.moves.iter().find(|m| {
        m.incoming
            .iter()
            .any(|i| !matches!(i.source, TransferSource::Live(_)))
    });
    if let Some(step) = offline {
        return Err(offline_error(&step.label));
    }
    let sources = plan.moves.iter().map(|m| &m.source);
    let empties = plan.delete_empty.iter().map(|(id, _)| id);
    for id in sources.chain(empties) {
        if id == &plan.target || protected_reason(id).is_some() {
            return Err(KringError::InvalidInput(format!(
                "{} must never be deleted by a consolidation",
                id.0
            )));
        }
    }
    Ok(())
}

/// Builds the error for an offline item found in a consolidation move step.
fn offline_error(label: &str) -> KringError {
    KringError::InvalidInput(format!(
        "move step {label} has an offline item; consolidation moves live items only"
    ))
}

/// Runs every step in order; the first failure ends the run.
async fn run<S: SecretStore + ?Sized>(
    store: &S,
    plan: &ConsolidationPlan,
    picked: &[Vec<Pick>],
    runner: &mut Runner<'_>,
) -> std::result::Result<(), StepError> {
    for (step, picks) in plan.moves.iter().zip(picked) {
        let name = format!("Move {}", step.label);
        let report = move_step(store, &plan.target, step, picks)
            .await
            .map_err(|e| (name.clone(), e.to_string()))?;
        if !report.failed.is_empty() {
            // Show what did move before the failure that ends the run.
            let error = failure_summary(&report);
            runner.outcomes.push(StepOutcome::Moved {
                source: step.label.clone(),
                report,
            });
            return Err((name, error));
        }
        runner.step(StepOutcome::Moved {
            source: step.label.clone(),
            report,
        });
    }
    for step in &plan.moves {
        let outcome = delete_if_empty(store, &step.source, &step.label, false).await?;
        runner.step(outcome);
    }
    for (id, label) in &plan.delete_empty {
        let outcome = delete_if_empty(store, id, label, true).await?;
        runner.step(outcome);
    }
    if plan.set_default {
        store
            .set_alias(DEFAULT_ALIAS, &plan.target)
            .await
            .map_err(|e| ("Set default".to_string(), e.to_string()))?;
        runner.step(StepOutcome::DefaultSet);
    }
    Ok(())
}

/// Summarizes the failed items of a transfer (labels and errors only).
fn failure_summary(report: &TransferReport) -> String {
    let items: Vec<String> = report
        .failed
        .iter()
        .map(|(label, error)| format!("{label}: {error}"))
        .collect();
    format!("{} item(s) failed: {}", items.len(), items.join("; "))
}

/// Deletes a collection when it holds no items right now.
///
/// A non-empty collection is a failure when `must_be_empty` (it was planned
/// as empty), otherwise it is kept and reported as [`StepOutcome::Kept`].
async fn delete_if_empty<S: SecretStore + ?Sized>(
    store: &S,
    id: &CollectionId,
    label: &str,
    must_be_empty: bool,
) -> std::result::Result<StepOutcome, StepError> {
    let name = format!("Delete {label}");
    let remaining = store
        .list_items(id)
        .await
        .map_err(|e| (name.clone(), e.to_string()))?
        .len();
    if remaining > 0 && must_be_empty {
        return Err((
            name,
            format!("not empty at apply time: {remaining} item(s)"),
        ));
    }
    if remaining > 0 {
        return Ok(StepOutcome::Kept {
            source: label.to_string(),
            remaining,
        });
    }
    store
        .delete_collection(id)
        .await
        .map_err(|e| (name, e.to_string()))?;
    Ok(StepOutcome::Deleted(label.to_string()))
}

/// Re-plans one move step against the live source and target, then applies it.
///
/// Left out (their sources stay, labels appended to
/// [`TransferReport::source_kept`]): items changed since the preview, items in
/// a conflict the preview did not show, and items in a conflict resolved as
/// KeepTarget where the preview showed the target as older. The last rule is
/// judged on the preview, not the live target: an item created or updated by
/// an earlier step is stamped with the current time and would always look
/// newer.
async fn move_step<S: SecretStore + ?Sized>(
    store: &S,
    target: &CollectionId,
    step: &MoveStep,
    picks: &[Pick],
) -> Result<TransferReport> {
    let (fresh, mut kept) = fresh_incoming(store, step).await?;
    let existing = live_existing(store, target, &fresh).await?;
    let all: Vec<Incoming> = fresh.iter().map(|(_, item)| item.clone()).collect();
    let first = plan_transfer(&all, &existing);
    let mut reviewed: Vec<(usize, Incoming)> = Vec::new();
    for ((index, item), action) in fresh.into_iter().zip(&first.actions) {
        let keep_source = match (action, pick(picks, index)) {
            (Action::Conflict(_), None) => true,
            (Action::Conflict(_), Some(p)) => p.choice == Choice::KeepTarget && p.target_older,
            _ => false,
        };
        if keep_source {
            kept.push(item.label.clone());
            continue;
        }
        reviewed.push((index, item));
    }
    // Dropping conflict items changes no other action (only creates shape
    // later decisions), so every conflict left has a user choice.
    let incoming: Vec<Incoming> = reviewed.iter().map(|(_, item)| item.clone()).collect();
    let plan = plan_transfer(&incoming, &existing);
    let choices = plan
        .conflicts
        .iter()
        .map(|c| {
            pick(picks, reviewed[c.incoming].0)
                .map(|p| p.choice)
                .ok_or_else(|| {
                    KringError::InvalidInput(format!(
                        "no choice for conflict on {}",
                        c.label_incoming
                    ))
                })
        })
        .collect::<Result<Vec<Choice>>>()?;
    let mut report = apply_transfer(
        store,
        target,
        &incoming,
        &plan,
        &choices,
        TransferMode::Move,
    )
    .await?;
    report.source_kept.extend(kept);
    Ok(report)
}

/// Returns the user choice for the preview conflict of incoming `index`.
fn pick(picks: &[Pick], index: usize) -> Option<Pick> {
    picks.iter().find(|p| p.incoming == index).copied()
}

/// Re-reads the step's live sources: returns the unchanged items with their
/// preview index, and the labels of items whose attributes or secret changed.
/// Items no longer in the source are dropped.
async fn fresh_incoming<S: SecretStore + ?Sized>(
    store: &S,
    step: &MoveStep,
) -> Result<(Vec<(usize, Incoming)>, Vec<String>)> {
    let live = store.list_items(&step.source).await?;
    let mut fresh = Vec::new();
    let mut changed = Vec::new();
    for (index, item) in step.incoming.iter().enumerate() {
        let TransferSource::Live(id) = &item.source else {
            return Err(offline_error(&step.label));
        };
        let Some(info) = live.iter().find(|i| &i.id == id) else {
            continue;
        };
        let secret: SecretValue = store.read_secret(id).await?;
        if info.attributes != item.attributes || secret.as_bytes() != item.secret.as_bytes() {
            changed.push(item.label.clone());
            continue;
        }
        fresh.push((index, item.clone()));
    }
    Ok((fresh, changed))
}

/// Reads the target items sharing an identity with any incoming item.
async fn live_existing<S: SecretStore + ?Sized>(
    store: &S,
    target: &CollectionId,
    incoming: &[(usize, Incoming)],
) -> Result<Vec<Existing>> {
    let wanted: Vec<Attributes> = incoming
        .iter()
        .map(|(_, item)| identity(&item.attributes))
        .collect();
    let mut out = Vec::new();
    for info in store.list_items(target).await? {
        if !wanted.contains(&identity(&info.attributes)) {
            continue;
        }
        let secret = store.read_secret(&info.id).await?;
        out.push(Existing {
            id: info.id,
            label: info.label,
            attributes: info.attributes,
            secret,
            modified: info.modified,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_store::FakeStore;
    use crate::model::{
        CollectionInfo, ItemId, ItemInfo, ItemUpdate, LOGIN_COLLECTION_PATH, NewItem,
    };
    use crate::transfer::consolidate::{CollectionSnapshot, PLANNED_ID_PREFIX, plan_consolidation};

    /// Store wrapper whose `create_item` fails for one label.
    struct FailingStore(FakeStore, &'static str);

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

    /// Creates an item with attribute `k=key` and returns its id.
    async fn put(
        store: &FakeStore,
        col: &CollectionId,
        label: &str,
        key: &str,
        secret: &str,
    ) -> ItemId {
        let mut attributes = Attributes::new();
        attributes.insert("k".into(), key.into());
        let new = NewItem {
            label: label.into(),
            attributes,
            secret: SecretValue::from_text(secret),
            replace: false,
        };
        store.create_item(col, new).await.unwrap()
    }

    /// Reads every collection the way the worker does (locked -> `None`).
    async fn snapshots(store: &FakeStore) -> Vec<CollectionSnapshot> {
        let mut out = Vec::new();
        for info in store.list_collections().await.unwrap() {
            let items = if info.locked {
                None
            } else {
                let mut items = Vec::new();
                for i in store.list_items(&info.id).await.unwrap() {
                    items.push(Existing {
                        secret: store.read_secret(&i.id).await.unwrap(),
                        id: i.id,
                        label: i.label,
                        attributes: i.attributes,
                        modified: i.modified,
                    });
                }
                Some(items)
            };
            out.push(CollectionSnapshot { info, items });
        }
        out
    }

    /// Plans a consolidation of the whole store into `target`.
    async fn plan_for(store: &FakeStore, target: &CollectionId) -> ConsolidationPlan {
        plan_with_modified(store, target, &[]).await
    }

    /// Plans like [`plan_for`], first overriding the snapshot `modified` of
    /// the items with the given labels.
    async fn plan_with_modified(
        store: &FakeStore,
        target: &CollectionId,
        modified: &[(&str, u64)],
    ) -> ConsolidationPlan {
        let default = store.read_alias("default").await.unwrap();
        let mut snaps = snapshots(store).await;
        for item in snaps.iter_mut().flat_map(|s| s.items.iter_mut().flatten()) {
            if let Some((_, m)) = modified.iter().find(|(l, _)| *l == item.label) {
                item.modified = *m;
            }
        }
        plan_consolidation(&snaps, target, default.as_ref()).unwrap()
    }

    /// Default choices of a plan (the preselected side of each conflict).
    fn defaults(plan: &ConsolidationPlan) -> Vec<Vec<Choice>> {
        plan.moves
            .iter()
            .map(|m| m.plan.conflicts.iter().map(|c| c.default_choice).collect())
            .collect()
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

    /// Returns true when the collection still exists.
    async fn exists(store: &FakeStore, col: &CollectionId) -> bool {
        store
            .list_collections()
            .await
            .unwrap()
            .iter()
            .any(|c| &c.id == col)
    }

    /// Adds the login collection (fixed path) to a fake store.
    fn add_login(store: &FakeStore) -> CollectionId {
        let login = store.add_collection("login", "p", false);
        assert_eq!(login.0, LOGIN_COLLECTION_PATH);
        login
    }

    /// Moves, deletes the emptied source and empty orphans, then sets default.
    #[tokio::test]
    async fn applies_in_order_and_sets_default() {
        let store = FakeStore::new();
        let login = add_login(&store);
        let a = store.add_collection("A", "p", false);
        let b = store.add_collection("B", "p", false);
        put(&store, &login, "shared", "s", "same").await;
        put(&store, &a, "shared", "s", "same").await;
        put(&store, &a, "fresh", "f", "new").await;
        store.set_alias("default", &a).await.unwrap();
        let plan = plan_for(&store, &login).await;
        let report = apply_consolidation(&store, &plan, &defaults(&plan), &mut |_, _| {})
            .await
            .unwrap();
        assert!(report.completed);
        let StepOutcome::Moved {
            source,
            report: moved,
        } = &report.outcomes[0]
        else {
            panic!("first outcome is not a move: {:?}", report.outcomes);
        };
        assert_eq!(source, "A");
        assert_eq!(
            (moved.created, moved.duplicates, moved.source_deleted),
            (1, 1, 2)
        );
        assert_eq!(
            report.outcomes[1..],
            [
                StepOutcome::Deleted("A".into()),
                StepOutcome::Deleted("B".into()),
                StepOutcome::DefaultSet
            ]
        );
        assert_eq!(labels(&store, &login).await, ["fresh", "shared"]);
        assert!(!exists(&store, &a).await && !exists(&store, &b).await);
        assert_eq!(store.read_alias("default").await.unwrap(), Some(login));
    }

    /// A failed item stops the run: nothing after it happens.
    #[tokio::test]
    async fn stops_on_first_failure() {
        let store = FailingStore(FakeStore::new(), "bad");
        let login = add_login(&store.0);
        let a = store.0.add_collection("A", "p", false);
        let b = store.0.add_collection("B", "p", false);
        let c = store.0.add_collection("C", "p", false);
        put(&store.0, &a, "bad", "x", "1").await;
        put(&store.0, &a, "fine", "z", "3").await;
        put(&store.0, &b, "good", "y", "2").await;
        let plan = plan_for(&store.0, &login).await;
        let report = apply_consolidation(&store, &plan, &defaults(&plan), &mut |_, _| {})
            .await
            .unwrap();
        assert!(!report.completed);
        assert_eq!(report.outcomes.len(), 2);
        // The partial move is shown before the failure.
        let StepOutcome::Moved {
            source,
            report: moved,
        } = &report.outcomes[0]
        else {
            panic!("expected the partial move: {:?}", report.outcomes);
        };
        assert_eq!(source, "A");
        assert_eq!((moved.created, moved.source_deleted), (1, 1));
        assert_eq!(moved.failed.len(), 1);
        let StepOutcome::Failed { step, error } = &report.outcomes[1] else {
            panic!("expected a failure: {:?}", report.outcomes);
        };
        assert_eq!(step, "Move A");
        assert!(error.contains("bad"), "{error}");
        assert_eq!(labels(&store.0, &a).await, ["bad"]);
        assert_eq!(labels(&store.0, &login).await, ["fine"]);
        assert_eq!(labels(&store.0, &b).await, ["good"]);
        assert!(exists(&store.0, &c).await);
        assert_eq!(store.0.read_alias("default").await.unwrap(), None);
    }

    /// An "empty" collection that gained an item is not deleted and stops the run.
    #[tokio::test]
    async fn non_empty_at_apply_time_not_deleted() {
        let store = FakeStore::new();
        let login = add_login(&store);
        let b = store.add_collection("B", "p", false);
        let plan = plan_for(&store, &login).await;
        assert_eq!(plan.delete_empty.len(), 1);
        put(&store, &b, "late", "l", "v").await;
        let report = apply_consolidation(&store, &plan, &[], &mut |_, _| {})
            .await
            .unwrap();
        assert!(!report.completed);
        assert!(matches!(
            &report.outcomes[..],
            [StepOutcome::Failed { step, .. }] if step == "Delete B"
        ));
        assert_eq!(labels(&store, &b).await, ["late"]);
        assert_eq!(store.read_alias("default").await.unwrap(), None);
    }

    /// Protected collections or the target smuggled into a plan are refused.
    #[tokio::test]
    async fn protected_in_plan_rejected() {
        let store = FakeStore::new();
        let login = add_login(&store);
        let work = store.add_collection("Work", "p", false);
        let session = store.add_collection("session", "p", false);
        let mut plan = plan_for(&store, &work).await;
        plan.delete_empty = vec![(session.clone(), "session".into())];
        let err = apply_consolidation(&store, &plan, &[], &mut |_, _| {})
            .await
            .unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
        plan.delete_empty = vec![(login.clone(), "login".into())];
        assert!(
            apply_consolidation(&store, &plan, &[], &mut |_, _| {})
                .await
                .is_err()
        );
        plan.delete_empty = vec![(work.clone(), "Work".into())];
        assert!(
            apply_consolidation(&store, &plan, &[], &mut |_, _| {})
                .await
                .is_err()
        );
        assert!(exists(&store, &login).await && exists(&store, &session).await);
        assert!(exists(&store, &work).await);
    }

    /// A move source is deleted only when nothing remains in it.
    #[tokio::test]
    async fn source_deleted_only_when_empty_after_move() {
        let store = FakeStore::new();
        let login = add_login(&store);
        let a = store.add_collection("A", "p", false);
        let c = store.add_collection("C", "p", false);
        // Same identity, different secret in one source: the second stays.
        put(&store, &a, "first", "x", "1").await;
        put(&store, &a, "second", "x", "2").await;
        put(&store, &c, "solo", "y", "3").await;
        let plan = plan_for(&store, &login).await;
        let report = apply_consolidation(&store, &plan, &defaults(&plan), &mut |_, _| {})
            .await
            .unwrap();
        assert!(report.completed, "{:?}", report.outcomes);
        assert_eq!(
            report.outcomes[2..],
            [
                StepOutcome::Kept {
                    source: "A".into(),
                    remaining: 1
                },
                StepOutcome::Deleted("C".into()),
                StepOutcome::DefaultSet
            ]
        );
        assert_eq!(labels(&store, &a).await, ["second"]);
        assert_eq!(labels(&store, &login).await, ["first", "solo"]);
    }

    /// Items changed since the preview, or clashing in a conflict nobody saw,
    /// stay in their source.
    #[tokio::test]
    async fn changed_or_unreviewed_items_stay_in_source() {
        let store = FakeStore::new();
        let login = add_login(&store);
        let a = store.add_collection("A", "p", false);
        let changed = put(&store, &a, "changed", "c", "old").await;
        put(&store, &a, "clash", "k", "mine").await;
        put(&store, &a, "plain", "p", "v").await;
        let plan = plan_for(&store, &login).await;
        assert_eq!(plan.conflict_count, 0);
        let update = ItemUpdate {
            secret: Some(SecretValue::from_text("newer")),
            ..ItemUpdate::default()
        };
        store.update_item(&changed, update).await.unwrap();
        put(&store, &login, "theirs", "k", "other").await;
        let report = apply_consolidation(&store, &plan, &defaults(&plan), &mut |_, _| {})
            .await
            .unwrap();
        assert!(report.completed);
        let StepOutcome::Moved { report: moved, .. } = &report.outcomes[0] else {
            panic!("expected a move: {:?}", report.outcomes);
        };
        assert_eq!((moved.created, moved.source_deleted), (1, 1));
        assert_eq!(moved.source_kept, ["changed", "clash"]);
        assert_eq!(labels(&store, &a).await, ["changed", "clash"]);
        assert_eq!(labels(&store, &login).await, ["plain", "theirs"]);
        assert_eq!(
            store.read_secret(&changed).await.unwrap().as_bytes(),
            b"newer"
        );
    }

    /// Steps after the first see what it created: duplicates are dropped and
    /// a conflict choice made against a planned item applies to the real one.
    #[tokio::test]
    async fn later_steps_see_earlier_creates() {
        let store = FakeStore::new();
        let login = add_login(&store);
        let a = store.add_collection("A", "p", false);
        let b = store.add_collection("B", "p", false);
        put(&store, &a, "same-a", "s", "same").await;
        put(&store, &a, "clash-a", "c", "from-a").await;
        put(&store, &b, "same-b", "s", "same").await;
        put(&store, &b, "clash-b", "c", "from-b").await;
        let plan = plan_for(&store, &login).await;
        assert_eq!(plan.moves[1].plan.conflicts.len(), 1);
        let report = apply_consolidation(
            &store,
            &plan,
            &[vec![], vec![Choice::UseIncoming]],
            &mut |_, _| {},
        )
        .await
        .unwrap();
        assert!(report.completed, "{:?}", report.outcomes);
        assert_eq!(labels(&store, &login).await, ["clash-b", "same-a"]);
        let items = store.list_items(&login).await.unwrap();
        let clash = items.iter().find(|i| i.label == "clash-b").unwrap();
        assert_eq!(
            store.read_secret(&clash.id).await.unwrap().as_bytes(),
            b"from-b"
        );
        assert!(!exists(&store, &a).await && !exists(&store, &b).await);
    }

    /// KeepTarget against an item an earlier step creates keeps the source
    /// when the preview showed that item as older.
    #[tokio::test]
    async fn keep_target_older_placeholder_keeps_source() {
        let store = FakeStore::new();
        let login = add_login(&store);
        let a = store.add_collection("A", "p", false);
        let b = store.add_collection("B", "p", false);
        put(&store, &a, "from-a", "c", "old").await;
        put(&store, &b, "from-b", "c", "new").await;
        let plan = plan_with_modified(&store, &login, &[("from-a", 1), ("from-b", 9)]).await;
        let conflict = &plan.moves[1].plan.conflicts[0];
        assert!(conflict.existing.0.starts_with(PLANNED_ID_PREFIX));
        assert_eq!(conflict.default_choice, Choice::UseIncoming);
        let report = apply_consolidation(
            &store,
            &plan,
            &[vec![], vec![Choice::KeepTarget]],
            &mut |_, _| {},
        )
        .await
        .unwrap();
        assert!(report.completed, "{:?}", report.outcomes);
        let StepOutcome::Moved { report: moved, .. } = &report.outcomes[1] else {
            panic!("expected the second move: {:?}", report.outcomes);
        };
        assert_eq!(moved.source_kept, ["from-b"]);
        assert_eq!(
            report.outcomes[2..4],
            [
                StepOutcome::Deleted("A".into()),
                StepOutcome::Kept {
                    source: "B".into(),
                    remaining: 1
                }
            ]
        );
        assert_eq!(labels(&store, &b).await, ["from-b"]);
        assert_eq!(labels(&store, &login).await, ["from-a"]);
    }

    /// KeepTarget against a target item that an earlier UseIncoming updated
    /// keeps the source when the preview showed the target as older.
    #[tokio::test]
    async fn keep_target_after_use_incoming_keeps_source() {
        let store = FakeStore::new();
        let login = add_login(&store);
        let a = store.add_collection("A", "p", false);
        let b = store.add_collection("B", "p", false);
        let target_item = put(&store, &login, "t", "c", "target").await;
        put(&store, &a, "from-a", "c", "middle").await;
        put(&store, &b, "from-b", "c", "newest").await;
        let plan =
            plan_with_modified(&store, &login, &[("t", 1), ("from-a", 5), ("from-b", 9)]).await;
        let report = apply_consolidation(
            &store,
            &plan,
            &[vec![Choice::UseIncoming], vec![Choice::KeepTarget]],
            &mut |_, _| {},
        )
        .await
        .unwrap();
        assert!(report.completed, "{:?}", report.outcomes);
        assert_eq!(
            store.read_secret(&target_item).await.unwrap().as_bytes(),
            b"middle"
        );
        assert!(!exists(&store, &a).await);
        assert_eq!(labels(&store, &b).await, ["from-b"]);
        assert!(report.outcomes.contains(&StepOutcome::Kept {
            source: "B".into(),
            remaining: 1
        }));
    }

    /// A move step with an offline item is refused before any change.
    #[tokio::test]
    async fn offline_item_in_step_rejected() {
        let store = FakeStore::new();
        let login = add_login(&store);
        let a = store.add_collection("A", "p", false);
        put(&store, &a, "x", "x", "1").await;
        let mut plan = plan_for(&store, &login).await;
        plan.moves[0].incoming[0].source = TransferSource::Offline(0);
        let err = apply_consolidation(&store, &plan, &defaults(&plan), &mut |_, _| {})
            .await
            .unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
        assert_eq!(labels(&store, &a).await, ["x"]);
        assert!(labels(&store, &login).await.is_empty());
    }

    /// Progress goes from `(0, total)` to `(total, total)` one step at a time.
    #[tokio::test]
    async fn progress_reported() {
        let store = FakeStore::new();
        let login = add_login(&store);
        let a = store.add_collection("A", "p", false);
        store.add_collection("B", "p", false);
        put(&store, &a, "x", "x", "1").await;
        let plan = plan_for(&store, &login).await;
        let mut calls = Vec::new();
        let report = apply_consolidation(&store, &plan, &defaults(&plan), &mut |d, t| {
            calls.push((d, t))
        })
        .await
        .unwrap();
        assert!(report.completed);
        // 1 move + 1 source deletion + 1 empty + default.
        assert_eq!(calls, [(0, 4), (1, 4), (2, 4), (3, 4), (4, 4)]);
    }

    /// A choices shape that does not match the plan is refused untouched.
    #[tokio::test]
    async fn choices_shape_mismatch_rejected() {
        let store = FakeStore::new();
        let login = add_login(&store);
        let a = store.add_collection("A", "p", false);
        put(&store, &login, "t", "x", "1").await;
        put(&store, &a, "s", "x", "2").await;
        let plan = plan_for(&store, &login).await;
        for bad in [vec![], vec![vec![]], vec![vec![Choice::KeepTarget]; 2]] {
            let err = apply_consolidation(&store, &plan, &bad, &mut |_, _| {})
                .await
                .unwrap_err();
            assert!(matches!(err, KringError::InvalidInput(_)));
        }
        assert_eq!(labels(&store, &a).await, ["s"]);
    }
}
