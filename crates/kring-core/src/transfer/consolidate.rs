//! Consolidation planning: merge every readable orphan collection into one
//! target collection (pure).
//!
//! Rules, per snapshot in input order:
//!
//! - Ids containing `/aliases/` are alias paths, not collections: skipped as
//!   [`SkipReason::Protected`]`("alias")`.
//! - The target: skipped as [`SkipReason::Target`].
//! - The login collection ([`LOGIN_COLLECTION_PATH`]) and any id ending in
//!   `/collection/session`: skipped as [`SkipReason::Protected`].
//! - Locked or unreadable (`items: None`, or `info.locked`): skipped as
//!   [`SkipReason::Locked`]; never touched.
//! - Readable and empty: listed in [`ConsolidationPlan::delete_empty`].
//! - Readable and non-empty: a [`MoveStep`] planned with [`plan_transfer`]
//!   against the target's items plus every item planned as
//!   [`Action::Create`] by earlier move steps, so the same item in two
//!   orphans is created only once. Those earlier planned items carry a
//!   placeholder id built by [`planned_id`] (prefix [`PLANNED_ID_PREFIX`]),
//!   which never equals a real item path; a conflict may reference one.
//!
//! The executor re-plans every step against the live target, so the
//! placeholders never reach the store.

use crate::error::{KringError, Result};
use crate::model::{CollectionId, CollectionInfo, ItemId, LOGIN_COLLECTION_PATH};
use crate::transfer::plan::{
    Action, Existing, Incoming, TransferPlan, TransferSource, plan_transfer,
};

/// Prefix of placeholder ids standing for items planned by earlier steps.
pub const PLANNED_ID_PREFIX: &str = "planned:";

/// Path suffix of the session collection.
const SESSION_SUFFIX: &str = "/collection/session";

/// Path fragment of alias object paths.
const ALIAS_FRAGMENT: &str = "/aliases/";

/// A collection as read for planning.
#[derive(Clone, Debug)]
pub struct CollectionSnapshot {
    /// Collection summary.
    pub info: CollectionInfo,
    /// Items with secrets; `None` when locked or unreadable.
    pub items: Option<Vec<Existing>>,
}

/// Why a collection is left out of the consolidation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// Locked or unreadable: unlock it first to include it.
    Locked,
    /// Never consolidated (`"login"`, `"session"` or `"alias"`).
    Protected(&'static str),
    /// The consolidation target itself.
    Target,
}

/// Moving every item of one orphan collection into the target.
#[derive(Clone, Debug)]
pub struct MoveStep {
    /// The orphan collection.
    pub source: CollectionId,
    /// Its label.
    pub label: String,
    /// Its items as incoming items (`TransferSource::Live`).
    pub incoming: Vec<Incoming>,
    /// The transfer plan against the target (and earlier steps).
    pub plan: TransferPlan,
}

/// The whole consolidation, ready for preview and apply.
#[derive(Clone, Debug)]
pub struct ConsolidationPlan {
    /// Collection receiving every item.
    pub target: CollectionId,
    /// Move steps, applied in order.
    pub moves: Vec<MoveStep>,
    /// Empty collections to delete, `(id, label)`.
    pub delete_empty: Vec<(CollectionId, String)>,
    /// Collections left alone, `(id, label, reason)`.
    pub skipped: Vec<(CollectionId, String, SkipReason)>,
    /// True when the `default` alias must be pointed at the target.
    pub set_default: bool,
    /// Total conflicts over all move steps.
    pub conflict_count: usize,
}

/// Builds the placeholder id of incoming item `index` of move step `step`.
pub fn planned_id(step: usize, index: usize) -> ItemId {
    ItemId(format!("{PLANNED_ID_PREFIX}{step}:{index}"))
}

/// Returns the protection reason of a collection id, if it is never to be
/// consolidated or deleted (login, session, alias paths).
pub fn protected_reason(id: &CollectionId) -> Option<&'static str> {
    if id.0.contains(ALIAS_FRAGMENT) {
        return Some("alias");
    }
    if id.0 == LOGIN_COLLECTION_PATH {
        return Some("login");
    }
    if id.0.ends_with(SESSION_SUFFIX) {
        return Some("session");
    }
    None
}

/// Plans the consolidation of `snapshots` into `target` (pure).
///
/// Fails with `InvalidInput` when the target is missing from the snapshots
/// or is not readable. See the module docs for the rules.
pub fn plan_consolidation(
    snapshots: &[CollectionSnapshot],
    target: &CollectionId,
    current_default: Option<&CollectionId>,
) -> Result<ConsolidationPlan> {
    let target_snapshot = snapshots
        .iter()
        .find(|s| &s.info.id == target)
        .ok_or_else(|| KringError::InvalidInput(format!("target {} not found", target.0)))?;
    let target_items = target_snapshot
        .items
        .as_ref()
        .filter(|_| !target_snapshot.info.locked)
        .ok_or_else(|| KringError::InvalidInput(format!("target {} is locked", target.0)))?;
    let mut plan = ConsolidationPlan {
        target: target.clone(),
        moves: Vec::new(),
        delete_empty: Vec::new(),
        skipped: Vec::new(),
        set_default: current_default != Some(target),
        conflict_count: 0,
    };
    // Target items plus items planned for creation by earlier steps.
    let mut existing: Vec<Existing> = target_items.clone();
    for snapshot in snapshots {
        let id = &snapshot.info.id;
        let label = snapshot.info.label.clone();
        let reason = if id == target {
            Some(SkipReason::Target)
        } else if let Some(why) = protected_reason(id) {
            Some(SkipReason::Protected(why))
        } else if snapshot.info.locked || snapshot.items.is_none() {
            Some(SkipReason::Locked)
        } else {
            None
        };
        if let Some(reason) = reason {
            plan.skipped.push((id.clone(), label, reason));
            continue;
        }
        let items = snapshot.items.as_deref().unwrap_or_default();
        if items.is_empty() {
            plan.delete_empty.push((id.clone(), label));
            continue;
        }
        let step = plan.moves.len();
        let incoming: Vec<Incoming> = items.iter().map(as_incoming).collect();
        let transfer = plan_transfer(&incoming, &existing);
        for (index, (item, action)) in incoming.iter().zip(&transfer.actions).enumerate() {
            if *action == Action::Create {
                existing.push(as_planned(step, index, item));
            }
        }
        plan.conflict_count += transfer.conflicts.len();
        plan.moves.push(MoveStep {
            source: id.clone(),
            label,
            incoming,
            plan: transfer,
        });
    }
    Ok(plan)
}

/// Turns an item of an orphan collection into a live incoming item.
pub(crate) fn as_incoming(item: &Existing) -> Incoming {
    Incoming {
        source: TransferSource::Live(item.id.clone()),
        label: item.label.clone(),
        attributes: item.attributes.clone(),
        secret: item.secret.clone(),
        secret_missing: false,
        modified: item.modified,
    }
}

/// Turns an incoming item planned for creation into a placeholder existing item.
fn as_planned(step: usize, index: usize, item: &Incoming) -> Existing {
    Existing {
        id: planned_id(step, index),
        label: item.label.clone(),
        attributes: item.attributes.clone(),
        secret: item.secret.clone(),
        modified: item.modified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attributes, SecretValue};

    /// Builds a collection summary for a path under the collection prefix.
    fn info(name: &str, locked: bool) -> CollectionInfo {
        CollectionInfo {
            id: cid(name),
            label: name.to_string(),
            locked,
            item_count: 0,
            aliases: Vec::new(),
            is_login: name == "login",
            created: 1,
            modified: 1,
        }
    }

    /// Builds a collection id from its last path segment.
    fn cid(name: &str) -> CollectionId {
        CollectionId(format!("/org/freedesktop/secrets/collection/{name}"))
    }

    /// Builds an existing item in collection `col` with one attribute.
    fn item(col: &str, n: usize, key: &str, secret: &str) -> Existing {
        let mut attributes = Attributes::new();
        attributes.insert("k".into(), key.into());
        Existing {
            id: ItemId(format!("{}/{n}", cid(col).0)),
            label: format!("{col}-{key}"),
            attributes,
            secret: SecretValue::from_text(secret),
            modified: 5,
        }
    }

    /// Builds a readable snapshot.
    fn snap(name: &str, items: Vec<Existing>) -> CollectionSnapshot {
        CollectionSnapshot {
            info: info(name, false),
            items: Some(items),
        }
    }

    /// Builds a locked snapshot.
    fn locked(name: &str) -> CollectionSnapshot {
        CollectionSnapshot {
            info: info(name, true),
            items: None,
        }
    }

    /// Empty orphans are deleted; target, login and session never are.
    #[test]
    fn empty_orphans_deleted_protected_never() {
        let snapshots = [
            snap("Main", vec![]),
            snap("login", vec![]),
            snap("session", vec![]),
            snap("Default_1", vec![]),
            snap("Default_2", vec![item("Default_2", 1, "a", "s")]),
        ];
        let plan = plan_consolidation(&snapshots, &cid("Main"), None).unwrap();
        assert_eq!(plan.delete_empty, [(cid("Default_1"), "Default_1".into())]);
        assert_eq!(plan.moves.len(), 1);
        assert_eq!(plan.moves[0].source, cid("Default_2"));
        assert_eq!(
            plan.skipped,
            [
                (cid("Main"), "Main".into(), SkipReason::Target),
                (cid("login"), "login".into(), SkipReason::Protected("login")),
                (
                    cid("session"),
                    "session".into(),
                    SkipReason::Protected("session")
                ),
            ]
        );
        // Login as target: the other protected one is still skipped.
        let snapshots = [snap("login", vec![]), snap("session", vec![])];
        let plan = plan_consolidation(&snapshots, &cid("login"), None).unwrap();
        assert!(plan.delete_empty.is_empty() && plan.moves.is_empty());
        assert_eq!(plan.skipped.len(), 2);
        // Alias paths are never planned.
        let mut alias = snap("x", vec![]);
        alias.info.id = CollectionId("/org/freedesktop/secrets/aliases/default".into());
        let plan =
            plan_consolidation(&[snap("login", vec![]), alias], &cid("login"), None).unwrap();
        assert!(plan.delete_empty.is_empty());
        assert_eq!(plan.skipped[1].2, SkipReason::Protected("alias"));
    }

    /// Locked collections are skipped, never moved or deleted.
    #[test]
    fn locked_skipped() {
        let mut half = snap("Half", vec![]);
        half.info.locked = true;
        let snapshots = [snap("login", vec![]), locked("Work"), half];
        let plan = plan_consolidation(&snapshots, &cid("login"), None).unwrap();
        assert!(plan.moves.is_empty() && plan.delete_empty.is_empty());
        assert_eq!(
            plan.skipped[1..],
            [
                (cid("Work"), "Work".into(), SkipReason::Locked),
                (cid("Half"), "Half".into(), SkipReason::Locked),
            ]
        );
    }

    /// The same item in two orphans is created once.
    #[test]
    fn cross_orphan_dedupe() {
        let snapshots = [
            snap("login", vec![item("login", 1, "t", "target")]),
            snap(
                "A",
                vec![item("A", 1, "x", "same"), item("A", 2, "y", "one")],
            ),
            snap(
                "B",
                vec![item("B", 1, "x", "same"), item("B", 2, "y", "two")],
            ),
        ];
        let plan = plan_consolidation(&snapshots, &cid("login"), None).unwrap();
        assert_eq!(plan.moves.len(), 2);
        assert_eq!(plan.moves[0].plan.actions, [Action::Create, Action::Create]);
        assert_eq!(
            plan.moves[0].incoming[0].source,
            TransferSource::Live(ItemId(format!("{}/1", cid("A").0)))
        );
        let second = &plan.moves[1].plan;
        assert_eq!(
            second.actions,
            [
                Action::Duplicate {
                    existing: planned_id(0, 0)
                },
                Action::Conflict(0)
            ]
        );
        assert_eq!(second.conflicts[0].existing, planned_id(0, 1));
        assert!(planned_id(0, 1).0.starts_with(PLANNED_ID_PREFIX));
        assert_eq!(plan.conflict_count, 1);
    }

    /// Conflicts with the target are counted over every step.
    #[test]
    fn conflicts_counted() {
        let snapshots = [
            snap(
                "login",
                vec![item("login", 1, "a", "t1"), item("login", 2, "b", "t2")],
            ),
            snap("A", vec![item("A", 1, "a", "x"), item("A", 2, "c", "new")]),
            snap("B", vec![item("B", 1, "b", "y"), item("B", 2, "a", "t1")]),
        ];
        let plan = plan_consolidation(&snapshots, &cid("login"), None).unwrap();
        assert_eq!(plan.moves[0].plan.conflicts.len(), 1);
        assert_eq!(plan.moves[1].plan.conflicts.len(), 1);
        assert_eq!(plan.conflict_count, 2);
        assert_eq!(plan.moves[1].plan.counts().duplicate, 1);
    }

    /// A missing or unreadable target is invalid input.
    #[test]
    fn target_must_be_readable() {
        let err = plan_consolidation(&[snap("A", vec![])], &cid("login"), None).unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
        let err = plan_consolidation(&[locked("login")], &cid("login"), None).unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
        // Items present but the collection reports locked: same as for orphans.
        let mut half = snap("login", vec![]);
        half.info.locked = true;
        let err = plan_consolidation(&[half], &cid("login"), None).unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
    }

    /// The default alias is set unless it already points at the target.
    #[test]
    fn default_alias_flag() {
        let snapshots = [snap("login", vec![]), snap("A", vec![])];
        let target = cid("login");
        let plan = plan_consolidation(&snapshots, &target, Some(&target)).unwrap();
        assert!(!plan.set_default);
        let plan = plan_consolidation(&snapshots, &target, Some(&cid("A"))).unwrap();
        assert!(plan.set_default);
        let plan = plan_consolidation(&snapshots, &target, None).unwrap();
        assert!(plan.set_default);
    }
}
