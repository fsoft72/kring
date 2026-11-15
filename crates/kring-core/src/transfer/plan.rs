//! Source-agnostic transfer planning shared by copy, move and import.
//!
//! The planner is pure: it compares incoming items (live or offline) with the
//! items already in the target and decides, per incoming item, what to do.
//! Identity of an item is its attribute map without `xdg:content-type`.
//!
//! Rules, applied per incoming item in order:
//!
//! 1. No secret (`secret_missing`): [`Action::NoSecret`]. Such items never
//!    match anything and never count as existing for later items.
//! 2. Identity match against `existing`: if any matching existing item has the
//!    same secret bytes the action is [`Action::Duplicate`] (of the first such
//!    item); otherwise it is [`Action::Conflict`] against the first matching
//!    existing item. The conflict default is the side with the newer
//!    `modified`; a tie keeps the target.
//! 3. Identity match against earlier incoming items that were planned as
//!    [`Action::Create`]: any with the same secret gives
//!    [`Action::SkipSameBatch`], otherwise [`Action::ConflictSameBatch`] (the
//!    item is skipped and the first one wins).
//! 4. Otherwise [`Action::Create`].

use oo7::CONTENT_TYPE_ATTRIBUTE;

use crate::model::{Attributes, ItemId, SecretValue};

/// Where an incoming item comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferSource {
    /// An item in a live collection.
    Live(ItemId),
    /// An item of an offline list, by index in that list.
    Offline(usize),
}

/// An item to be transferred into the target.
#[derive(Clone, Debug)]
pub struct Incoming {
    /// Where the item comes from.
    pub source: TransferSource,
    /// Item label.
    pub label: String,
    /// Item attributes.
    pub attributes: Attributes,
    /// Item secret (empty when `secret_missing`).
    pub secret: SecretValue,
    /// True when the source had no secret for this item.
    pub secret_missing: bool,
    /// Last modification time, unix seconds.
    pub modified: u64,
}

/// An item already present in the target, with its secret.
#[derive(Clone, Debug)]
pub struct Existing {
    /// Item id in the target.
    pub id: ItemId,
    /// Item label.
    pub label: String,
    /// Item attributes.
    pub attributes: Attributes,
    /// Item secret.
    pub secret: SecretValue,
    /// Last modification time, unix seconds.
    pub modified: u64,
}

/// Resolution of a conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// Keep the item already in the target.
    KeepTarget,
    /// Overwrite the target item with the incoming one.
    UseIncoming,
}

/// Same identity as an existing item, with a different secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    /// Index in the incoming list.
    pub incoming: usize,
    /// The clashing item in the target.
    pub existing: ItemId,
    /// Label of the incoming item.
    pub label_incoming: String,
    /// Label of the existing item.
    pub label_existing: String,
    /// Modification time of the incoming item.
    pub modified_incoming: u64,
    /// Modification time of the existing item.
    pub modified_existing: u64,
    /// Preselected choice: the newer side, ties keep the target.
    pub default_choice: Choice,
}

/// What to do with one incoming item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Create the item in the target.
    Create,
    /// An identical item exists in the target.
    Duplicate {
        /// The identical item in the target.
        existing: ItemId,
    },
    /// Clashes with a target item; index into [`TransferPlan::conflicts`].
    Conflict(usize),
    /// The source had no secret for the item.
    NoSecret,
    /// Identical to an earlier incoming item that will be created.
    SkipSameBatch,
    /// Same identity, different secret than an earlier incoming item that
    /// will be created (skipped, first wins).
    ConflictSameBatch,
}

/// Counts of planned actions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransferCounts {
    /// Items to create.
    pub create: usize,
    /// Items identical to target items.
    pub duplicate: usize,
    /// Conflicts with target items.
    pub conflict: usize,
    /// Items without a secret.
    pub no_secret: usize,
    /// Items skipped because of an earlier incoming item
    /// (`SkipSameBatch` plus `ConflictSameBatch`).
    pub same_batch: usize,
}

/// The plan: one action per incoming item plus the listed conflicts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransferPlan {
    /// One action per incoming item, in order.
    pub actions: Vec<Action>,
    /// Conflicts with target items, referenced by `Action::Conflict`.
    pub conflicts: Vec<Conflict>,
}

impl TransferPlan {
    /// Counts the planned actions.
    pub fn counts(&self) -> TransferCounts {
        let mut counts = TransferCounts::default();
        for action in &self.actions {
            match action {
                Action::Create => counts.create += 1,
                Action::Duplicate { .. } => counts.duplicate += 1,
                Action::Conflict(_) => counts.conflict += 1,
                Action::NoSecret => counts.no_secret += 1,
                Action::SkipSameBatch | Action::ConflictSameBatch => counts.same_batch += 1,
            }
        }
        counts
    }
}

/// Returns the attributes used for equality, without `xdg:content-type`.
pub fn identity(attrs: &Attributes) -> Attributes {
    let mut out = attrs.clone();
    out.remove(CONTENT_TYPE_ATTRIBUTE);
    out
}

/// Plans a transfer of `incoming` into a target holding `existing` (pure).
///
/// See the module docs for the exact rules.
pub fn plan_transfer(incoming: &[Incoming], existing: &[Existing]) -> TransferPlan {
    let existing_ids: Vec<Attributes> = existing.iter().map(|e| identity(&e.attributes)).collect();
    let mut created: Vec<(Attributes, &[u8])> = Vec::new();
    let mut plan = TransferPlan::default();
    for (index, item) in incoming.iter().enumerate() {
        if item.secret_missing {
            plan.actions.push(Action::NoSecret);
            continue;
        }
        let ident = identity(&item.attributes);
        let matches: Vec<&Existing> = existing
            .iter()
            .zip(&existing_ids)
            .filter(|(_, id)| **id == ident)
            .map(|(e, _)| e)
            .collect();
        if let Some(first) = matches.first() {
            let same = matches
                .iter()
                .find(|e| e.secret.as_bytes() == item.secret.as_bytes());
            if let Some(dup) = same {
                plan.actions.push(Action::Duplicate {
                    existing: dup.id.clone(),
                });
                continue;
            }
            let default_choice = if item.modified > first.modified {
                Choice::UseIncoming
            } else {
                Choice::KeepTarget
            };
            plan.actions.push(Action::Conflict(plan.conflicts.len()));
            plan.conflicts.push(Conflict {
                incoming: index,
                existing: first.id.clone(),
                label_incoming: item.label.clone(),
                label_existing: first.label.clone(),
                modified_incoming: item.modified,
                modified_existing: first.modified,
                default_choice,
            });
            continue;
        }
        let mut batch = created.iter().filter(|(id, _)| *id == ident).peekable();
        if batch.peek().is_some() {
            let same = batch.any(|(_, s)| *s == item.secret.as_bytes());
            plan.actions.push(if same {
                Action::SkipSameBatch
            } else {
                Action::ConflictSameBatch
            });
            continue;
        }
        created.push((ident, item.secret.as_bytes()));
        plan.actions.push(Action::Create);
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds attributes from pairs.
    fn attrs(pairs: &[(&str, &str)]) -> Attributes {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Builds an incoming offline item.
    fn inc(index: usize, pairs: &[(&str, &str)], secret: &str, modified: u64) -> Incoming {
        Incoming {
            source: TransferSource::Offline(index),
            label: format!("in{index}"),
            attributes: attrs(pairs),
            secret: SecretValue::from_text(secret),
            secret_missing: false,
            modified,
        }
    }

    /// Builds an existing item.
    fn ex(id: &str, pairs: &[(&str, &str)], secret: &str, modified: u64) -> Existing {
        Existing {
            id: ItemId(id.into()),
            label: format!("ex{id}"),
            attributes: attrs(pairs),
            secret: SecretValue::from_text(secret),
            modified,
        }
    }

    /// Duplicates and conflicts against existing items are detected.
    #[test]
    fn duplicate_and_conflict_detected() {
        let existing = [
            ex("/1", &[("a", "1")], "s1", 5),
            ex("/2", &[("a", "2")], "s2", 5),
        ];
        let incoming = [
            inc(0, &[("a", "1")], "s1", 9),
            inc(1, &[("a", "2")], "other", 9),
            inc(2, &[("a", "3")], "s3", 9),
        ];
        let plan = plan_transfer(&incoming, &existing);
        assert_eq!(
            plan.actions,
            [
                Action::Duplicate {
                    existing: ItemId("/1".into())
                },
                Action::Conflict(0),
                Action::Create
            ]
        );
        assert_eq!(plan.conflicts.len(), 1);
        let c = &plan.conflicts[0];
        assert_eq!(c.incoming, 1);
        assert_eq!(c.existing, ItemId("/2".into()));
        assert_eq!(c.label_incoming, "in1");
        assert_eq!(c.label_existing, "ex/2");
        assert_eq!((c.modified_incoming, c.modified_existing), (9, 5));
        assert_eq!(
            plan.counts(),
            TransferCounts {
                create: 1,
                duplicate: 1,
                conflict: 1,
                no_secret: 0,
                same_batch: 0
            }
        );
    }

    /// The newer side is preselected; ties keep the target.
    #[test]
    fn newest_preselected_tie_keeps_target() {
        let existing = [ex("/1", &[("a", "1")], "old", 5)];
        let choice = |modified| {
            let plan = plan_transfer(&[inc(0, &[("a", "1")], "new", modified)], &existing);
            plan.conflicts[0].default_choice
        };
        assert_eq!(choice(6), Choice::UseIncoming);
        assert_eq!(choice(5), Choice::KeepTarget);
        assert_eq!(choice(4), Choice::KeepTarget);
    }

    /// Items without a secret neither match nor shadow others.
    #[test]
    fn no_secret_never_matches() {
        let existing = [ex("/1", &[("a", "1")], "s1", 5)];
        let mut empty_a = inc(0, &[("a", "2")], "", 1);
        empty_a.secret_missing = true;
        let mut empty_b = inc(2, &[("a", "1")], "", 1);
        empty_b.secret_missing = true;
        let incoming = [empty_a, inc(1, &[("a", "2")], "s2", 1), empty_b];
        let plan = plan_transfer(&incoming, &existing);
        assert_eq!(
            plan.actions,
            [Action::NoSecret, Action::Create, Action::NoSecret]
        );
        assert!(plan.conflicts.is_empty());
        assert_eq!(plan.counts().no_secret, 2);
    }

    /// The first of clashing incoming items wins.
    #[test]
    fn same_batch_duplicates_and_conflicts() {
        let incoming = [
            inc(0, &[("a", "1")], "s", 1),
            inc(1, &[("a", "1")], "s", 1),
            inc(2, &[("a", "1")], "other", 1),
        ];
        let plan = plan_transfer(&incoming, &[]);
        assert_eq!(
            plan.actions,
            [
                Action::Create,
                Action::SkipSameBatch,
                Action::ConflictSameBatch
            ]
        );
        assert!(plan.conflicts.is_empty());
        let counts = plan.counts();
        assert_eq!((counts.create, counts.same_batch), (1, 2));
    }

    /// `xdg:content-type` is ignored on both sides.
    #[test]
    fn content_type_ignored() {
        let a = attrs(&[("a", "1"), (CONTENT_TYPE_ATTRIBUTE, "text/plain")]);
        assert_eq!(identity(&a), attrs(&[("a", "1")]));
        let existing = [ex(
            "/1",
            &[("a", "1"), (CONTENT_TYPE_ATTRIBUTE, "text/plain")],
            "s",
            1,
        )];
        let plan = plan_transfer(&[inc(0, &[("a", "1")], "s", 1)], &existing);
        assert_eq!(plan.counts().duplicate, 1);
        let plan = plan_transfer(
            &[inc(
                0,
                &[("a", "1"), (CONTENT_TYPE_ATTRIBUTE, "x/y")],
                "t",
                1,
            )],
            &existing,
        );
        assert_eq!(plan.counts().conflict, 1);
    }

    /// Several existing items sharing an identity: any same secret is a
    /// duplicate, none is a conflict against the first.
    #[test]
    fn several_existing_with_same_identity() {
        let existing = [
            ex("/1", &[("a", "1")], "first", 5),
            ex("/2", &[("a", "1")], "second", 6),
        ];
        let plan = plan_transfer(&[inc(0, &[("a", "1")], "second", 9)], &existing);
        assert_eq!(
            plan.actions,
            [Action::Duplicate {
                existing: ItemId("/2".into())
            }]
        );
        let plan = plan_transfer(&[inc(0, &[("a", "1")], "third", 9)], &existing);
        assert_eq!(plan.actions, [Action::Conflict(0)]);
        assert_eq!(plan.conflicts[0].existing, ItemId("/1".into()));
        assert_eq!(plan.conflicts[0].modified_existing, 5);
    }
}
