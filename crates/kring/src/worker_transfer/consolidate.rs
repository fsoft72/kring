//! Consolidation handlers: snapshots, preview, apply with progress and the
//! batch retire of empty plaintext orphan files.

use std::io::Read;

use kring_core::backup::{KEYRING_MAGIC, is_plaintext_keyring, keyring_backup_set};
use kring_core::keyring_file::{
    KeyringFileInfo, KeyringFormat, RetireBatchReport, RetireMode, retire_files_batch, retire_mode,
    scan_dir,
};
use kring_core::model::{CollectionId, CollectionInfo, SecretValue};
use kring_core::transfer::consolidate::{
    CollectionSnapshot, ConsolidationPlan, SkipReason, plan_consolidation, protected_reason,
};
use kring_core::transfer::consolidate_apply::apply_consolidation;
use kring_core::transfer::plan::{Choice, Existing};
use kring_core::{KringError, Result, SecretStore};

use super::{
    ConsolidationSummary, Ctx, DEFAULT_ALIAS, Origin, PendingPlan, PlanState, REASON_CONSOLIDATE,
    StepSummary, conflict_view, existing_of, invalid,
};
use crate::worker::{
    BackupStep, CHANGE_WORDING, Event, WorkerConfig, backup_collections, load_items, refresh,
};
use crate::worker_offline::emit_backup;

/// Extension of keyring files.
const KEYRING_EXTENSION: &str = "keyring";

/// Reads every collection for planning a consolidation.
///
/// Locked collections, and protected ones that are not the target (login,
/// session, aliases: never consolidated), are not read and become
/// `items: None`; a collection that reports `Locked` while read does too.
async fn snapshots<S: SecretStore>(
    store: &S,
    collections: &[CollectionInfo],
    target: &CollectionId,
) -> Result<Vec<CollectionSnapshot>> {
    let mut out = Vec::with_capacity(collections.len());
    for info in collections {
        let skip = info.locked || (&info.id != target && protected_reason(&info.id).is_some());
        let items = if skip {
            None
        } else {
            match read_items(store, &info.id).await {
                Ok(items) => Some(items),
                Err(KringError::Locked(_)) => None,
                Err(e) => return Err(e),
            }
        };
        out.push(CollectionSnapshot {
            info: info.clone(),
            items,
        });
    }
    Ok(out)
}

/// Reads all items of a collection with their secrets.
async fn read_items<S: SecretStore>(store: &S, id: &CollectionId) -> Result<Vec<Existing>> {
    let mut out = Vec::new();
    for info in store.list_items(id).await? {
        out.push(existing_of(store, info).await?);
    }
    Ok(out)
}

/// Returns the empty plaintext orphan files of the keyrings dir (fresh scan).
///
/// Candidates are textual, plaintext, have zero items and are not served by
/// the daemon (`retire_mode` is `DeleteFile`); de-duplicated by path.
fn orphan_candidates(
    config: &WorkerConfig,
    live: &[CollectionInfo],
) -> Result<Vec<KeyringFileInfo>> {
    let mut out: Vec<KeyringFileInfo> = Vec::new();
    for info in scan_dir(&config.keyrings_dir)? {
        let empty_plaintext =
            info.format == KeyringFormat::Textual && info.plaintext && info.item_count == Some(0);
        if !empty_plaintext || retire_mode(&info, live) != RetireMode::DeleteFile {
            continue;
        }
        if out.iter().any(|f| f.path == info.path) {
            continue;
        }
        out.push(info);
    }
    Ok(out)
}

/// Plans a consolidation into `target` and emits its preview.
pub(super) async fn plan_consolidate<S, N>(
    ctx: &Ctx<'_, S, N>,
    plans: &mut PlanState,
    target: &CollectionId,
    include_orphan_files: bool,
) -> Result<()>
where
    S: SecretStore,
    N: Fn(),
{
    if !ctx.allow_writes() {
        return Ok(());
    }
    let collections = ctx.store.list_collections().await?;
    let snapshots = snapshots(ctx.store, &collections, target).await?;
    let current_default = ctx.store.read_alias(DEFAULT_ALIAS).await?;
    let plan = plan_consolidation(&snapshots, target, current_default.as_ref())?;
    let orphan_files: Vec<String> = if include_orphan_files {
        orphan_candidates(ctx.config, &collections)?
            .into_iter()
            .map(|f| f.name)
            .collect()
    } else {
        Vec::new()
    };
    let summary = summarize(&plan, orphan_files.clone());
    let plan_id = plans.put(PendingPlan::Consolidation { plan, orphan_files });
    ctx.out
        .emit(Event::ConsolidationPreview { plan_id, summary });
    Ok(())
}

/// Builds the secret-free preview of a consolidation plan.
fn summarize(plan: &ConsolidationPlan, orphan_files: Vec<String>) -> ConsolidationSummary {
    let steps = plan
        .moves
        .iter()
        .map(|step| StepSummary {
            source: step.source.clone(),
            label: step.label.clone(),
            counts: step.plan.counts(),
            conflicts: step
                .plan
                .conflicts
                .iter()
                .map(|c| conflict_view(c, &step.incoming, Origin::Live))
                .collect(),
        })
        .collect();
    let locked_count = plan
        .skipped
        .iter()
        .filter(|(_, _, reason)| *reason == SkipReason::Locked)
        .count();
    ConsolidationSummary {
        target: plan.target.clone(),
        steps,
        delete_empty: plan.delete_empty.clone(),
        skipped: plan.skipped.clone(),
        locked_count,
        set_default: plan.set_default,
        conflict_count: plan.conflict_count,
        orphan_files,
    }
}

/// Passphrases carried by an apply-consolidation command.
#[derive(Clone, Copy)]
pub(super) struct Passphrases<'a> {
    /// For the backup of the keyring set.
    pub(super) backup: Option<&'a SecretValue>,
    /// For the encrypted backup of the retired orphan files.
    pub(super) orphan_files: Option<&'a SecretValue>,
}

/// Applies a consolidation plan; returns true when it waits for passphrases
/// (reported as [`Event::ApplyPassphrasesNeeded`] for `plan_id`, never by
/// echoing the command).
///
/// Order: write gate, choices shape, orphan file candidates (fresh scan,
/// limited to the previewed names; their passphrase is required when any
/// remain), ONE backup covering the target, every move source and every
/// empty collection to delete (fail closed), the core apply with progress
/// events, then (only when every step completed) the batch retire of the
/// orphan files.
pub(super) async fn apply_consolidate<S, N>(
    ctx: &Ctx<'_, S, N>,
    plan: &ConsolidationPlan,
    orphan_files: &[String],
    choices: &[Vec<Choice>],
    passes: Passphrases<'_>,
    plan_id: u64,
) -> Result<bool>
where
    S: SecretStore,
    N: Fn(),
{
    if !ctx.allow_writes() {
        return Ok(false);
    }
    let shape_ok = choices.len() == plan.moves.len()
        && plan
            .moves
            .iter()
            .zip(choices)
            .all(|(step, picks)| picks.len() == step.plan.conflicts.len());
    if !shape_ok {
        return Err(invalid("Choices do not match the consolidation plan"));
    }
    let candidates: Vec<KeyringFileInfo> = if orphan_files.is_empty() {
        Vec::new()
    } else {
        let live = ctx.store.list_collections().await?;
        orphan_candidates(ctx.config, &live)?
            .into_iter()
            .filter(|f| orphan_files.contains(&f.name))
            .collect()
    };
    if !candidates.is_empty() && passes.orphan_files.is_none() {
        let backup = passes.backup.is_none() && backup_needs_passphrase(ctx.config);
        ctx.out.emit(Event::ApplyPassphrasesNeeded {
            plan_id,
            backup,
            orphan_files: true,
        });
        return Ok(true);
    }
    let mut names = vec![plan.target.clone()];
    names.extend(plan.moves.iter().map(|m| m.source.clone()));
    names.extend(plan.delete_empty.iter().map(|(id, _)| id.clone()));
    let step = backup_collections(
        ctx.out,
        ctx.config,
        &names,
        REASON_CONSOLIDATE,
        passes.backup,
        None,
        &CHANGE_WORDING,
    );
    match step {
        BackupStep::Proceed(_) => {}
        BackupStep::AwaitingPassphrase => {
            ctx.out.emit(Event::ApplyPassphrasesNeeded {
                plan_id,
                backup: true,
                orphan_files: false,
            });
            return Ok(true);
        }
        BackupStep::Stop => return Ok(false),
    }
    let mut progress = |done: usize, total: usize| {
        ctx.out.emit(Event::ConsolidationProgress { done, total });
    };
    let report = apply_consolidation(ctx.store, plan, choices, &mut progress).await?;
    let retired = match (report.completed, passes.orphan_files) {
        (true, Some(pass)) if !candidates.is_empty() => {
            retire_orphans(ctx, &candidates, pass).await
        }
        _ => None,
    };
    let retire_ran = retired.is_some();
    ctx.out.emit(Event::ConsolidationDone(report, retired));
    refresh(ctx.out, ctx.store).await;
    load_items(ctx.out, ctx.store, &plan.target).await;
    if retire_ran {
        match scan_dir(&ctx.config.keyrings_dir) {
            Ok(files) => ctx.out.emit(Event::Files(files)),
            Err(e) => ctx.out.error(e.to_string()),
        }
    }
    Ok(false)
}

/// Returns true when the keyring backup set holds a plaintext keyring, so a
/// backup needs a passphrase. Reads only the magic of each file; an
/// unreadable set or file counts as needing one (the backup reports the error).
fn backup_needs_passphrase(config: &WorkerConfig) -> bool {
    let Ok(files) = keyring_backup_set(&config.keyrings_dir) else {
        return true;
    };
    files
        .iter()
        .filter(|path| path.extension().is_some_and(|e| e == KEYRING_EXTENSION))
        .any(|path| {
            let mut head = [0u8; KEYRING_MAGIC.len()];
            let read = std::fs::File::open(path).and_then(|mut f| f.read(&mut head));
            match read {
                Ok(n) => is_plaintext_keyring(&head[..n]),
                Err(_) => true,
            }
        })
}

/// Retires the orphan files in one encrypted backup; reports a failure as an error.
async fn retire_orphans<S, N>(
    ctx: &Ctx<'_, S, N>,
    candidates: &[KeyringFileInfo],
    passphrase: &SecretValue,
) -> Option<RetireBatchReport>
where
    S: SecretStore,
    N: Fn(),
{
    let live = match ctx.store.list_collections().await {
        Ok(live) => live,
        Err(e) => {
            ctx.out.error(format!("Orphan files not retired: {e}"));
            return None;
        }
    };
    let config = ctx.config;
    match retire_files_batch(
        &config.backups,
        candidates,
        &config.keyrings_dir,
        &live,
        passphrase,
    ) {
        Ok(report) => {
            if let Some(backup) = report.backup.clone() {
                emit_backup(ctx.out, backup);
            }
            Some(report)
        }
        Err(e) => {
            ctx.out.error(format!("Orphan files not retired: {e}"));
            None
        }
    }
}
