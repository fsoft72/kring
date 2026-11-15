//! Worker handlers for transfers (copy, move, imports) and consolidation.
//!
//! The worker computes every plan itself and keeps it in [`PlanState`]; the UI
//! only sees previews without secrets ([`ConflictView`],
//! [`ConsolidationSummary`]) and applies a plan by id with its choices.
//! Every command that may change keyring data drops the pending plan (see
//! [`invalidates_plan`]), and an apply always consumes it, except when it
//! stops to ask for a passphrase: then the same plan id stays valid for the
//! resent command.
//!
//! Imports of keyring files and archives (`ImportFile` / `PlanFileImport`,
//! `ImportArchive` / `PlanArchiveImport`, same behavior) are planned against
//! the target: without conflicts they are applied directly as a copy (no
//! backup, pure addition) and answered with [`Event::ImportDone`]; with
//! conflicts they are answered with [`Event::TransferPreview`] and wait for
//! [`Command::ApplyTransfer`]. Offline secrets stay in the pending plan.
//! KWallet imports (`PlanWalletImport`, read in [`crate::worker_wallet`])
//! follow the same rule through [`plan_wallet_import`].

use kring_core::keyring_file::textual::OfflineItem;
use kring_core::model::{CollectionId, CollectionInfo, ItemId, ItemInfo, SecretValue};
use kring_core::provider::ProviderInfo;
use kring_core::transfer::apply::{TransferMode, TransferReport, apply_transfer};
use kring_core::transfer::archive::read_archive;
use kring_core::transfer::consolidate::{ConsolidationPlan, PLANNED_ID_PREFIX, SkipReason};
use kring_core::transfer::import::ImportReport;
use kring_core::transfer::plan::{
    Action, Choice, Conflict, Existing, Incoming, TransferCounts, TransferPlan, TransferSource,
    identity, plan_transfer,
};
use kring_core::{KringError, MasterPasswordStore, Result, SecretStore};

use crate::worker::{
    BackupStep, CHANGE_WORDING, Command, Emitter, Event, MSG_NO_PROVIDER, MSG_UNSUPPORTED,
    WorkerConfig, backup_collections, collection_of, load_items, refresh,
};
use crate::worker_offline::{read_file, resolve_file};
use crate::worker_wallet::competitor_notice;

/// Message for an apply whose plan is missing or was replaced.
pub(crate) const MSG_STALE_PLAN: &str = "Plan is out of date, preview again";
/// Message for a move whose target already holds the items.
pub(crate) const MSG_MOVE_INTO_SELF: &str = "Cannot move items into the collection they are in";
/// Message for a transfer of live items that changed after the preview.
pub(crate) const MSG_SOURCES_CHANGED: &str = "Items changed since the preview, preview again";
/// Message for a transfer whose target changed after the preview.
pub(crate) const MSG_TARGET_CHANGED: &str = "Target changed since the preview, preview again";
/// Message for a transfer request without items.
const MSG_NO_ITEMS: &str = "No items selected";
/// Alias read to know whether consolidation must set the default.
const DEFAULT_ALIAS: &str = "default";
/// Backup reason of a transfer.
const REASON_TRANSFER: &str = "transfer";
/// Backup reason of a consolidation.
const REASON_CONSOLIDATE: &str = "consolidate";

/// A conflict as shown to the UI (never carries secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictView {
    /// Label of the incoming item.
    pub label_incoming: String,
    /// Label of the target item.
    pub label_existing: String,
    /// Modification time of the incoming item, unix seconds.
    pub modified_incoming: u64,
    /// Modification time of the target item, unix seconds.
    pub modified_existing: u64,
    /// Preselected choice (newer side, ties keep the target).
    pub default_choice: Choice,
    /// Live source item, revealed with `RevealSecret`; `None` for offline items.
    pub incoming_item: Option<ItemId>,
    /// True when the UI can show the incoming secret: a live item, an item
    /// of a keyring file import (`AppState::file_items[offline_index]`) or
    /// of a wallet import (`AppState::wallet_items[offline_index]`; the UI
    /// keeps it true only while that wallet is open). Archive items are
    /// never revealable (their secrets stay in the worker).
    pub incoming_revealable: bool,
    /// Target item, revealed with `RevealSecret`; `None` when it is only
    /// planned by an earlier consolidation step (see `existing_planned`).
    pub existing_item: Option<ItemId>,
    /// True when the target side is an item an earlier consolidation step
    /// will create; it has no id yet and must never be revealed.
    pub existing_planned: bool,
    /// Index of the incoming item in the imported keyring file or in the
    /// wallet items (file and wallet imports only).
    pub offline_index: Option<usize>,
}

/// One move step of a consolidation preview.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepSummary {
    /// The source collection.
    pub source: CollectionId,
    /// Its label.
    pub label: String,
    /// What the step will do with its items.
    pub counts: TransferCounts,
    /// Its conflicts; choices for the step are given in this order.
    pub conflicts: Vec<ConflictView>,
}

/// A consolidation preview (never carries secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolidationSummary {
    /// Collection receiving every item.
    pub target: CollectionId,
    /// Move steps, in apply order.
    pub steps: Vec<StepSummary>,
    /// Empty collections to delete, `(id, label)`.
    pub delete_empty: Vec<(CollectionId, String)>,
    /// Collections left alone, `(id, label, reason)`.
    pub skipped: Vec<(CollectionId, String, SkipReason)>,
    /// Skipped collections with [`SkipReason::Locked`] (unlock them to include them).
    pub locked_count: usize,
    /// True when the `default` alias will be pointed at the target.
    pub set_default: bool,
    /// Total conflicts over all steps.
    pub conflict_count: usize,
    /// Names of the empty plaintext orphan files to retire (when requested).
    pub orphan_files: Vec<String>,
    /// True when the keyring backup set holds a plaintext keyring at plan
    /// time, so the pre-apply backup will need a passphrase.
    pub backup_needs_passphrase: bool,
}

/// Where the incoming items of a transfer plan come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    /// Live items of collections.
    Live,
    /// Items of a keyring file (the UI holds them in `AppState::file_items`).
    File,
    /// Items of an archive (only the worker holds them).
    Archive,
    /// Entries of a KWallet wallet (the UI holds them in `AppState::wallet_items`).
    Wallet,
}

/// A transfer plan held by the worker, with the secrets of its items.
struct TransferJob {
    /// Target collection.
    target: CollectionId,
    /// Copy or move.
    mode: TransferMode,
    /// Origin of the incoming items.
    origin: Origin,
    /// Incoming items with their secrets.
    incoming: Vec<Incoming>,
    /// The plan against the target.
    plan: TransferPlan,
    /// Collections of the live incoming items.
    sources: Vec<CollectionId>,
}

/// A plan waiting to be applied.
enum PendingPlan {
    /// A copy, move or import.
    Transfer(TransferJob),
    /// A consolidation, with the orphan file names shown in its preview.
    Consolidation {
        plan: ConsolidationPlan,
        orphan_files: Vec<String>,
    },
}

/// The worker's pending plan and plan id counter.
#[derive(Default)]
pub(crate) struct PlanState {
    /// The plan waiting for its apply command, by id.
    pending: Option<(u64, PendingPlan)>,
    /// Last plan id handed out.
    last_id: u64,
}

impl PlanState {
    /// Drops the pending plan (and the secrets it holds).
    pub(crate) fn clear(&mut self) {
        self.pending = None;
    }

    /// Stores a new plan and returns its fresh id.
    fn put(&mut self, plan: PendingPlan) -> u64 {
        self.last_id += 1;
        self.pending = Some((self.last_id, plan));
        self.last_id
    }

    /// Takes the pending plan out; returns it only when its id is `id`.
    fn take(&mut self, id: u64) -> Option<PendingPlan> {
        let (pending_id, plan) = self.pending.take()?;
        (pending_id == id).then_some(plan)
    }

    /// Puts a taken plan back under its id (an apply waiting for a passphrase).
    fn restore(&mut self, id: u64, plan: PendingPlan) {
        self.pending = Some((id, plan));
    }
}

/// Returns true for commands handled by this module.
pub(crate) fn is_transfer(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::ImportFile { .. }
            | Command::ImportArchive { .. }
            | Command::PlanTransfer { .. }
            | Command::PlanFileImport { .. }
            | Command::PlanArchiveImport { .. }
            | Command::ApplyTransfer { .. }
            | Command::PlanConsolidation { .. }
            | Command::ApplyConsolidation { .. }
            | Command::DiscardPlan
    )
}

/// Returns true for commands that drop the pending plan: everything that may
/// change keyring data or what a plan could read. Only pure reads keep it
/// (deny-list: a new command drops the plan unless listed here; SSH key and
/// agent changes drop it too).
pub(crate) fn invalidates_plan(cmd: &Command) -> bool {
    !matches!(
        cmd,
        Command::Refresh
            | Command::LoadItems(_)
            | Command::RevealSecret(_)
            | Command::ScanFiles
            | Command::OpenFile { .. }
            | Command::ScanWallets
            | Command::OpenWallet { .. }
            | Command::ListBackups
            | Command::ExportCollection { .. }
            | Command::ScanSshKeys
            | Command::ReadSshPublicKey { .. }
            | Command::AgentList
            | Command::ExportSshPrivate { .. }
    )
}

/// Handles one transfer command, reporting failures as [`Event::Error`].
///
/// A `NotFound` failure also re-lists the collections.
pub(crate) async fn handle<S, N>(
    out: &Emitter<N>,
    store: Option<&S>,
    provider: Option<&ProviderInfo>,
    config: &WorkerConfig,
    plans: &mut PlanState,
    cmd: Command,
) where
    S: SecretStore + MasterPasswordStore,
    N: Fn(),
{
    if matches!(cmd, Command::DiscardPlan) {
        return plans.clear();
    }
    let Some(store) = store else {
        plans.clear();
        return out.error(MSG_NO_PROVIDER);
    };
    let ctx = Ctx {
        out,
        store,
        provider,
        config,
    };
    if let Err(e) = run(&ctx, plans, &cmd).await {
        out.error(e.to_string());
        if matches!(e, KringError::NotFound(_)) {
            refresh(out, store).await;
        }
    }
}

/// Shared handler context.
struct Ctx<'a, S, N: Fn()> {
    /// Event sink.
    out: &'a Emitter<N>,
    /// The store.
    store: &'a S,
    /// The provider, for the write gate.
    provider: Option<&'a ProviderInfo>,
    /// Filesystem locations.
    config: &'a WorkerConfig,
}

impl<S, N: Fn()> Ctx<'_, S, N> {
    /// Returns true when the provider allows writes; otherwise emits the refusal.
    fn allow_writes(&self) -> bool {
        let allowed = self.provider.is_some_and(ProviderInfo::allows_writes);
        if !allowed {
            self.out.error(MSG_UNSUPPORTED);
        }
        allowed
    }
}

/// Executes one transfer command.
async fn run<S, N>(ctx: &Ctx<'_, S, N>, plans: &mut PlanState, cmd: &Command) -> Result<()>
where
    S: SecretStore,
    N: Fn(),
{
    match cmd {
        Command::PlanTransfer {
            items,
            target,
            mode,
        } => {
            plans.clear();
            plan_live_transfer(ctx, plans, items, target, *mode).await
        }
        Command::ImportFile {
            name,
            password,
            target,
        }
        | Command::PlanFileImport {
            name,
            password,
            target,
        } => {
            plans.clear();
            let info = resolve_file(ctx.config, name)?;
            let Some((items, _)) = read_file(ctx.out, &info, password.as_ref()).await? else {
                return Ok(());
            };
            plan_import(ctx, plans, target, offline_incoming(items), Origin::File).await
        }
        Command::ImportArchive {
            path,
            passphrase,
            target,
        }
        | Command::PlanArchiveImport {
            path,
            passphrase,
            target,
        } => {
            plans.clear();
            let items = read_archive(path, passphrase)?
                .into_iter()
                .map(|e| e.item)
                .collect();
            plan_import(ctx, plans, target, offline_incoming(items), Origin::Archive).await
        }
        Command::ApplyTransfer {
            plan_id,
            choices,
            backup_passphrase,
        } => {
            let Some(PendingPlan::Transfer(job)) = plans.take(*plan_id) else {
                ctx.out.error(MSG_STALE_PLAN);
                return Ok(());
            };
            let pass = backup_passphrase.as_ref();
            let Some(job) = apply_job(ctx, job, choices, pass, *plan_id).await? else {
                return Ok(());
            };
            plans.restore(*plan_id, PendingPlan::Transfer(job));
            Ok(())
        }
        Command::PlanConsolidation {
            target,
            include_orphan_files,
        } => {
            plans.clear();
            consolidate::plan_consolidate(ctx, plans, target, *include_orphan_files).await
        }
        Command::ApplyConsolidation {
            plan_id,
            choices,
            backup_passphrase,
            orphan_files_passphrase,
        } => {
            let Some(PendingPlan::Consolidation { plan, orphan_files }) = plans.take(*plan_id)
            else {
                ctx.out.error(MSG_STALE_PLAN);
                return Ok(());
            };
            let passes = consolidate::Passphrases {
                backup: backup_passphrase.as_ref(),
                orphan_files: orphan_files_passphrase.as_ref(),
            };
            let waiting = consolidate::apply_consolidate(
                ctx,
                &plan,
                &orphan_files,
                choices,
                passes,
                *plan_id,
            )
            .await?;
            if waiting {
                let plan = PendingPlan::Consolidation { plan, orphan_files };
                plans.restore(*plan_id, plan);
            }
            Ok(())
        }
        _ => Err(KringError::InvalidInput(
            "Command sent to the transfer path".into(),
        )),
    }
}

/// Builds an `InvalidInput` error.
fn invalid(message: impl Into<String>) -> KringError {
    KringError::InvalidInput(message.into())
}

/// Finds `id` among `collections`; fails with `NotFound`, or `Locked` when locked.
fn unlocked<'a>(
    collections: &'a [CollectionInfo],
    id: &CollectionId,
) -> Result<&'a CollectionInfo> {
    let info = collections
        .iter()
        .find(|c| &c.id == id)
        .ok_or_else(|| KringError::NotFound(id.0.clone()))?;
    if info.locked {
        return Err(KringError::Locked(id.0.clone()));
    }
    Ok(info)
}

/// Plans copying or moving live `items` into `target` and emits the preview.
///
/// Move needs a writable provider and refuses items already in the target.
/// The target and the source collections must exist and be unlocked; the
/// target must be a collection as listed (never an alias path).
async fn plan_live_transfer<S, N>(
    ctx: &Ctx<'_, S, N>,
    plans: &mut PlanState,
    items: &[ItemId],
    target: &CollectionId,
    mode: TransferMode,
) -> Result<()>
where
    S: SecretStore,
    N: Fn(),
{
    if mode == TransferMode::Move && !ctx.allow_writes() {
        return Ok(());
    }
    if items.is_empty() {
        return Err(invalid(MSG_NO_ITEMS));
    }
    let mut ids: Vec<&ItemId> = Vec::new();
    let mut sources: Vec<CollectionId> = Vec::new();
    for id in items {
        if ids.contains(&id) {
            continue;
        }
        ids.push(id);
        let source = collection_of(id);
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    if mode == TransferMode::Move && sources.contains(target) {
        ctx.out.error(MSG_MOVE_INTO_SELF);
        return Ok(());
    }
    let collections = ctx.store.list_collections().await?;
    unlocked(&collections, target)?;
    let mut listed: Vec<ItemInfo> = Vec::new();
    for source in &sources {
        unlocked(&collections, source)?;
        listed.extend(ctx.store.list_items(source).await?);
    }
    let mut incoming = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(info) = listed.iter().find(|i| &i.id == id) else {
            return Err(KringError::NotFound(id.0.clone()));
        };
        incoming.push(Incoming {
            source: TransferSource::Live(id.clone()),
            label: info.label.clone(),
            attributes: info.attributes.clone(),
            secret: ctx.store.read_secret(id).await?,
            secret_missing: false,
            modified: info.modified,
        });
    }
    let existing = target_existing(ctx.store, target, &incoming).await?;
    let plan = plan_transfer(&incoming, &existing);
    let job = TransferJob {
        target: target.clone(),
        mode,
        origin: Origin::Live,
        incoming,
        plan,
        sources,
    };
    emit_preview(ctx.out, plans, job);
    Ok(())
}

/// Plans importing the decrypted entries of a KWallet wallet into `target`
/// (same rule as a keyring file import), reporting failures as [`Event::Error`].
///
/// The pending plan must already be cleared by the caller. A successful
/// import (direct, or later through [`Command::ApplyTransfer`]) is followed
/// by the KWallet competitor notice when one is running.
pub(crate) async fn plan_wallet_import<S, N>(
    out: &Emitter<N>,
    store: &S,
    provider: Option<&ProviderInfo>,
    config: &WorkerConfig,
    plans: &mut PlanState,
    target: &CollectionId,
    incoming: Vec<Incoming>,
) where
    S: SecretStore,
    N: Fn(),
{
    let ctx = Ctx {
        out,
        store,
        provider,
        config,
    };
    if let Err(e) = plan_import(&ctx, plans, target, incoming, Origin::Wallet).await {
        out.error(e.to_string());
        if matches!(e, KringError::NotFound(_)) {
            refresh(out, store).await;
        }
    }
}

/// Maps offline items to transfer items, `TransferSource::Offline(position)`.
fn offline_incoming(items: Vec<OfflineItem>) -> Vec<Incoming> {
    items
        .into_iter()
        .enumerate()
        .map(|(index, item)| Incoming {
            source: TransferSource::Offline(index),
            label: item.label,
            attributes: item.attributes,
            secret: item.secret,
            secret_missing: item.secret_missing,
            modified: item.modified,
        })
        .collect()
}

/// Plans importing offline `incoming` items into `target`: applies directly
/// when there are no conflicts (copy, no backup), otherwise emits the preview.
async fn plan_import<S, N>(
    ctx: &Ctx<'_, S, N>,
    plans: &mut PlanState,
    target: &CollectionId,
    incoming: Vec<Incoming>,
    origin: Origin,
) -> Result<()>
where
    S: SecretStore,
    N: Fn(),
{
    let collections = ctx.store.list_collections().await?;
    unlocked(&collections, target)?;
    let existing = target_existing(ctx.store, target, &incoming).await?;
    let plan = plan_transfer(&incoming, &existing);
    if plan.conflicts.is_empty() {
        let report =
            apply_transfer(ctx.store, target, &incoming, &plan, &[], TransferMode::Copy).await?;
        ctx.out
            .emit(Event::ImportDone(import_report(&incoming, &plan, report)));
        if origin == Origin::Wallet {
            competitor_notice(ctx.out, ctx.provider);
        }
        load_items(ctx.out, ctx.store, target).await;
        refresh(ctx.out, ctx.store).await;
        return Ok(());
    }
    let job = TransferJob {
        target: target.clone(),
        mode: TransferMode::Copy,
        origin,
        incoming,
        plan,
        sources: Vec::new(),
    };
    emit_preview(ctx.out, plans, job);
    Ok(())
}

/// Maps a direct (conflict-free) import to the Plan 2 import report.
///
/// Same-batch duplicates count as duplicates and same-batch conflicts are
/// listed as conflicts, as the Plan 2 importer did.
fn import_report(
    incoming: &[Incoming],
    plan: &TransferPlan,
    report: TransferReport,
) -> ImportReport {
    let mut out = ImportReport {
        created: report.created,
        duplicates: report.duplicates,
        conflicts: Vec::new(),
        failed: report.failed,
        no_secret: report.no_secret,
    };
    for (item, action) in incoming.iter().zip(&plan.actions) {
        match action {
            Action::SkipSameBatch => out.duplicates += 1,
            Action::ConflictSameBatch => out.conflicts.push(item.label.clone()),
            _ => {}
        }
    }
    out
}

/// Reads the target items sharing an identity with an incoming item (with secrets).
async fn target_existing<S: SecretStore>(
    store: &S,
    target: &CollectionId,
    incoming: &[Incoming],
) -> Result<Vec<Existing>> {
    let wanted: Vec<_> = incoming
        .iter()
        .filter(|i| !i.secret_missing)
        .map(|i| identity(&i.attributes))
        .collect();
    let mut out = Vec::new();
    for info in store.list_items(target).await? {
        if !wanted.contains(&identity(&info.attributes)) {
            continue;
        }
        out.push(existing_of(store, info).await?);
    }
    Ok(out)
}

/// Reads the secret of a listed item into an [`Existing`].
async fn existing_of<S: SecretStore>(store: &S, info: ItemInfo) -> Result<Existing> {
    let secret = store.read_secret(&info.id).await?;
    Ok(Existing {
        id: info.id,
        label: info.label,
        attributes: info.attributes,
        secret,
        modified: info.modified,
    })
}

/// Builds the UI view of a conflict of a plan over `incoming`.
fn conflict_view(conflict: &Conflict, incoming: &[Incoming], origin: Origin) -> ConflictView {
    let source = incoming.get(conflict.incoming).map(|i| &i.source);
    let incoming_item = match source {
        Some(TransferSource::Live(id)) => Some(id.clone()),
        _ => None,
    };
    // File items are listed in plan order; wallet views are one per
    // incoming item, so the incoming position is their index.
    let offline_index = match (origin, source) {
        (Origin::File, Some(TransferSource::Offline(index))) => Some(*index),
        (Origin::Wallet, Some(TransferSource::Offline(_))) => Some(conflict.incoming),
        _ => None,
    };
    let existing_planned = conflict.existing.0.starts_with(PLANNED_ID_PREFIX);
    ConflictView {
        label_incoming: conflict.label_incoming.clone(),
        label_existing: conflict.label_existing.clone(),
        modified_incoming: conflict.modified_incoming,
        modified_existing: conflict.modified_existing,
        default_choice: conflict.default_choice,
        incoming_revealable: incoming_item.is_some() || offline_index.is_some(),
        incoming_item,
        existing_item: (!existing_planned).then(|| conflict.existing.clone()),
        existing_planned,
        offline_index,
    }
}

/// Stores a transfer plan and emits its preview.
fn emit_preview<N: Fn()>(out: &Emitter<N>, plans: &mut PlanState, job: TransferJob) {
    let conflicts = job
        .plan
        .conflicts
        .iter()
        .map(|c| conflict_view(c, &job.incoming, job.origin))
        .collect();
    let counts = job.plan.counts();
    let (target, mode) = (job.target.clone(), job.mode);
    let plan_id = plans.put(PendingPlan::Transfer(job));
    out.emit(Event::TransferPreview {
        plan_id,
        target,
        mode,
        counts,
        conflicts,
    });
}

/// Applies a transfer plan; returns the job when it must wait for a passphrase
/// (reported as [`Event::ApplyPassphrasesNeeded`] for `plan_id`).
///
/// Move or any `UseIncoming` needs a writable provider and ONE backup first:
/// of the target and (for Move) of every source collection. Copy without
/// `UseIncoming` only adds items and needs no backup. Live sources are
/// re-read first: if any changed or vanished since the preview nothing runs.
/// The target is re-read and re-planned too: if the plan differs from the
/// previewed one (see [`target_unchanged`]) nothing runs.
async fn apply_job<S, N>(
    ctx: &Ctx<'_, S, N>,
    job: TransferJob,
    choices: &[Choice],
    passphrase: Option<&SecretValue>,
    plan_id: u64,
) -> Result<Option<TransferJob>>
where
    S: SecretStore,
    N: Fn(),
{
    if choices.len() != job.plan.conflicts.len() {
        return Err(invalid(format!(
            "expected {} conflict choices, got {}",
            job.plan.conflicts.len(),
            choices.len()
        )));
    }
    let use_incoming = choices.contains(&Choice::UseIncoming);
    let is_move = job.mode == TransferMode::Move;
    if (is_move || use_incoming) && !ctx.allow_writes() {
        return Ok(None);
    }
    if job.origin == Origin::Live && !sources_unchanged(ctx.store, &job.incoming).await? {
        ctx.out.error(MSG_SOURCES_CHANGED);
        return Ok(None);
    }
    if !target_unchanged(ctx.store, &job).await? {
        ctx.out.error(MSG_TARGET_CHANGED);
        return Ok(None);
    }
    let mut names: Vec<CollectionId> = Vec::new();
    if is_move || use_incoming {
        names.push(job.target.clone());
    }
    if is_move {
        names.extend(job.sources.iter().cloned());
    }
    if !names.is_empty() {
        let step = backup_collections(
            ctx.out,
            ctx.config,
            &names,
            REASON_TRANSFER,
            passphrase,
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
                return Ok(Some(job));
            }
            BackupStep::Stop => return Ok(None),
        }
    }
    let report = apply_transfer(
        ctx.store,
        &job.target,
        &job.incoming,
        &job.plan,
        choices,
        job.mode,
    )
    .await?;
    ctx.out.emit(Event::TransferDone(report));
    if job.origin == Origin::Wallet {
        competitor_notice(ctx.out, ctx.provider);
    }
    load_items(ctx.out, ctx.store, &job.target).await;
    if is_move {
        for source in &job.sources {
            load_items(ctx.out, ctx.store, source).await;
        }
    }
    refresh(ctx.out, ctx.store).await;
    Ok(None)
}

/// Returns true when planning the job's incoming items against the target as
/// it is now gives the previewed plan: the same actions and the same
/// conflicts (target item and incoming index).
async fn target_unchanged<S: SecretStore>(store: &S, job: &TransferJob) -> Result<bool> {
    let existing = target_existing(store, &job.target, &job.incoming).await?;
    let now = plan_transfer(&job.incoming, &existing);
    if now.actions != job.plan.actions || now.conflicts.len() != job.plan.conflicts.len() {
        return Ok(false);
    }
    let same = now
        .conflicts
        .iter()
        .zip(&job.plan.conflicts)
        .all(|(a, b)| a.existing == b.existing && a.incoming == b.incoming);
    Ok(same)
}

/// Returns true when every live incoming item still exists with the same
/// label, identity (see [`identity`]) and secret as when it was planned.
async fn sources_unchanged<S: SecretStore>(store: &S, incoming: &[Incoming]) -> Result<bool> {
    let mut listed: Vec<(CollectionId, Vec<ItemInfo>)> = Vec::new();
    for item in incoming {
        let TransferSource::Live(id) = &item.source else {
            continue;
        };
        let collection = collection_of(id);
        if !listed.iter().any(|(c, _)| c == &collection) {
            let items = store.list_items(&collection).await?;
            listed.push((collection.clone(), items));
        }
        let found = listed
            .iter()
            .filter(|(c, _)| c == &collection)
            .flat_map(|(_, items)| items)
            .find(|i| &i.id == id);
        let Some(info) = found else {
            return Ok(false);
        };
        if info.label != item.label || identity(&info.attributes) != identity(&item.attributes) {
            return Ok(false);
        }
        let secret = store.read_secret(id).await?;
        if secret.as_bytes() != item.secret.as_bytes() {
            return Ok(false);
        }
    }
    Ok(true)
}

mod consolidate;

pub(crate) use consolidate::MSG_ORPHANS_NOT_RETIRED;

#[cfg(test)]
mod tests;
