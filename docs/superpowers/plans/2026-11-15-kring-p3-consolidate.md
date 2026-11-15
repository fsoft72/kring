# kring Plan 3: Copy, move, conflict preview, consolidate

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Copy and move items between keyrings, resolve conflicts in a side-by-side preview (newest preselected), upgrade offline/archive import to the same preview, and consolidate the user's orphan `Default*` keyrings into one target with a previewed, backed-up, step-by-step plan (including one-shot retirement of empty plaintext orphan files).

**Architecture:** `kring-core::transfer` gains a source-agnostic transfer planner and executor (live items and offline items share one model) and a pure consolidation planner + executor. The worker keeps the last computed plan in memory under a plan id, so the UI only sends back the plan id and per-conflict choices (secrets never round-trip through the UI). UI: multi-select on item cards with Copy to / Move to, a conflict preview dialog reused by import, and a Consolidate area under the rail.

**Tech Stack:** as Plans 1-2. No new dependencies expected.

**Spec:** `docs/superpowers/specs/2026-11-15-kring-design.md` sections 2.1 (copy/move), 2.3 (consolidate), 6.6. User decision recorded in the spec: conflicts are shown side by side with the newest preselected, the user decides per item, the loser is kept only in the backup.

## Context from Plans 1-2 and the user's system

- Plan 2 import (`transfer/import.rs`): `plan_import`/`import_items`, decisions Create / SkipDuplicate / SkipConflict / SkipNoSecret; equality ignores `xdg:content-type`; items without secret never shadow real ones. Plan 3 replaces SkipConflict with a user-resolved conflict.
- Worker deletes go through `backup_before` (fail closed unless the target `<name>.keyring` is in the backup set; `session` skips backup). Backups of files whose original no longer exists are pinned (never pruned).
- User's system: ~70 keyrings, many `Default_N` / `Default_keyring_N` orphans; 20 empty textual orphan files (not daemon-loaded or empty); 4 daemon-unreadable textual files (handled by Plan 2 import + retire). Many binary orphans are probably locked with unknown passwords.

## Global Constraints

- All Plan 1/2 constraints apply (no GUI toolkits, oo7 pinned, SecretValue + zeroize, no secrets in logs/events except the dedicated secret events, English, rustdoc, early returns, UPPER_SNAKE, no long dash, rustfmt, Conventional Commits without AI attribution).
- **Equality** (identity of an item): attributes map with `xdg:content-type` removed. Duplicate = same identity + same secret bytes. Conflict = same identity + different secret.
- **Conflict default**: preselect the side with the newer `modified`; ties -> keep target. Choices: `KeepTarget` | `UseIncoming`. `UseIncoming` updates the existing target item (secret + label) via `update_item`; the overwritten value survives only in the pre-apply backup, so applying any `UseIncoming` or any Move requires the worker's `backup_before` on the target collection (and on the source collection for Move), fail closed.
- **Move** = copy, then delete the source item only after its copy succeeded (or was a duplicate / resolved as KeepTarget with identical-or-newer target). Never delete a source item whose content is not present in the target after apply.
- **Consolidate** never deletes: the target collection, the collection holding the `login` path, the `session` collection, or locked collections it could not read. Empty collections are deleted only when they contain zero items at apply time (re-checked). Default alias is set to the target at the end.
- **One backup per apply** (transfer or consolidation), created before any mutation; any backup failure aborts with nothing changed.
- **Stop on first error** during consolidation apply; report completed steps and the failing step; never continue past an error.
- Plans held by the worker expire when any mutating command runs (plan id mismatch -> `Error("Plan is out of date, preview again")`).
- Tests never use the real Secret Service or real keyring files; FakeStore + tempdirs + synthetic fixtures; integration via `scripts/it-session.sh`.
- UI: Obsidian design system (`crates/kring/src/ui`), screenshots via the scratchpad `shot-kring.sh` in `scripts/dev-session.sh` only.

## Review Focus

1. **Move never loses data**: a source item is deleted only after its content is verified present in the target (created, duplicate, or KeepTarget where the target already holds the same identity). Test in Task 2.
2. **UseIncoming overwrites only after backup**: no `update_item` on a target item happens unless the pre-apply backup succeeded. Test in Task 6.
3. **Consolidation never deletes protected collections** (target, login path, session, unreadable locked) and re-checks emptiness at apply time. Tests in Tasks 3-4.
4. **Stale plan**: applying a plan after any other mutation is refused. Test in Task 6.
5. **Secrets never travel back from the UI**: ApplyTransfer / ApplyConsolidation carry only plan id + choices. Test in Task 6 (type-level: commands have no SecretValue fields).

---

### Task 1: Transfer plan model

**Files:**
- Create: `crates/kring-core/src/transfer/plan.rs`
- Modify: `crates/kring-core/src/transfer/import.rs` (reimplement `plan_import` on top of `plan_transfer`, keep its public API and tests passing; SkipConflict entries now come from `TransferPlan.conflicts`)

**Interfaces:**
- Produces:
  - `pub enum TransferSource { Live(ItemId), Offline(usize) /* index into the incoming offline list */ }`
  - `pub struct Incoming { pub source: TransferSource, pub label: String, pub attributes: Attributes, pub secret: SecretValue, pub secret_missing: bool, pub modified: u64 }`
  - `pub struct Existing { pub id: ItemId, pub label: String, pub attributes: Attributes, pub secret: SecretValue, pub modified: u64 }`
  - `pub enum Choice { KeepTarget, UseIncoming }`
  - `pub struct Conflict { pub incoming: usize /* index in incoming */, pub existing: ItemId, pub label_incoming: String, pub label_existing: String, pub modified_incoming: u64, pub modified_existing: u64, pub default_choice: Choice }`
  - `pub enum Action { Create, Duplicate { existing: ItemId }, Conflict(usize /* index in conflicts */), NoSecret, SkipSameBatch, ConflictSameBatch }`
  - `pub struct TransferPlan { pub actions: Vec<Action> /* one per incoming */, pub conflicts: Vec<Conflict> }` with `pub fn counts(&self) -> TransferCounts { create, duplicate, conflict, no_secret }`.
  - `pub fn identity(attrs: &Attributes) -> Attributes` (drops `xdg:content-type`; move the existing helper here).
  - `pub fn plan_transfer(incoming: &[Incoming], existing: &[Existing]) -> TransferPlan` (pure). Rules: NoSecret first (never matched, never matches others); then identity match against `existing` (first match): same secret bytes -> Duplicate, else Conflict (default newest by modified, tie KeepTarget); then identity match against earlier incoming items planned as Create: same secret -> SkipSameBatch, different -> ConflictSameBatch (skipped, listed, first wins). Document exactly in rustdoc.
- [ ] Failing tests: `duplicate_and_conflict_detected`, `newest_preselected_tie_keeps_target`, `no_secret_never_matches`, `same_batch_duplicates_and_conflicts`, `content_type_ignored`; existing import tests still pass.
- [ ] Implement, pass, commit `feat(core): source-agnostic transfer planner`.

### Task 2: Transfer executor (copy / move / apply choices)

**Files:**
- Create: `crates/kring-core/src/transfer/apply.rs`

**Interfaces:**
- Produces:
  - `pub enum TransferMode { Copy, Move }`
  - `pub struct TransferReport { pub created: usize, pub duplicates: usize, pub replaced: usize, pub kept_target: usize, pub no_secret: usize, pub same_batch_skipped: usize, pub source_deleted: usize, pub source_kept: Vec<String> /* labels kept because not safely transferred */, pub failed: Vec<(String, String)> }`
  - `pub async fn apply_transfer<S: SecretStore + ?Sized>(store: &S, target: &CollectionId, incoming: &[Incoming], plan: &TransferPlan, choices: &[Choice] /* one per conflict */, mode: TransferMode) -> Result<TransferReport>`: validates `choices.len() == plan.conflicts.len()`; target unlocked else `Locked`; Create -> `create_item(replace: false)`; Conflict+UseIncoming -> `update_item(existing, label+secret)`; Move deletes `TransferSource::Live` sources only when the item's content is in the target afterwards: Create succeeded, Duplicate, Conflict+UseIncoming succeeded, Conflict+KeepTarget only if target modified >= incoming modified (else keep source, list in `source_kept`); NoSecret/same-batch: Move deletes the source only for SkipSameBatch duplicates (identical content present), never for NoSecret or ConflictSameBatch. Per-item failures recorded; continue; no source deletion for failed items.
- [ ] Failing tests (FakeStore): `copy_creates_and_counts`, `move_deletes_only_safe_sources` (Review Focus 1, all branches), `use_incoming_updates_target`, `keep_target_older_keeps_source_on_move`, `choices_length_mismatch_rejected`, `locked_target_rejected`, `failed_create_keeps_source`.
- [ ] Implement, pass, commit `feat(core): apply transfers with copy and move semantics`.

### Task 3: Consolidation planner (pure)

**Files:**
- Create: `crates/kring-core/src/transfer/consolidate.rs`

**Interfaces:**
- Produces:
  - `pub struct CollectionSnapshot { pub info: CollectionInfo, pub items: Option<Vec<Existing>> /* None when locked/unreadable */ }`
  - `pub enum SkipReason { Locked, Protected(&'static str), Target }`
  - `pub struct MoveStep { pub source: CollectionId, pub label: String, pub incoming: Vec<Incoming>, pub plan: TransferPlan }`
  - `pub struct ConsolidationPlan { pub target: CollectionId, pub moves: Vec<MoveStep>, pub delete_empty: Vec<(CollectionId, String)>, pub skipped: Vec<(CollectionId, String, SkipReason)>, pub set_default: bool, pub conflict_count: usize }`
  - `pub fn plan_consolidation(snapshots: &[CollectionSnapshot], target: &CollectionId, current_default: Option<&CollectionId>) -> Result<ConsolidationPlan>`: target must be present and readable (else InvalidInput); protected = target, `LOGIN_COLLECTION_PATH`, any id ending `/collection/session`; locked/unreadable -> skipped Locked; empty readable non-protected -> delete_empty; non-empty readable non-protected -> MoveStep planned against the target's items PLUS items already planned for creation by earlier MoveSteps (so two orphans with the same item do not both create it); `set_default = current_default != Some(target)`.
  - Conflict indexing: each MoveStep has its own `plan.conflicts`; the UI addresses a choice as `(step index, conflict index)`.
- [ ] Failing tests: `empty_orphans_deleted_protected_never`, `locked_skipped`, `cross_orphan_dedupe` (same item in two orphans -> created once, second is Duplicate/SameBatch), `conflicts_counted`, `target_must_be_readable`, `default_alias_flag`.
- [ ] Implement, pass, commit `feat(core): consolidation planner`.

### Task 4: Consolidation executor

**Files:**
- Modify: `crates/kring-core/src/transfer/consolidate.rs` (or `consolidate_apply.rs` if > ~300 lines)

**Interfaces:**
- Produces:
  - `pub enum StepOutcome { Moved { source: String, report: TransferReport }, Deleted(String), DefaultSet, Failed { step: String, error: String } }`
  - `pub struct ConsolidationReport { pub outcomes: Vec<StepOutcome>, pub completed: bool }`
  - `pub async fn apply_consolidation<S: SecretStore + ?Sized>(store: &S, plan: &ConsolidationPlan, choices: &[Vec<Choice>] /* per move step */, progress: &mut dyn FnMut(usize, usize)) -> Result<ConsolidationReport>`: order = moves (each `apply_transfer` with Move), then for each source of a move: delete the source collection only if now empty (re-list), then `delete_empty` entries (re-checked empty at apply time; non-empty -> Failed and stop), then `set_alias("default", target)`. Stop on first `Failed` (any `apply_transfer` with `failed` non-empty counts as failed). Backups are the worker's job (Task 6), not this function's.
- [ ] Failing tests: `applies_in_order_and_sets_default`, `stops_on_first_failure`, `non_empty_at_apply_time_not_deleted` (Review Focus 3), `source_deleted_only_when_empty_after_move`, `progress_reported`.
- [ ] Implement, pass, commit `feat(core): apply consolidation step by step`.

### Task 5: Batch retire of empty plaintext orphan files

**Files:**
- Modify: `crates/kring-core/src/keyring_file/retire.rs`

**Interfaces:**
- Produces: `pub fn retire_files_batch(manager: &BackupManager, infos: &[KeyringFileInfo], keyrings_dir: &Path, live: &[CollectionInfo], passphrase: &SecretValue) -> Result<RetireBatchReport>` with `pub struct RetireBatchReport { pub backup: BackupInfo, pub removed: Vec<String>, pub kept: Vec<(String, String)> }`: every file passes the same per-file checks as `retire_file` (location, not live, plaintext by bytes, unchanged since scan); any file failing the pre-checks is listed in `kept` and excluded; ONE backup of the remaining files; verify each in the manifest (encrypted + sha256) then unlink each with the pre-unlink unchanged check (a changed file is kept, listed). Refactor `retire_file` to share the checks (no behavior change; existing tests pass).
- [ ] Failing tests: `batch_one_backup_many_files`, `batch_excludes_live_and_binary`, `batch_keeps_changed_file`, `batch_backup_failure_removes_nothing`.
- [ ] Implement, pass, commit `feat(core): retire plaintext files in one batch`.

### Task 6: Worker: plans, previews and applies

**Files:**
- Create: `crates/kring/src/worker_transfer.rs` (+ `worker_transfer/tests.rs`)
- Modify: `crates/kring/src/worker.rs` (variants + dispatch only), `crates/kring/src/worker_offline.rs` (ImportFile / ImportArchive now produce a preview), `crates/kring/src/app_state.rs`

**Interfaces:**
- Commands:
  - `PlanTransfer { items: Vec<ItemId>, target: CollectionId, mode: TransferMode }`
  - `PlanFileImport { name: String, password: Option<SecretValue>, target: CollectionId }` (replaces ImportFile; ImportFile stays as alias that plans and, when there are no conflicts, applies directly - keep Plan 2 behavior for no-conflict imports)
  - `PlanArchiveImport { path: PathBuf, passphrase: SecretValue, target: CollectionId }` (same rule)
  - `ApplyTransfer { plan_id: u64, choices: Vec<Choice>, backup_passphrase: Option<SecretValue> }`
  - `PlanConsolidation { target: CollectionId, include_orphan_files: bool }`
  - `ApplyConsolidation { plan_id: u64, choices: Vec<Vec<Choice>>, backup_passphrase: Option<SecretValue>, orphan_files_passphrase: Option<SecretValue> }`
  - `DiscardPlan`
- Events:
  - `TransferPreview { plan_id: u64, target: CollectionId, mode: TransferMode, counts: TransferCounts, conflicts: Vec<ConflictView> }` where `ConflictView { label_incoming, label_existing, modified_incoming, modified_existing, default_choice, incoming_item: Option<ItemId>, existing_item: ItemId, offline_index: Option<usize> }` (NO secrets; the UI reveals values through existing RevealSecret / file items)
  - `TransferDone(TransferReport)`
  - `ConsolidationPreview { plan_id: u64, summary: ConsolidationSummary }` with per-step counts, delete list, skipped list (reasons), conflicts per step as `ConflictView`, orphan files list (names) when requested
  - `ConsolidationProgress { done: usize, total: usize }`
  - `ConsolidationDone(ConsolidationReport, Option<RetireBatchReport>)`
- Rules:
  - The worker stores `pending_plan: Option<(u64, PendingPlan)>`; any mutating command (all Plan 1/2 mutating commands and every Apply) clears it; Apply with a mismatching or missing id -> `Error("Plan is out of date, preview again")` (Review Focus 4).
  - Snapshots for planning read item secrets via `read_secret` only for unlocked collections; locked ones become `items: None`.
  - Before ApplyTransfer: if mode is Move or any choice is UseIncoming -> `backup_before` covering the target collection and (for Move) the source collection(s) - extend `backup_before` (or add `backup_collections`) to require every named collection's `.keyring` in the set; single backup; PassphraseNeeded flow as Plan 1. Copy without UseIncoming needs no backup (pure addition).
  - Before ApplyConsolidation: one backup of the whole keyring set, required (fail closed); then core apply with progress events; then, if requested, `retire_files_batch` for empty plaintext non-live orphan files from a fresh scan (needs `orphan_files_passphrase`).
  - Gating: Move, UseIncoming, consolidation deletes need `allows_writes()`; copy-only into any provider allowed (as Plan 1).
  - All handlers under `run_guarded`.
- [ ] Failing tests (FakeStore + tempdir keyrings fixtures): `plan_then_apply_copy`, `stale_plan_rejected`, `use_incoming_requires_backup_first` (Review Focus 2: backup failure -> no update), `move_backs_up_source_and_target`, `file_import_without_conflicts_applies_directly`, `file_import_with_conflicts_previews`, `consolidation_preview_then_apply_with_progress`, `consolidation_backup_failure_changes_nothing`, `orphan_batch_runs_after_consolidation`, `apply_commands_carry_no_secrets` (compile-time: a test that constructs ApplyTransfer/ApplyConsolidation with only ids/choices/passphrases).
- [ ] Implement, pass, commit `feat(app): worker plans and applies transfers and consolidation`.

### Task 7: UI: multi-select, Copy to / Move to, conflict preview

**Files:**
- Create: `crates/kring/src/views/transfer.rs` (target picker + conflict preview dialog), modify `views/item_list.rs` (selection checkboxes, toolbar actions), `views/file_detail.rs` + `views/backups.rs`/archive import call sites (use preview), `views/dialogs.rs` family.

**Behavior:**
- Item cards get a checkbox (left edge); toolbar shows "N selected - Copy to... - Move to..." (Move disabled with the write gate tooltip). Single-item card menu also offers Copy/Move.
- Target picker: unlocked collections except the current one (locked shown disabled "(locked)").
- Conflict preview dialog (Obsidian modal, wide): header counts ("3 new - 2 already there - 1 conflict - 0 without secret"); one row per conflict: left "In <target>" (label, modified, masked secret with eye -> RevealSecret of existing item), right "Incoming" (label, modified, masked secret with eye -> RevealSecret of the source live item or the offline item's secret already in AppState.file_items), a two-option toggle (Keep current / Use incoming) with the newest preselected and marked "newer". Footer: Cancel, Apply (primary; danger style when any Use incoming or Move: text "Apply (backup first)").
- Revealed values in the dialog are cleared when the dialog closes.
- After apply: toast from TransferDone counts; selection cleared.
- [ ] Pure helpers tested: `selection_toggle`, `preview_header(counts)`, `apply_is_destructive(mode, choices)`, `default_choices(conflicts)`.
- [ ] Screenshots (dev-session, presets extended: `KRING_DEV_DIALOG=transfer-preview` with a seeded conflict: extend `seed_dev` so `Work` and `login` share one item identity with different secrets).
- [ ] Commit `feat(ui): copy and move items with conflict preview`.

### Task 8: UI: Consolidate area

**Files:**
- Create: `crates/kring/src/views/consolidate.rs`; modify `views/rail.rs` (new "Consolidate" tile with a merge glyph, between Backups and the bottom), `app.rs`.

**Behavior:**
- Start card: explains the action; target combo (default `login` if readable); checkbox "Also retire empty plaintext orphan files (N found)"; "Preview" primary.
- Preview: summary cards: "Move N items from M keyrings into <target>", "Delete K empty keyrings", "Skipped: L locked keyrings (unlock them first to include)" with the list and an Unlock shortcut, "Set <target> as default", "Retire R empty plaintext files"; per-step expandable list; conflicts section reusing the Task 7 conflict rows (choices per step).
- Apply: danger primary "Consolidate (backup first)"; passphrase dialog(s) as needed (backup passphrase when plaintext keyrings exist; orphan files passphrase with confirm); progress bar from ConsolidationProgress; result card listing outcomes (failed step highlighted in ERROR, completed steps in OK) and the backup location.
- [ ] Pure helpers tested: `summary_lines(summary)`, `outcome_rows(report)`, `needs_passphrases(summary, files)`.
- [ ] Screenshots with seeded orphans (seed_dev already creates `Default_1`; add `Default_2` with one duplicate item of login and `Default_3` empty).
- [ ] Commit `feat(ui): consolidate keyrings area`.

### Task 9: End-to-end consolidation test on a throwaway gnome-keyring + docs

- [ ] `crates/kring-core/tests/it_consolidate.rs` (guarded by `it_guard`, run via `scripts/it-session.sh`): create orphans in the private daemon (empty, duplicate item, conflicting item, locked one), plan + apply consolidation into `login` with choices, assert: items present in login, empty orphans deleted, locked one untouched, default alias = login, and that the private keyrings dir has no leftover files for deleted collections.
- [ ] README: Copy/Move and Consolidate sections, recommended order for the user's real cleanup (import + retire the 4 unreadable files first, then consolidate, then retire orphan files), and the restart hint.
- [ ] Commit `test: end-to-end consolidation on a throwaway keyring` and `docs: consolidation usage`.
