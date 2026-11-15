//! Consolidate area: merge every readable orphan keyring into one target.
//!
//! Flow: the start card (target, orphan files option, `Preview`), the
//! preview sent by the worker (summary cards, the move steps, the conflicts
//! with one choice each), the apply (`Consolidate (backup first)`, the
//! passphrases it needs, a progress bar) and the result card (outcome of
//! every step and the backup location).
//!
//! The preview holds no secrets: conflict sides are revealed on demand with
//! the shared conflict row and dropped when the preview closes or the area
//! is left.

use std::collections::{BTreeSet, HashMap};

use eframe::egui::{self, Align, Color32, CornerRadius, Layout, RichText, Sense, Ui};
use kring_core::keyring_file::{
    KeyringFileInfo, KeyringFormat, RetireBatchReport, RetireMode, retire_mode,
};
use kring_core::model::{CollectionId, CollectionInfo, SecretValue, decode_path_segment};
use kring_core::transfer::apply::TransferReport;
use kring_core::transfer::consolidate::SkipReason;
use kring_core::transfer::consolidate_apply::{ConsolidationReport, StepOutcome};
use kring_core::transfer::plan::{Choice, TransferCounts};

use crate::app_state::{AppState, count_noun};
use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;
use crate::ui::widgets::{
    accent_card, card, chip, danger_button, field_label, heading, muted, muted_text,
    primary_button, secondary_button, semibold,
};
use crate::views::collection::{display_name, display_names};
use crate::views::conflict_row::{MSG_CONFLICTS, RowEvent, conflict_row};
use crate::views::dialogs::DialogKind;
use crate::views::locked_list;
use crate::views::sidebar::row_background;
use crate::views::transfer::{default_choices, preview_header};
use crate::views::{Action, Gates};
use crate::worker::{Command, ConsolidationSummary};

/// Explanation of the start card.
const MSG_EXPLAIN: &str = "Moves every item of the other readable keyrings into the target \
     and deletes the keyrings left empty. Locked, login and session keyrings are never \
     touched. One backup of all keyring files is taken before anything changes.";
/// Hint of the start card: locked keyrings are unlocked from the preview.
const MSG_UNLOCK_HINT: &str =
    "Locked keyrings are skipped: unlock them from the preview, which then refreshes.";
/// Tooltip of Preview without a target.
const MSG_NO_TARGET: &str = "Choose a target keyring";
/// Tooltip of Consolidate while the apply runs.
const MSG_APPLYING: &str = "Consolidating...";
/// Text of the apply button.
const APPLY_TEXT: &str = "Consolidate (backup first)";
/// Height of a keyring row of the list.
const ROW_HEIGHT: f32 = 44.0;
/// Horizontal padding inside a keyring row.
const ROW_PADDING: f32 = 12.0;
/// Height of the progress bar.
const PROGRESS_HEIGHT: f32 = 8.0;
/// Height of a step header row.
const STEP_ROW_HEIGHT: f32 = 26.0;
/// Width of the target combo.
const TARGET_WIDTH: f32 = 320.0;
/// Height of the button row of the preview footer.
const FOOTER_ROW_HEIGHT: f32 = 36.0;
/// Room kept below the scrolled preview for its footer (note, progress, buttons).
const PREVIEW_FOOTER_HEIGHT: f32 = 110.0;

/// What a summary line is about (it decides colour and extra content).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    /// Items moved into the target (followed by the steps).
    Move,
    /// Empty keyrings deleted (followed by their names).
    Delete,
    /// Locked keyrings skipped (rendered as the locked keyrings card).
    Skipped,
    /// Keyrings skipped because reading them failed (followed by the errors).
    Unreadable,
    /// Protected keyrings never touched.
    NotTouched,
    /// The default alias moves to the target.
    Default,
    /// Empty plaintext orphan files retired.
    Retire,
}

/// One summary card of the preview.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryLine {
    /// What the line is about.
    pub kind: LineKind,
    /// Text of the line.
    pub text: String,
}

/// Tone of a result row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeTone {
    /// Done as planned (OK).
    Ok,
    /// Done, but something was left in place (TERTIARY).
    Kept,
    /// The step that failed (ERROR).
    Failed,
}

/// One row of the result card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutcomeRow {
    /// Colour of the row.
    pub tone: OutcomeTone,
    /// Text of the row.
    pub text: String,
}

/// Passphrases an apply will ask for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PassphraseNeeds {
    /// The backup holds plaintext keyrings: it is encrypted.
    pub backup: bool,
    /// Orphan files are retired into their own encrypted backup.
    pub orphan_files: bool,
}

impl PassphraseNeeds {
    /// Returns true when any passphrase is needed.
    pub fn any(self) -> bool {
        self.backup || self.orphan_files
    }
}

/// Role of a keyring in the consolidation, shown as a chip in the list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Receives every item.
    Target,
    /// Its items are moved, then it is deleted when empty.
    Move,
    /// Empty: deleted.
    Delete,
    /// Locked: skipped.
    Locked,
    /// Reading it failed: skipped.
    Unreadable,
    /// Never touched (login, session, alias).
    Protected,
}

impl Role {
    /// Chip text and colour of the role.
    pub fn chip(self) -> (&'static str, Color32) {
        match self {
            Self::Target => ("target", theme::SECONDARY),
            Self::Move => ("move", theme::PRIMARY),
            Self::Delete => ("delete", theme::TERTIARY),
            Self::Locked => ("locked", theme::TERTIARY),
            Self::Unreadable => ("unreadable", theme::ERROR),
            Self::Protected => ("protected", theme::LABEL),
        }
    }
}

/// Returns the name shown for collection `id` labelled `label`: the label,
/// or the decoded last segment of its path when the label is blank (e.g.
/// `session`).
pub fn collection_name(id: &CollectionId, label: &str) -> String {
    if !label.trim().is_empty() {
        return label.to_string();
    }
    let segment = id.0.rsplit('/').next().unwrap_or_default();
    decode_path_segment(segment).unwrap_or_else(|_| segment.to_string())
}

/// Returns the shown name of `id`: from `names` (see `display_names`), else
/// [`collection_name`] of its summary label.
pub fn name_in(names: &HashMap<CollectionId, String>, id: &CollectionId, label: &str) -> String {
    names
        .get(id)
        .cloned()
        .unwrap_or_else(|| collection_name(id, label))
}

/// Returns the number of items a step carries (every planned action).
fn _step_items(counts: &TransferCounts) -> usize {
    counts.create + counts.duplicate + counts.conflict + counts.no_secret + counts.same_batch
}

/// Returns the summary cards of a preview into `target_label`, in order:
/// move, delete, skipped (locked), skipped (unreadable), not touched
/// (protected), default, retire. Lines with nothing to say are left out, except the move line.
///
/// Keyrings are named through `names` (see [`name_in`]).
pub fn summary_lines(
    summary: &ConsolidationSummary,
    target_label: &str,
    names: &HashMap<CollectionId, String>,
) -> Vec<SummaryLine> {
    let line = |kind, text: String| SummaryLine { kind, text };
    let items: usize = summary.steps.iter().map(|s| _step_items(&s.counts)).sum();
    let mut out = vec![if summary.steps.is_empty() {
        line(
            LineKind::Move,
            format!("Nothing to move into {target_label}"),
        )
    } else {
        line(
            LineKind::Move,
            format!(
                "Move {} from {} into {target_label}",
                count_noun(items, "item"),
                count_noun(summary.steps.len(), "keyring")
            ),
        )
    }];
    if !summary.delete_empty.is_empty() {
        let text = format!(
            "Delete {}",
            count_noun(summary.delete_empty.len(), "empty keyring")
        );
        out.push(line(LineKind::Delete, text));
    }
    let locked = summary
        .skipped
        .iter()
        .filter(|(_, _, r)| *r == SkipReason::Locked)
        .count();
    if locked > 0 {
        let text = format!("Skipped: {}", count_noun(locked, "locked keyring"));
        out.push(line(LineKind::Skipped, text));
    }
    let unreadable: Vec<String> = summary
        .skipped
        .iter()
        .filter(|(_, _, r)| matches!(r, SkipReason::Unreadable(_)))
        .map(|(id, label, _)| name_in(names, id, label))
        .collect();
    if !unreadable.is_empty() {
        let text = format!("Skipped: unreadable {}", unreadable.join(", "));
        out.push(line(LineKind::Unreadable, text));
    }
    let protected: Vec<String> = summary
        .skipped
        .iter()
        .filter(|(_, _, r)| matches!(r, SkipReason::Protected(_)))
        .map(|(id, label, _)| name_in(names, id, label))
        .collect();
    if !protected.is_empty() {
        let text = format!("Not touched: {} (protected)", protected.join(", "));
        out.push(line(LineKind::NotTouched, text));
    }
    if summary.set_default {
        out.push(line(
            LineKind::Default,
            format!("Set {target_label} as default"),
        ));
    }
    if !summary.orphan_files.is_empty() {
        let text = format!(
            "Retire {}",
            count_noun(summary.orphan_files.len(), "empty plaintext file")
        );
        out.push(line(LineKind::Retire, text));
    }
    out
}

/// Returns the counts of a finished move, e.g. `2 new, 1 already there, 0 replaced, 1 kept`.
fn _move_counts(report: &TransferReport) -> String {
    let mut text = format!(
        "{} new, {} already there, {} replaced, {} kept",
        report.created, report.duplicates, report.replaced, report.kept_target
    );
    if !report.failed.is_empty() {
        text.push_str(&format!(", {} failed", report.failed.len()));
    }
    text
}

/// Returns the rows of the result card: one per step outcome (moves and
/// deletes OK, a kept source TERTIARY, the failed step ERROR), then the
/// retired orphan files and those kept with their reason.
pub fn outcome_rows(
    report: &ConsolidationReport,
    retired: Option<&RetireBatchReport>,
) -> Vec<OutcomeRow> {
    let row = |tone, text: String| OutcomeRow { tone, text };
    let mut out: Vec<OutcomeRow> = report
        .outcomes
        .iter()
        .map(|o| match o {
            StepOutcome::Moved { source, report } => row(
                OutcomeTone::Ok,
                format!("Moved {source}: {}", _move_counts(report)),
            ),
            StepOutcome::Kept { source, remaining } => row(
                OutcomeTone::Kept,
                format!("Kept {source}: {} remain", count_noun(*remaining, "item")),
            ),
            StepOutcome::Deleted(label) => row(OutcomeTone::Ok, format!("Deleted {label}")),
            StepOutcome::DefaultSet => row(OutcomeTone::Ok, "Default keyring set".to_string()),
            StepOutcome::Failed { step, error } => {
                row(OutcomeTone::Failed, format!("{step} failed: {error}"))
            }
        })
        .collect();
    let Some(retired) = retired else {
        return out;
    };
    if !retired.removed.is_empty() {
        let text = format!(
            "Retired {}",
            count_noun(retired.removed.len(), "orphan file")
        );
        out.push(row(OutcomeTone::Ok, text));
    }
    for (name, reason) in &retired.kept {
        out.push(row(
            OutcomeTone::Kept,
            format!("Kept file {name}: {reason}"),
        ));
    }
    out
}

/// Returns the passphrases an apply of `summary` needs: the backup one as
/// judged by the worker on the files it backs up at plan time, the orphan
/// files one when files are retired. The worker still asks for any it finds
/// missing at apply time.
pub fn needs_passphrases(summary: &ConsolidationSummary) -> PassphraseNeeds {
    PassphraseNeeds {
        backup: summary.backup_needs_passphrase,
        orphan_files: !summary.orphan_files.is_empty(),
    }
}

/// Returns the number of empty plaintext orphan files of the last scan:
/// textual, plaintext, zero items and not served by the daemon.
pub fn orphan_count(files: &[KeyringFileInfo], live: &[CollectionInfo]) -> usize {
    files
        .iter()
        .filter(|f| f.format == KeyringFormat::Textual && f.plaintext)
        .filter(|f| f.item_count == Some(0))
        .filter(|f| retire_mode(f, live) == RetireMode::DeleteFile)
        .count()
}

/// Returns the default target: `login` when unlocked, else the first
/// unlocked keyring.
pub fn default_target(collections: &[CollectionInfo]) -> Option<CollectionId> {
    let login = collections.iter().find(|c| c.is_login && !c.locked);
    login
        .or_else(|| collections.iter().find(|c| !c.locked))
        .map(|c| c.id.clone())
}

/// Returns the role of keyring `c`: from the preview when there is one,
/// otherwise `Target` for the chosen target and `Locked` for locked ones.
pub fn keyring_role(
    summary: Option<&ConsolidationSummary>,
    target: Option<&CollectionId>,
    c: &CollectionInfo,
) -> Option<Role> {
    let Some(summary) = summary else {
        if target == Some(&c.id) {
            return Some(Role::Target);
        }
        return c.locked.then_some(Role::Locked);
    };
    if summary.target == c.id {
        return Some(Role::Target);
    }
    if summary.steps.iter().any(|s| s.source == c.id) {
        return Some(Role::Move);
    }
    if summary.delete_empty.iter().any(|(id, _)| id == &c.id) {
        return Some(Role::Delete);
    }
    let reason = &summary.skipped.iter().find(|(id, _, _)| id == &c.id)?.2;
    match reason {
        SkipReason::Locked => Some(Role::Locked),
        SkipReason::Unreadable(_) => Some(Role::Unreadable),
        SkipReason::Protected(_) => Some(Role::Protected),
        SkipReason::Target => Some(Role::Target),
    }
}

/// Passphrases already given for a plan, resent when the worker asks again.
#[derive(Default)]
struct KeptPassphrases {
    /// Plan they were given for.
    plan_id: Option<u64>,
    /// Backup passphrase.
    backup: Option<SecretValue>,
    /// Orphan files passphrase.
    orphan_files: Option<SecretValue>,
}

/// State of the Consolidate area: start card fields, the choices of the
/// open preview, expanded steps and the passphrases given for its plan.
#[derive(Default)]
pub struct ConsolidateView {
    /// Chosen target keyring.
    pub target: Option<CollectionId>,
    /// Retire the empty plaintext orphan files too.
    pub include_orphans: bool,
    /// Plan the choices belong to.
    plan_id: Option<u64>,
    /// One choice list per move step, one choice per conflict.
    pub choices: Vec<Vec<Choice>>,
    /// Move steps (by index) whose details are shown.
    expanded: BTreeSet<usize>,
    /// Passphrases given for the plan.
    kept: KeptPassphrases,
    /// Every locked keyring of the preview is listed (not only the first rows).
    show_all_locked: bool,
}

impl ConsolidateView {
    /// Follows the state: a new plan resets choices, expanded steps and the
    /// kept passphrases; a missing or locked target is replaced by the default.
    pub fn sync(&mut self, state: &AppState) {
        let usable = |id: &CollectionId| state.collections.iter().any(|c| &c.id == id && !c.locked);
        if !self.target.as_ref().is_some_and(usable) {
            self.target = default_target(&state.collections);
        }
        let preview = state.consolidation_preview.as_ref();
        let id = preview.map(|(id, _)| *id);
        if id == self.plan_id {
            return;
        }
        self.plan_id = id;
        self.choices = preview.map_or_else(Vec::new, |(_, summary)| {
            summary
                .steps
                .iter()
                .map(|s| default_choices(&s.conflicts))
                .collect()
        });
        self.expanded.clear();
        self.kept = KeptPassphrases::default();
    }

    /// Sets the choice of conflict `index` of step `step`.
    pub fn choose(&mut self, step: usize, index: usize, choice: Choice) {
        if let Some(slot) = self.choices.get_mut(step).and_then(|c| c.get_mut(index)) {
            *slot = choice;
        }
    }

    /// Shows or hides the details of step `step`.
    pub fn toggle_step(&mut self, step: usize) {
        if !self.expanded.remove(&step) {
            self.expanded.insert(step);
        }
    }

    /// Returns true when the details of step `step` are shown.
    pub fn is_expanded(&self, step: usize) -> bool {
        self.expanded.contains(&step)
    }

    /// Remembers the passphrases of an apply of the current plan, so a
    /// later request for another one resends them.
    pub fn remember(&mut self, cmd: &Command) {
        let Command::ApplyConsolidation {
            plan_id,
            backup_passphrase,
            orphan_files_passphrase,
            ..
        } = cmd
        else {
            return;
        };
        if Some(*plan_id) != self.plan_id {
            return;
        }
        self.kept.plan_id = Some(*plan_id);
        if backup_passphrase.is_some() {
            self.kept.backup = backup_passphrase.clone();
        }
        if orphan_files_passphrase.is_some() {
            self.kept.orphan_files = orphan_files_passphrase.clone();
        }
    }

    /// Drops the kept passphrases (the apply ended or its result was closed).
    pub fn forget_passphrases(&mut self) {
        self.kept = KeptPassphrases::default();
    }

    /// Returns the passphrases kept for `plan_id`: `(backup, orphan files)`.
    pub fn kept(&self, plan_id: u64) -> (Option<SecretValue>, Option<SecretValue>) {
        if self.kept.plan_id != Some(plan_id) {
            return (None, None);
        }
        (self.kept.backup.clone(), self.kept.orphan_files.clone())
    }

    /// Returns the command or dialog applying plan `plan_id`: the dialog
    /// asking the passphrases in `needs` that were not given yet, or the
    /// apply itself with the kept ones.
    pub fn apply_action(&self, plan_id: u64, needs: PassphraseNeeds) -> Action {
        let (backup, orphan_files) = self.kept(plan_id);
        let missing = PassphraseNeeds {
            backup: needs.backup && backup.is_none(),
            orphan_files: needs.orphan_files && orphan_files.is_none(),
        };
        if missing.any() {
            return Action::Open(DialogKind::consolidate_passphrases(
                plan_id,
                self.choices.clone(),
                missing,
                backup,
                orphan_files,
            ));
        }
        Action::Send(Command::ApplyConsolidation {
            plan_id,
            choices: self.choices.clone(),
            backup_passphrase: backup,
            orphan_files_passphrase: orphan_files,
        })
    }
}

/// Returns the label of collection `id`, or its path when unknown.
fn _label_of(state: &AppState, id: &CollectionId) -> String {
    state
        .collections
        .iter()
        .find(|c| &c.id == id)
        .map_or_else(|| id.0.clone(), |c| shown(state, c))
}

/// Returns the shown name of `c` among the listed collections.
fn shown(state: &AppState, c: &CollectionInfo) -> String {
    display_names(&state.collections)
        .remove(&c.id)
        .unwrap_or_else(|| display_name(c))
}

/// Renders one keyring row of the list (shown as `name`) with its role chip.
fn _list_row(ui: &mut Ui, c: &CollectionInfo, name: &str, role: Option<Role>) {
    let size = egui::vec2(ui.available_width(), ROW_HEIGHT);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    row_background(ui, rect, false, resp.hovered());
    let inner = rect.shrink2(egui::vec2(ROW_PADDING, 0.0));
    ui.scope_builder(
        egui::UiBuilder::new()
            .max_rect(inner)
            .layout(Layout::left_to_right(Align::Center)),
        |ui| {
            ui.vertical(|ui| {
                ui.add_space(4.0);
                ui.add(egui::Label::new(semibold(name, 14.0)).truncate());
                let detail = if c.locked {
                    "locked".to_string()
                } else {
                    count_noun(c.item_count, "item")
                };
                ui.label(muted_text(detail));
            });
            let Some(role) = role else {
                return;
            };
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let (text, color) = role.chip();
                chip(ui, text, color);
            });
        },
    );
}

/// Renders the keyring list of the area with the role of each keyring.
pub fn list(ui: &mut Ui, state: &AppState, view: &ConsolidateView) -> Option<Action> {
    field_label(ui, "Keyrings");
    ui.add_space(4.0);
    let summary = state.consolidation_preview.as_ref().map(|(_, s)| s);
    egui::ScrollArea::vertical()
        .id_salt("kring-consolidate-list")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            let names = display_names(&state.collections);
            for c in &state.collections {
                let role = keyring_role(summary, view.target.as_ref(), c);
                let name = names.get(&c.id).map_or("", String::as_str);
                _list_row(ui, c, name, role);
            }
        });
    None
}

/// Target combo: unlocked keyrings; locked ones disabled with "(locked)".
fn _target_combo(ui: &mut Ui, state: &AppState, target: &mut Option<CollectionId>) {
    let selected = target
        .as_ref()
        .map_or_else(|| MSG_NO_TARGET.to_string(), |id| _label_of(state, id));
    egui::ComboBox::from_id_salt("kring-consolidate-target")
        .selected_text(selected)
        .width(TARGET_WIDTH)
        .show_ui(ui, |ui| {
            let names = display_names(&state.collections);
            for c in &state.collections {
                let mut text = names.get(&c.id).cloned().unwrap_or_else(|| display_name(c));
                if c.locked {
                    text.push_str(" (locked)");
                }
                let checked = target.as_ref() == Some(&c.id);
                ui.add_enabled_ui(!c.locked, |ui| {
                    if ui.selectable_label(checked, text).clicked() {
                        *target = Some(c.id.clone());
                    }
                });
            }
        });
}

/// Renders the start card: target, orphan files option and `Preview`.
fn _start_card(
    ui: &mut Ui,
    state: &AppState,
    view: &mut ConsolidateView,
    gates: Gates,
) -> Option<Action> {
    let mut action = None;
    card(ui, |ui| {
        ui.spacing_mut().item_spacing.y = 6.0;
        ui.label(RichText::new(MSG_EXPLAIN).color(theme::TEXT).size(13.0));
        ui.label(muted_text(MSG_UNLOCK_HINT));
        ui.add_space(6.0);
        field_label(ui, "Target keyring");
        _target_combo(ui, state, &mut view.target);
        ui.add_space(4.0);
        let orphans = orphan_count(&state.files, &state.collections);
        let text = format!("Also retire empty plaintext orphan files ({orphans} found)");
        ui.checkbox(
            &mut view.include_orphans,
            RichText::new(text).color(theme::TEXT),
        );
        ui.add_space(6.0);
        let blocked = gates
            .write
            .or(view.target.is_none().then_some(MSG_NO_TARGET));
        if primary_button(ui, "Preview", blocked)
            && let Some(target) = view.target.clone()
        {
            action = Some(Action::Send(Command::PlanConsolidation {
                target,
                include_orphan_files: view.include_orphans,
            }));
        }
    });
    action
}

/// Returns the accent colour of a summary line.
fn _line_color(kind: LineKind) -> Color32 {
    match kind {
        LineKind::Move => theme::PRIMARY,
        LineKind::Delete | LineKind::Retire | LineKind::Skipped => theme::TERTIARY,
        LineKind::Unreadable => theme::ERROR,
        LineKind::NotTouched => theme::LABEL,
        LineKind::Default => theme::SECONDARY,
    }
}

/// Renders the expandable move steps under the move line.
fn _steps(
    ui: &mut Ui,
    names: &HashMap<CollectionId, String>,
    summary: &ConsolidationSummary,
    view: &mut ConsolidateView,
) {
    for (index, step) in summary.steps.iter().enumerate() {
        let open = view.is_expanded(index);
        let size = egui::vec2(ui.available_width(), STEP_ROW_HEIGHT);
        let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
        let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
        if resp.hovered() {
            let r = CornerRadius::same(theme::RADIUS_CTRL);
            ui.painter().rect_filled(rect, r, theme::INPUT_FILL_BLUE);
        }
        let ico = if open {
            Ico::ChevronDown
        } else {
            Ico::ChevronRight
        };
        let glyph = egui::Rect::from_min_size(rect.min, egui::vec2(STEP_ROW_HEIGHT, rect.height()));
        glyphs::paint(ui.painter(), glyph, ico, theme::LABEL);
        let text = format!(
            "{} - {}",
            name_in(names, &step.source, &step.label),
            count_noun(_step_items(&step.counts), "item")
        );
        ui.painter().text(
            egui::pos2(glyph.right() + 2.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            text,
            egui::FontId::new(13.0, theme::medium()),
            theme::TEXT,
        );
        if resp.clicked() {
            view.toggle_step(index);
        }
        if open {
            ui.horizontal(|ui| {
                ui.add_space(STEP_ROW_HEIGHT + 2.0);
                ui.label(muted_text(preview_header(&step.counts)));
            });
        }
    }
}

/// Renders the extra content of a summary line (the locked keyrings have
/// their own card, see [`locked_list::card`]).
fn _line_extra(
    ui: &mut Ui,
    kind: LineKind,
    names: &HashMap<CollectionId, String>,
    summary: &ConsolidationSummary,
    view: &mut ConsolidateView,
) {
    match kind {
        LineKind::Move => _steps(ui, names, summary, view),
        LineKind::Delete => {
            let names: Vec<String> = summary
                .delete_empty
                .iter()
                .map(|(id, label)| name_in(names, id, label))
                .collect();
            ui.label(muted_text(names.join(", ")));
        }
        LineKind::Retire => {
            ui.label(muted_text(summary.orphan_files.join(", ")));
        }
        LineKind::Unreadable => {
            for (id, label, reason) in &summary.skipped {
                let SkipReason::Unreadable(why) = reason else {
                    continue;
                };
                ui.label(muted_text(format!("{}: {why}", name_in(names, id, label))));
            }
        }
        LineKind::Skipped | LineKind::NotTouched | LineKind::Default => {}
    }
}

/// Renders the conflicts of every step with the shared conflict row.
fn _conflicts(
    ui: &mut Ui,
    state: &AppState,
    summary: &ConsolidationSummary,
    view: &mut ConsolidateView,
    target_label: &str,
) -> Option<Action> {
    if summary.conflict_count == 0 {
        return None;
    }
    let names = display_names(&state.collections);
    let mut action = None;
    ui.add_space(8.0);
    field_label(ui, "Conflicts");
    muted(ui, MSG_CONFLICTS);
    ui.add_space(4.0);
    for (step_index, step) in summary.steps.iter().enumerate() {
        if step.conflicts.is_empty() {
            continue;
        }
        let name = name_in(&names, &step.source, &step.label);
        ui.label(muted_text(format!("From {name}")));
        for (index, c) in step.conflicts.iter().enumerate() {
            let choice = view
                .choices
                .get(step_index)
                .and_then(|v| v.get(index))
                .copied()
                .unwrap_or(c.default_choice);
            match conflict_row(ui, state, c, choice, false, target_label) {
                Some(RowEvent::Choose(choice)) => view.choose(step_index, index, choice),
                Some(RowEvent::ToggleOffline) | None => {}
                Some(other) => action = other.secret_action(),
            }
        }
    }
    action
}

/// Returns the note of the passphrases the apply will ask for.
fn _passphrase_note(needs: PassphraseNeeds) -> Option<&'static str> {
    match (needs.backup, needs.orphan_files) {
        (true, true) => {
            Some("You will choose a passphrase for the backup and one for the retired files.")
        }
        (true, false) => {
            Some("Plaintext keyrings exist: you will choose a passphrase for the backup.")
        }
        (false, true) => Some("You will choose a passphrase for the retired files."),
        (false, false) => None,
    }
}

/// Renders the scrolled part of the preview: summary cards and conflicts.
fn _preview_body(
    ui: &mut Ui,
    state: &AppState,
    view: &mut ConsolidateView,
    summary: &ConsolidationSummary,
    gates: Gates,
) -> Option<Action> {
    let target_label = _label_of(state, &summary.target);
    let names = display_names(&state.collections);
    let mut action = None;
    for line in summary_lines(summary, &target_label, &names) {
        if line.kind == LineKind::Skipped {
            let entries = locked_list::locked_entries(summary, &names);
            let show_all = &mut view.show_all_locked;
            let found = locked_list::card(ui, &line.text, &entries, show_all, gates);
            action = found.or(action.take());
        } else {
            accent_card(ui, _line_color(line.kind), |ui| {
                ui.label(semibold(&line.text, 14.0));
                _line_extra(ui, line.kind, &names, summary, view);
            });
        }
        ui.add_space(6.0);
    }
    let found = _conflicts(ui, state, summary, view, &target_label);
    found.or(action)
}

/// Renders the fixed footer of the preview: the passphrase note, the
/// progress of a running apply, Cancel and the apply button.
fn _preview_footer(
    ui: &mut Ui,
    state: &AppState,
    view: &ConsolidateView,
    plan_id: u64,
    summary: &ConsolidationSummary,
    gates: Gates,
) -> Option<Action> {
    let mut action = None;
    let needs = needs_passphrases(summary);
    if let Some(text) = _passphrase_note(needs) {
        muted(ui, text);
    }
    if let Some((done, total)) = state.consolidation_progress {
        _progress(ui, done, total);
    }
    ui.add_space(4.0);
    let row = egui::vec2(ui.available_width(), FOOTER_ROW_HEIGHT);
    ui.allocate_ui_with_layout(row, Layout::right_to_left(Align::Center), |ui| {
        let blocked = if state.is_applying_consolidation() {
            Some(MSG_APPLYING)
        } else {
            gates.destructive()
        };
        if danger_button(ui, APPLY_TEXT, blocked) {
            action = Some(view.apply_action(plan_id, needs));
        }
        let busy = state.is_applying_consolidation().then_some(MSG_APPLYING);
        if secondary_button(ui, "Cancel", busy) {
            action = Some(Action::CloseConsolidationPreview);
        }
    });
    action
}

/// Renders the progress of the running apply as a thin bar.
fn _progress(ui: &mut Ui, done: usize, total: usize) {
    let fraction = if total == 0 {
        0.0
    } else {
        done.min(total) as f32 / total as f32
    };
    ui.add_space(6.0);
    ui.label(muted_text(format!("Step {done} of {total}")));
    let size = egui::vec2(ui.available_width(), PROGRESS_HEIGHT);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let r = CornerRadius::same(theme::RADIUS_CTRL);
    ui.painter().rect_filled(rect, r, theme::INPUT_FILL);
    let mut fill = rect;
    fill.set_width(rect.width() * fraction);
    ui.painter().rect_filled(fill, r, theme::PRIMARY);
}

/// Returns the colour of a result row.
fn _tone_color(tone: OutcomeTone) -> Color32 {
    match tone {
        OutcomeTone::Ok => theme::OK,
        OutcomeTone::Kept => theme::TERTIARY,
        OutcomeTone::Failed => theme::ERROR,
    }
}

/// Renders the result card of the last apply with the backup locations.
fn _result(
    ui: &mut Ui,
    state: &AppState,
    report: &ConsolidationReport,
    retired: Option<&RetireBatchReport>,
) -> Option<Action> {
    let (title, accent) = if report.completed {
        ("Consolidation complete", theme::OK)
    } else {
        ("Consolidation stopped", theme::ERROR)
    };
    let mut action = None;
    accent_card(ui, accent, |ui| {
        ui.spacing_mut().item_spacing.y = 4.0;
        ui.label(semibold(title, 16.0));
        ui.add_space(2.0);
        for row in outcome_rows(report, retired) {
            ui.label(
                RichText::new(row.text)
                    .color(_tone_color(row.tone))
                    .size(13.0),
            );
        }
        if !report.completed {
            muted(ui, "Nothing after the failed step ran.");
        }
        ui.add_space(4.0);
        for dir in &state.consolidation_backups {
            ui.label(muted_text(format!("Backup: {}", dir.display())));
        }
        ui.add_space(4.0);
        if secondary_button(ui, "Done", None) {
            action = Some(Action::DismissConsolidation);
        }
    });
    action
}

/// Renders the detail pane of the Consolidate area.
pub fn detail(
    ui: &mut Ui,
    state: &AppState,
    view: &mut ConsolidateView,
    gates: Gates,
) -> Option<Action> {
    view.sync(state);
    heading(ui, "Consolidate keyrings");
    ui.add_space(8.0);
    let mut action = None;
    let Some((plan_id, summary)) = &state.consolidation_preview else {
        egui::ScrollArea::vertical()
            .id_salt("kring-consolidate")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                action = match &state.last_consolidation {
                    Some((report, retired)) => _result(ui, state, report, retired.as_ref()),
                    None => _start_card(ui, state, view, gates),
                };
            });
        return action;
    };
    let body_height = (ui.available_height() - PREVIEW_FOOTER_HEIGHT).max(0.0);
    egui::ScrollArea::vertical()
        .id_salt("kring-consolidate-preview")
        .max_height(body_height)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            action = _preview_body(ui, state, view, summary, gates);
        });
    ui.add_space(8.0);
    let found = _preview_footer(ui, state, view, *plan_id, summary, gates);
    found.or(action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::{ConflictView, Event, StepSummary};
    use kring_core::model::LOGIN_COLLECTION_PATH;

    /// Builds a collection.
    fn col(path: &str, label: &str, locked: bool) -> CollectionInfo {
        CollectionInfo {
            id: CollectionId(path.into()),
            label: label.into(),
            locked,
            item_count: 0,
            aliases: vec![],
            is_login: path == LOGIN_COLLECTION_PATH,
            created: 0,
            modified: 0,
        }
    }

    /// Builds a conflict preselecting `choice`.
    fn conflict(choice: Choice) -> ConflictView {
        ConflictView {
            label_incoming: "a".into(),
            label_existing: "a".into(),
            modified_incoming: 2,
            modified_existing: 1,
            default_choice: choice,
            incoming_item: None,
            incoming_revealable: false,
            existing_item: None,
            existing_planned: true,
            offline_index: None,
        }
    }

    /// Builds a step from `source` with `create` new items and `conflicts`.
    fn step(source: &str, create: usize, conflicts: Vec<ConflictView>) -> StepSummary {
        StepSummary {
            source: CollectionId(source.into()),
            label: source.trim_start_matches("/c/").into(),
            counts: TransferCounts {
                create,
                duplicate: 1,
                conflict: conflicts.len(),
                ..TransferCounts::default()
            },
            conflicts,
        }
    }

    /// A summary with every kind of line.
    fn full_summary() -> ConsolidationSummary {
        ConsolidationSummary {
            target: CollectionId("/c/login".into()),
            steps: vec![
                step("/c/d2", 0, vec![]),
                step("/c/work", 2, vec![conflict(Choice::UseIncoming)]),
            ],
            delete_empty: vec![(CollectionId("/c/d3".into()), "Default_3".into())],
            skipped: vec![
                (
                    CollectionId("/c/login".into()),
                    "Login".into(),
                    SkipReason::Target,
                ),
                (
                    CollectionId("/c/d1".into()),
                    "Default_1".into(),
                    SkipReason::Locked,
                ),
                (
                    CollectionId("/c/session".into()),
                    String::new(),
                    SkipReason::Protected("session"),
                ),
                (
                    CollectionId("/c/d4".into()),
                    "Default_4".into(),
                    SkipReason::Unreadable("D-Bus error".into()),
                ),
            ],
            locked_count: 1,
            set_default: true,
            conflict_count: 1,
            orphan_files: vec!["empty_textual".into()],
            backup_needs_passphrase: false,
        }
    }

    /// Every line in order; the skipped line counts locked keyrings only and
    /// protected ones are listed apart; the target is not listed.
    #[test]
    fn summary_lines_cover_the_plan() {
        let lines = summary_lines(&full_summary(), "Login", &HashMap::new());
        let texts: Vec<_> = lines.iter().map(|l| (l.kind, l.text.as_str())).collect();
        assert_eq!(
            texts,
            [
                (LineKind::Move, "Move 5 items from 2 keyrings into Login"),
                (LineKind::Delete, "Delete 1 empty keyring"),
                (LineKind::Skipped, "Skipped: 1 locked keyring"),
                (LineKind::Unreadable, "Skipped: unreadable Default_4"),
                (LineKind::NotTouched, "Not touched: session (protected)"),
                (LineKind::Default, "Set Login as default"),
                (LineKind::Retire, "Retire 1 empty plaintext file"),
            ]
        );
    }

    /// An empty plan keeps only the move line.
    #[test]
    fn summary_lines_of_empty_plan() {
        let summary = ConsolidationSummary {
            steps: vec![],
            delete_empty: vec![],
            skipped: vec![],
            locked_count: 0,
            set_default: false,
            conflict_count: 0,
            orphan_files: vec![],
            backup_needs_passphrase: false,
            ..full_summary()
        };
        assert_eq!(
            summary_lines(&summary, "Login", &HashMap::new()),
            [SummaryLine {
                kind: LineKind::Move,
                text: "Nothing to move into Login".into()
            }]
        );
    }

    /// Moves and deletes are OK, a kept source TERTIARY, the failure ERROR;
    /// retired and kept orphan files follow.
    #[test]
    fn outcome_rows_tone_each_step() {
        let report = ConsolidationReport {
            outcomes: vec![
                StepOutcome::Moved {
                    source: "Work".into(),
                    report: TransferReport {
                        created: 2,
                        duplicates: 1,
                        ..TransferReport::default()
                    },
                },
                StepOutcome::DefaultSet,
                StepOutcome::Kept {
                    source: "Work".into(),
                    remaining: 1,
                },
                StepOutcome::Deleted("Default_3".into()),
                StepOutcome::Failed {
                    step: "Delete Default_2".into(),
                    error: "boom".into(),
                },
            ],
            completed: false,
        };
        let retired = RetireBatchReport {
            backup: None,
            removed: vec!["a".into(), "b".into()],
            kept: vec![("c".into(), "not empty".into())],
        };
        let rows = outcome_rows(&report, Some(&retired));
        let got: Vec<_> = rows.iter().map(|r| (r.tone, r.text.as_str())).collect();
        assert_eq!(
            got,
            [
                (
                    OutcomeTone::Ok,
                    "Moved Work: 2 new, 1 already there, 0 replaced, 0 kept"
                ),
                (OutcomeTone::Ok, "Default keyring set"),
                (OutcomeTone::Kept, "Kept Work: 1 item remain"),
                (OutcomeTone::Ok, "Deleted Default_3"),
                (OutcomeTone::Failed, "Delete Default_2 failed: boom"),
                (OutcomeTone::Ok, "Retired 2 orphan files"),
                (OutcomeTone::Kept, "Kept file c: not empty"),
            ]
        );
        assert_eq!(outcome_rows(&report, None).len(), 5);
    }

    /// Builds a file info.
    fn file(name: &str, plaintext: bool, items: Option<usize>) -> KeyringFileInfo {
        KeyringFileInfo {
            path: format!("/k/{name}.keyring").into(),
            name: name.into(),
            format: if plaintext {
                KeyringFormat::Textual
            } else {
                KeyringFormat::BinaryV0
            },
            size: 1,
            modified: 0,
            display_name: None,
            item_count: items,
            daemon_readable: None,
            plaintext,
            error: None,
        }
    }

    /// The backup needs a passphrase when the worker said so; the orphan
    /// files one when files are retired.
    #[test]
    fn needs_passphrases_from_plan() {
        let summary = full_summary();
        assert_eq!(
            needs_passphrases(&summary),
            PassphraseNeeds {
                backup: false,
                orphan_files: true
            }
        );
        let no_orphans = ConsolidationSummary {
            orphan_files: vec![],
            backup_needs_passphrase: true,
            ..full_summary()
        };
        let needs = needs_passphrases(&no_orphans);
        assert!(needs.backup && !needs.orphan_files && needs.any());
        let neither = ConsolidationSummary {
            backup_needs_passphrase: false,
            ..no_orphans
        };
        assert!(!needs_passphrases(&neither).any());
    }

    /// Orphans are empty plaintext files the daemon does not serve.
    #[test]
    fn orphan_count_skips_live_and_non_empty() {
        let files = [
            file("old", true, Some(0)),
            file("full", true, Some(2)),
            file("bin", false, Some(0)),
            file("live", true, Some(0)),
        ];
        let live = [col(
            "/org/freedesktop/secrets/collection/live",
            "live",
            false,
        )];
        assert_eq!(orphan_count(&files, &live), 1);
    }

    /// login wins when unlocked; otherwise the first unlocked keyring.
    #[test]
    fn default_target_prefers_unlocked_login() {
        let cols = [
            col("/c/work", "Work", false),
            col(LOGIN_COLLECTION_PATH, "Login", false),
        ];
        assert_eq!(
            default_target(&cols).map(|c| c.0),
            Some(LOGIN_COLLECTION_PATH.to_string())
        );
        let cols = [
            col(LOGIN_COLLECTION_PATH, "Login", true),
            col("/c/a", "a", true),
            col("/c/work", "Work", false),
        ];
        assert_eq!(default_target(&cols).map(|c| c.0), Some("/c/work".into()));
        assert!(default_target(&[col("/c/a", "a", true)]).is_none());
    }

    /// Roles come from the preview, or from the target and lock state before it.
    #[test]
    fn roles_follow_preview() {
        let summary = full_summary();
        let role = |path: &str| keyring_role(Some(&summary), None, &col(path, "x", false));
        assert_eq!(role("/c/login"), Some(Role::Target));
        assert_eq!(role("/c/work"), Some(Role::Move));
        assert_eq!(role("/c/d3"), Some(Role::Delete));
        assert_eq!(role("/c/d1"), Some(Role::Locked));
        assert_eq!(role("/c/session"), Some(Role::Protected));
        assert_eq!(role("/c/d4"), Some(Role::Unreadable));
        assert_eq!(role("/c/other"), None);
        let target = CollectionId("/c/a".into());
        assert_eq!(
            keyring_role(None, Some(&target), &col("/c/a", "a", false)),
            Some(Role::Target)
        );
        assert_eq!(
            keyring_role(None, Some(&target), &col("/c/b", "b", true)),
            Some(Role::Locked)
        );
    }

    /// Choices start from the preview per step and reset on a new plan; the
    /// target defaults to login.
    #[test]
    fn view_follows_plan() {
        let mut s = AppState::default();
        s.apply(Event::Collections(vec![col(
            LOGIN_COLLECTION_PATH,
            "Login",
            false,
        )]));
        let mut v = ConsolidateView::default();
        v.sync(&s);
        assert_eq!(
            v.target.as_ref().map(|t| t.0.as_str()),
            Some(LOGIN_COLLECTION_PATH)
        );
        s.apply(Event::ConsolidationPreview {
            plan_id: 1,
            summary: full_summary(),
        });
        v.sync(&s);
        assert_eq!(v.choices, [vec![], vec![Choice::UseIncoming]]);
        v.choose(1, 0, Choice::KeepTarget);
        v.choose(5, 0, Choice::KeepTarget);
        v.toggle_step(0);
        v.sync(&s);
        assert_eq!(v.choices[1], [Choice::KeepTarget]);
        assert!(v.is_expanded(0));
        s.apply(Event::ConsolidationPreview {
            plan_id: 2,
            summary: full_summary(),
        });
        v.sync(&s);
        assert_eq!(v.choices[1], [Choice::UseIncoming]);
        assert!(!v.is_expanded(0));
    }

    /// The apply asks only the passphrases not given yet, keeping the
    /// choices; with all of them it sends the apply.
    #[test]
    fn apply_asks_only_missing_passphrases() {
        let mut s = AppState::default();
        s.apply(Event::ConsolidationPreview {
            plan_id: 1,
            summary: full_summary(),
        });
        let mut v = ConsolidateView::default();
        v.sync(&s);
        let both = PassphraseNeeds {
            backup: true,
            orphan_files: true,
        };
        let action = v.apply_action(1, both);
        assert!(matches!(
            action,
            Action::Open(DialogKind::ConsolidatePassphrases {
                ask_backup: true,
                ask_orphan_files: true,
                ..
            })
        ));
        v.remember(&Command::ApplyConsolidation {
            plan_id: 1,
            choices: vec![],
            backup_passphrase: None,
            orphan_files_passphrase: Some(SecretValue::from_text("o")),
        });
        let action = v.apply_action(1, both);
        assert!(matches!(
            &action,
            Action::Open(DialogKind::ConsolidatePassphrases {
                ask_backup: true,
                ask_orphan_files: false,
                kept_orphan_files: Some(_),
                choices,
                ..
            }) if choices == &[vec![], vec![Choice::UseIncoming]]
        ));
        v.remember(&Command::ApplyConsolidation {
            plan_id: 1,
            choices: vec![],
            backup_passphrase: Some(SecretValue::from_text("b")),
            orphan_files_passphrase: None,
        });
        let action = v.apply_action(1, both);
        assert!(matches!(
            action,
            Action::Send(Command::ApplyConsolidation {
                plan_id: 1,
                backup_passphrase: Some(_),
                orphan_files_passphrase: Some(_),
                ..
            })
        ));
        assert!(matches!(v.kept(9), (None, None)), "other plans get nothing");
        assert!(matches!(v.kept(1), (Some(_), Some(_))));
        v.forget_passphrases();
        assert!(matches!(v.kept(1), (None, None)));
        v.remember(&Command::ApplyConsolidation {
            plan_id: 1,
            choices: vec![],
            backup_passphrase: Some(SecretValue::from_text("b")),
            orphan_files_passphrase: Some(SecretValue::from_text("o")),
        });
        let none = v.apply_action(9, PassphraseNeeds::default());
        assert!(matches!(
            none,
            Action::Send(Command::ApplyConsolidation {
                backup_passphrase: None,
                ..
            })
        ));
    }

    /// Keyrings are named from the disambiguated names, else from their label.
    #[test]
    fn name_in_prefers_shown_names() {
        let id = CollectionId("/org/freedesktop/secrets/collection/Default_5f10".into());
        let mut names = HashMap::new();
        assert_eq!(name_in(&names, &id, "Default"), "Default");
        assert_eq!(name_in(&names, &id, " "), "Default_10");
        names.insert(id.clone(), "Default · Default_10".to_string());
        assert_eq!(name_in(&names, &id, "Default"), "Default · Default_10");
    }
}
