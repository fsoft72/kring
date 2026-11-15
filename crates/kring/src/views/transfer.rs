//! Copy / Move of items: the selection helpers, the target picker data and
//! the conflict preview dialog.
//!
//! The preview holds no secrets: each side of a conflict is revealed on
//! demand (`RevealSecret` for live items, `AppState::file_items` for the
//! imported keyring file) and every revealed value is dropped when the
//! dialog closes.

use std::collections::BTreeSet;

use eframe::egui::{self, CornerRadius, RichText, Sense, Stroke, StrokeKind, Ui};
use kring_core::model::{CollectionId, CollectionInfo, ItemId};
use kring_core::transfer::apply::TransferMode;
use kring_core::transfer::plan::{Choice, TransferCounts};

use crate::app_state::{AppState, TransferPreview};
use crate::local_time;
use crate::secret_display::{SecretView, secret_display};
use crate::ui::glyphs::Ico;
use crate::ui::theme;
use crate::ui::widgets::{
    card_frame, chip, danger_button, field_label, ico_button, muted, note, primary_button,
    secondary_button, semibold,
};
use crate::views::collection::display_name;
use crate::views::dialogs::{ImportTarget, styled_modal};
use crate::views::item_detail::value_box;
use crate::views::{Action, Gates, MSG_NO_PROVIDER};
use crate::worker::{Command, ConflictView};

/// Id of the preview modal.
const PREVIEW_MODAL_ID: &str = "kring-transfer-preview";
/// Width of the preview content.
const PREVIEW_WIDTH: f32 = 760.0;
/// Maximum height of the scrolled conflict list.
const PREVIEW_LIST_HEIGHT: f32 = 420.0;
/// Room taken by the eye button next to a secret.
const EYE_ROOM: f32 = 36.0;
/// Height of a choice button.
const CHOICE_HEIGHT: f32 = 30.0;
/// Radius of the radio mark of a choice button.
const RADIO_RADIUS: f32 = 6.0;
/// Size of dialog titles.
const TITLE_SIZE: f32 = 18.0;
/// Chip marking the newer side of a conflict.
const CHIP_NEWER: &str = "newer";
/// Shown instead of a secret that only the worker holds (archive items).
const MSG_NOT_AVAILABLE: &str = "not available";
/// Shown instead of the secret of an item an earlier step creates.
const MSG_PLANNED: &str = "will be created by an earlier step";
/// Tooltip of Copy / Move when no other keyring is unlocked.
const MSG_NO_OTHER_TARGET: &str = "Unlock another keyring first";
/// Tooltip of Apply while the apply runs.
const MSG_APPLYING: &str = "Applying...";
/// Note of a move preview.
const MSG_MOVE: &str = "Moved items are removed from their keyring once they are safely in \
     the target.";
/// Text of a preview without conflicts.
const MSG_NO_CONFLICTS: &str = "No conflicts: existing items in the target stay as they are.";
/// Explanation above the conflict list.
const MSG_CONFLICTS: &str = "Same attributes with another secret. Choose the secret to keep \
     for each item.";

/// Side of a conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The item already in the target.
    Existing,
    /// The item being copied or moved.
    Incoming,
}

/// Checks `id` when unchecked, unchecks it when checked.
pub fn selection_toggle(selection: &mut Vec<ItemId>, id: &ItemId) {
    if let Some(pos) = selection.iter().position(|s| s == id) {
        selection.remove(pos);
        return;
    }
    selection.push(id.clone());
}

/// Returns the count line of a preview, e.g.
/// `3 new - 2 already there - 1 conflict - 0 without secret`, followed by
/// `- N skipped in batch` when the batch repeats an item.
pub fn preview_header(counts: &TransferCounts) -> String {
    let plural = if counts.conflict == 1 { "" } else { "s" };
    let mut text = format!(
        "{} new - {} already there - {} conflict{plural} - {} without secret",
        counts.create, counts.duplicate, counts.conflict, counts.no_secret
    );
    if counts.same_batch > 0 {
        text.push_str(&format!(" - {} skipped in batch", counts.same_batch));
    }
    text
}

/// Returns true when applying changes or deletes existing data (a move, or
/// any conflict resolved with the incoming secret): it needs a backup first.
pub fn apply_is_destructive(mode: TransferMode, choices: &[Choice]) -> bool {
    mode == TransferMode::Move || choices.contains(&Choice::UseIncoming)
}

/// Returns the preselected choice of every conflict, in order.
pub fn default_choices(conflicts: &[ConflictView]) -> Vec<Choice> {
    conflicts.iter().map(|c| c.default_choice).collect()
}

/// Returns the keyrings offered as transfer targets: every collection but
/// `current`, locked ones included (shown disabled).
pub fn transfer_targets(
    collections: &[CollectionInfo],
    current: Option<&CollectionId>,
) -> Vec<ImportTarget> {
    collections
        .iter()
        .filter(|c| Some(&c.id) != current)
        .map(|c| ImportTarget {
            id: c.id.clone(),
            label: display_name(c),
            locked: c.locked,
        })
        .collect()
}

/// Returns the side modified later, or `None` on a tie.
pub fn newer_side(c: &ConflictView) -> Option<Side> {
    if c.modified_existing == c.modified_incoming {
        return None;
    }
    if c.modified_existing > c.modified_incoming {
        return Some(Side::Existing);
    }
    Some(Side::Incoming)
}

/// Returns why "Copy to..." is disabled for items of `current`: no provider,
/// or no other unlocked keyring to receive them.
pub fn copy_blocked(state: &AppState, current: &CollectionId) -> Option<&'static str> {
    if state.provider.is_none() {
        return Some(MSG_NO_PROVIDER);
    }
    let other = state
        .collections
        .iter()
        .any(|c| &c.id != current && !c.locked);
    (!other).then_some(MSG_NO_OTHER_TARGET)
}

/// Returns the button text of Apply.
pub fn apply_label(destructive: bool) -> &'static str {
    if destructive {
        "Apply (backup first)"
    } else {
        "Apply"
    }
}

/// Dialog state of the open preview: the user's choices and which offline
/// secrets are shown. Kept while a passphrase is asked.
#[derive(Debug, Default)]
pub struct TransferView {
    /// Plan the state belongs to.
    plan_id: Option<u64>,
    /// One choice per conflict, in order.
    pub choices: Vec<Choice>,
    /// Conflicts (by index) whose offline incoming secret is shown.
    shown_offline: BTreeSet<usize>,
}

impl TransferView {
    /// Resets to the preselected choices when another plan is previewed, and
    /// forgets everything when no preview is open.
    pub fn sync(&mut self, preview: Option<&TransferPreview>) {
        let id = preview.map(|p| p.plan_id);
        if id == self.plan_id {
            return;
        }
        self.plan_id = id;
        self.choices = preview.map_or_else(Vec::new, |p| default_choices(&p.conflicts));
        self.shown_offline.clear();
    }

    /// Sets the choice of conflict `index`.
    pub fn choose(&mut self, index: usize, choice: Choice) {
        if let Some(slot) = self.choices.get_mut(index) {
            *slot = choice;
        }
    }

    /// Shows or hides the offline incoming secret of conflict `index`.
    pub fn toggle_offline(&mut self, index: usize) {
        if !self.shown_offline.remove(&index) {
            self.shown_offline.insert(index);
        }
    }

    /// Returns true when the offline incoming secret of conflict `index` is shown.
    pub fn is_offline_shown(&self, index: usize) -> bool {
        self.shown_offline.contains(&index)
    }
}

/// How one side of a conflict shows its secret.
enum SideSecret {
    /// A live item, revealed with `RevealSecret`; `Some` when revealed.
    Live(ItemId, Option<SecretView>),
    /// An item of the imported file; `Some` when shown.
    Offline(Option<SecretView>),
    /// No secret can be shown; the reason replaces the box.
    Unavailable(&'static str),
}

/// What was clicked on one side of a conflict.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SideClick {
    /// Nothing.
    None,
    /// The choice button of the side.
    Choice,
    /// The eye next to the secret.
    Eye,
}

/// One side of a conflict, ready to render.
struct SideView<'a> {
    /// Uppercase heading, e.g. `In Work`.
    heading: String,
    /// Item label.
    label: &'a str,
    /// Modification time, unix seconds.
    modified: u64,
    /// True when this side was modified later.
    newer: bool,
    /// Secret display.
    secret: SideSecret,
    /// Text of the choice button.
    choice_text: &'static str,
    /// True when this side is the chosen one.
    chosen: bool,
}

/// Builds the secret display of the target side of `c`.
fn _existing_secret(state: &AppState, c: &ConflictView) -> SideSecret {
    if c.existing_planned {
        return SideSecret::Unavailable(MSG_PLANNED);
    }
    let Some(id) = &c.existing_item else {
        return SideSecret::Unavailable(MSG_NOT_AVAILABLE);
    };
    let shown = state.transfer_secret(id).map(secret_display);
    SideSecret::Live(id.clone(), shown)
}

/// Builds the secret display of the incoming side of conflict `index`.
fn _incoming_secret(
    state: &AppState,
    view: &TransferView,
    index: usize,
    c: &ConflictView,
) -> SideSecret {
    if !c.incoming_revealable {
        return SideSecret::Unavailable(MSG_NOT_AVAILABLE);
    }
    if let Some(id) = &c.incoming_item {
        let shown = state.transfer_secret(id).map(secret_display);
        return SideSecret::Live(id.clone(), shown);
    }
    let Some(item) = state.offline_incoming(c) else {
        return SideSecret::Unavailable(MSG_NOT_AVAILABLE);
    };
    let shown = view
        .is_offline_shown(index)
        .then(|| secret_display(&item.secret));
    SideSecret::Offline(shown)
}

/// Paints a full-width choice button with a radio mark; returns true when clicked.
fn _choice_button(ui: &mut Ui, text: &str, chosen: bool) -> bool {
    let size = egui::vec2(ui.available_width(), CHOICE_HEIGHT);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    let p = ui.painter();
    let r = CornerRadius::same(theme::RADIUS_CTRL);
    let (fill, border) = match (chosen, resp.hovered()) {
        (true, _) => (theme::INPUT_FILL_BLUE, theme::PRIMARY),
        (false, true) => (theme::FIELD_ROW_BG, theme::SECONDARY.gamma_multiply(0.6)),
        (false, false) => (theme::FIELD_ROW_BG, theme::BUTTON_BORDER),
    };
    p.rect_filled(rect, r, fill);
    p.rect_stroke(rect, r, Stroke::new(1.0_f32, border), StrokeKind::Inside);
    let center = egui::pos2(rect.left() + 12.0 + RADIO_RADIUS, rect.center().y);
    let ring = if chosen {
        theme::SECONDARY
    } else {
        theme::LABEL
    };
    p.circle_stroke(center, RADIO_RADIUS, Stroke::new(1.5_f32, ring));
    if chosen {
        p.circle_filled(center, RADIO_RADIUS - 3.0, theme::SECONDARY);
    }
    let color = if chosen { theme::TEXT } else { theme::LABEL };
    let galley = p.layout_no_wrap(
        text.to_string(),
        egui::FontId::new(13.0, theme::semibold()),
        color,
    );
    let pos = egui::pos2(
        center.x + RADIO_RADIUS + 8.0,
        rect.center().y - galley.size().y / 2.0,
    );
    p.galley(pos, galley, color);
    resp.clicked()
}

/// Renders the secret of a side: masked box with an eye, or the reason it
/// cannot be shown. Returns true when the eye was clicked.
fn _side_secret(ui: &mut Ui, secret: &SideSecret) -> bool {
    let shown = match secret {
        SideSecret::Live(_, shown) | SideSecret::Offline(shown) => shown.as_ref(),
        SideSecret::Unavailable(reason) => {
            let reason = RichText::new(*reason).italics().color(theme::MUTED);
            ui.add_sized([ui.available_width(), 34.0], egui::Label::new(reason));
            return false;
        }
    };
    let mut clicked = false;
    ui.horizontal(|ui| {
        value_box(ui, shown, ui.available_width() - EYE_ROOM);
        let (ico, tip) = if shown.is_some() {
            (Ico::EyeOff, "Hide")
        } else {
            (Ico::Eye, "Show")
        };
        clicked = ico_button(ui, ico, tip, None, false);
    });
    clicked
}

/// Renders one side of a conflict; returns what was clicked.
fn _side(ui: &mut Ui, side: &SideView<'_>) -> SideClick {
    ui.horizontal(|ui| {
        field_label(ui, &side.heading);
        if side.newer {
            chip(ui, CHIP_NEWER, theme::OK);
        }
    });
    ui.add(egui::Label::new(semibold(side.label, 14.0)).truncate());
    let modified = local_time::format_unix(side.modified, local_time::offset());
    muted(ui, &format!("Modified {modified}"));
    ui.add_space(4.0);
    let eye = _side_secret(ui, &side.secret);
    ui.add_space(6.0);
    if _choice_button(ui, side.choice_text, side.chosen) {
        return SideClick::Choice;
    }
    if eye {
        return SideClick::Eye;
    }
    SideClick::None
}

/// Returns the action of an eye click on a side.
fn _eye_action(secret: &SideSecret) -> Option<Action> {
    match secret {
        SideSecret::Live(id, None) => Some(Action::Send(Command::RevealSecret(id.clone()))),
        SideSecret::Live(id, Some(_)) => Some(Action::HideTransferSecret(id.clone())),
        SideSecret::Offline(_) | SideSecret::Unavailable(_) => None,
    }
}

/// Renders conflict `index` as a card with the target side on the left and
/// the incoming side on the right; returns the action to run.
fn _conflict_row(
    ui: &mut Ui,
    state: &AppState,
    view: &mut TransferView,
    index: usize,
    c: &ConflictView,
    target_label: &str,
) -> Option<Action> {
    let newer = newer_side(c);
    let choice = view.choices.get(index).copied().unwrap_or(c.default_choice);
    let existing = SideView {
        heading: format!("In {target_label}"),
        label: &c.label_existing,
        modified: c.modified_existing,
        newer: newer == Some(Side::Existing),
        secret: _existing_secret(state, c),
        choice_text: "Keep current",
        chosen: choice == Choice::KeepTarget,
    };
    let incoming = SideView {
        heading: "Incoming".to_string(),
        label: &c.label_incoming,
        modified: c.modified_incoming,
        newer: newer == Some(Side::Incoming),
        secret: _incoming_secret(state, view, index, c),
        choice_text: "Use incoming",
        chosen: choice == Choice::UseIncoming,
    };
    let mut clicks = (SideClick::None, SideClick::None);
    card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.columns(2, |cols| {
            cols[0].spacing_mut().item_spacing.y = 4.0;
            cols[1].spacing_mut().item_spacing.y = 4.0;
            clicks.0 = _side(&mut cols[0], &existing);
            clicks.1 = _side(&mut cols[1], &incoming);
        });
    });
    match clicks {
        (SideClick::Choice, _) => view.choose(index, Choice::KeepTarget),
        (_, SideClick::Choice) => view.choose(index, Choice::UseIncoming),
        (SideClick::Eye, _) => return _eye_action(&existing.secret),
        (_, SideClick::Eye) => {
            if matches!(incoming.secret, SideSecret::Offline(_)) {
                view.toggle_offline(index);
                return None;
            }
            return _eye_action(&incoming.secret);
        }
        _ => {}
    }
    None
}

/// Renders the title, the counts and the conflict list of `preview`.
fn _preview_body(
    ui: &mut Ui,
    state: &AppState,
    view: &mut TransferView,
    preview: &TransferPreview,
    target_label: &str,
) -> Option<Action> {
    let verb = match preview.mode {
        TransferMode::Copy => "Copy",
        TransferMode::Move => "Move",
    };
    ui.label(semibold(
        format!("{verb} into \"{target_label}\""),
        TITLE_SIZE,
    ));
    ui.add_space(2.0);
    ui.label(RichText::new(preview_header(&preview.counts)).color(theme::TEXT));
    if preview.mode == TransferMode::Move {
        ui.add_space(4.0);
        note(ui, theme::TERTIARY, MSG_MOVE, theme::TERTIARY);
    }
    ui.add_space(8.0);
    if preview.conflicts.is_empty() {
        muted(ui, MSG_NO_CONFLICTS);
        return None;
    }
    field_label(ui, "Conflicts");
    muted(ui, MSG_CONFLICTS);
    ui.add_space(4.0);
    let mut action = None;
    egui::ScrollArea::vertical()
        .id_salt("kring-transfer-conflicts")
        .max_height(PREVIEW_LIST_HEIGHT)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 8.0;
            for (index, c) in preview.conflicts.iter().enumerate() {
                let found = _conflict_row(ui, state, view, index, c, target_label);
                action = found.or(action.take());
            }
        });
    action
}

/// Renders the conflict preview modal of the open transfer preview, if any;
/// returns the action to run (close, apply, reveal or hide a secret).
pub fn show(
    ctx: &egui::Context,
    state: &AppState,
    view: &mut TransferView,
    gates: Gates,
) -> Option<Action> {
    let preview = state.transfer_preview.as_ref()?;
    view.sync(Some(preview));
    let target_label = state
        .collections
        .iter()
        .find(|c| c.id == preview.target)
        .map_or_else(|| preview.target.0.clone(), display_name);
    let destructive = apply_is_destructive(preview.mode, &view.choices);
    let blocked = if state.is_applying_transfer() {
        Some(MSG_APPLYING)
    } else if destructive {
        gates.write
    } else {
        None
    };
    let mut action = None;
    let (mut apply, mut cancel) = (false, false);
    let response = styled_modal(ctx, PREVIEW_MODAL_ID).show(ctx, |ui| {
        ui.set_width(PREVIEW_WIDTH);
        action = _preview_body(ui, state, view, preview, &target_label);
        ui.add_space(12.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let label = apply_label(destructive);
            apply = if destructive {
                danger_button(ui, label, blocked)
            } else {
                primary_button(ui, label, blocked)
            };
            cancel = secondary_button(ui, "Cancel", None);
        });
    });
    if cancel || response.should_close() {
        return Some(Action::CloseTransferPreview);
    }
    if apply {
        return Some(Action::ApplyTransfer);
    }
    action
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a conflict view preselecting `choice`.
    fn conflict(choice: Choice) -> ConflictView {
        ConflictView {
            label_incoming: "in".into(),
            label_existing: "ex".into(),
            modified_incoming: 2,
            modified_existing: 1,
            default_choice: choice,
            incoming_item: None,
            incoming_revealable: false,
            existing_item: Some(ItemId("/c/t/1".into())),
            existing_planned: false,
            offline_index: None,
        }
    }

    /// Builds a collection.
    fn col(path: &str, label: &str, locked: bool) -> CollectionInfo {
        CollectionInfo {
            id: CollectionId(path.into()),
            label: label.into(),
            locked,
            item_count: 0,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        }
    }

    /// Toggling adds, a second toggle removes; other ids are kept in order.
    #[test]
    fn selection_toggle_adds_and_removes() {
        let a = ItemId("/c/a/1".into());
        let b = ItemId("/c/a/2".into());
        let mut sel = Vec::new();
        selection_toggle(&mut sel, &a);
        selection_toggle(&mut sel, &b);
        assert_eq!(sel, [a.clone(), b.clone()]);
        selection_toggle(&mut sel, &a);
        assert_eq!(sel, std::slice::from_ref(&b));
        selection_toggle(&mut sel, &b);
        assert!(sel.is_empty());
    }

    /// The header counts new, duplicate, conflict and secretless items;
    /// same-batch skips appear only when there are some.
    #[test]
    fn preview_header_counts() {
        let counts = TransferCounts {
            create: 3,
            duplicate: 2,
            conflict: 1,
            no_secret: 0,
            same_batch: 0,
        };
        assert_eq!(
            preview_header(&counts),
            "3 new - 2 already there - 1 conflict - 0 without secret"
        );
        let more = TransferCounts {
            conflict: 2,
            same_batch: 1,
            ..counts
        };
        assert_eq!(
            preview_header(&more),
            "3 new - 2 already there - 2 conflicts - 0 without secret - 1 skipped in batch"
        );
    }

    /// Move, or any incoming secret, is destructive; a plain copy is not.
    #[test]
    fn destructive_when_move_or_use_incoming() {
        let keep = [Choice::KeepTarget, Choice::KeepTarget];
        assert!(!apply_is_destructive(TransferMode::Copy, &keep));
        assert!(!apply_is_destructive(TransferMode::Copy, &[]));
        assert!(apply_is_destructive(TransferMode::Move, &[]));
        let mixed = [Choice::KeepTarget, Choice::UseIncoming];
        assert!(apply_is_destructive(TransferMode::Copy, &mixed));
    }

    /// Default choices follow the preview, in order.
    #[test]
    fn default_choices_follow_preview() {
        let conflicts = [conflict(Choice::UseIncoming), conflict(Choice::KeepTarget)];
        assert_eq!(
            default_choices(&conflicts),
            [Choice::UseIncoming, Choice::KeepTarget]
        );
        assert!(default_choices(&[]).is_empty());
    }

    /// The newer side is marked; ties mark none.
    #[test]
    fn newer_side_marks_later_modification() {
        let mut c = conflict(Choice::UseIncoming);
        assert_eq!(newer_side(&c), Some(Side::Incoming));
        c.modified_existing = 5;
        assert_eq!(newer_side(&c), Some(Side::Existing));
        c.modified_incoming = 5;
        assert_eq!(newer_side(&c), None);
        assert_eq!(apply_label(true), "Apply (backup first)");
        assert_eq!(apply_label(false), "Apply");
    }

    /// Choices start from the preview, survive frames of the same plan and
    /// reset on another plan; no preview forgets everything.
    #[test]
    fn view_keeps_choices_per_plan() {
        let preview = |plan_id: u64| TransferPreview {
            plan_id,
            target: CollectionId("/c/t".into()),
            mode: TransferMode::Copy,
            counts: TransferCounts::default(),
            conflicts: vec![conflict(Choice::KeepTarget), conflict(Choice::UseIncoming)],
        };
        let mut v = TransferView::default();
        v.sync(Some(&preview(1)));
        assert_eq!(v.choices, [Choice::KeepTarget, Choice::UseIncoming]);
        v.choose(0, Choice::UseIncoming);
        v.choose(9, Choice::KeepTarget);
        v.toggle_offline(1);
        v.sync(Some(&preview(1)));
        assert_eq!(v.choices, [Choice::UseIncoming, Choice::UseIncoming]);
        assert!(v.is_offline_shown(1));
        v.sync(Some(&preview(2)));
        assert_eq!(v.choices, [Choice::KeepTarget, Choice::UseIncoming]);
        assert!(!v.is_offline_shown(1));
        v.toggle_offline(0);
        v.sync(None);
        assert!(v.choices.is_empty() && !v.is_offline_shown(0));
    }

    /// Copy needs a provider and another unlocked keyring.
    #[test]
    fn copy_needs_another_unlocked_keyring() {
        use crate::worker::Event;
        use kring_core::provider::{ProviderInfo, ProviderKind};
        let current = CollectionId("/c/login".into());
        let mut s = AppState::default();
        s.apply(Event::Collections(vec![
            col("/c/login", "Login", false),
            col("/c/work", "Work", true),
        ]));
        assert_eq!(copy_blocked(&s, &current), Some(MSG_NO_PROVIDER));
        s.apply(Event::Provider(ProviderInfo {
            kind: ProviderKind::GnomeKeyring,
            pid: None,
            process_name: None,
            competitors: vec![],
            has_master_password_iface: true,
        }));
        assert_eq!(copy_blocked(&s, &current), Some(MSG_NO_OTHER_TARGET));
        s.apply(Event::Collections(vec![
            col("/c/login", "Login", false),
            col("/c/work", "Work", false),
        ]));
        assert_eq!(copy_blocked(&s, &current), None);
    }

    /// Targets exclude the current keyring and keep locked ones (disabled).
    #[test]
    fn targets_exclude_current() {
        let cols = [
            col("/c/login", "Login", false),
            col("/c/work", "Work", true),
            col("/c/d1", "", false),
        ];
        let current = CollectionId("/c/login".into());
        let targets = transfer_targets(&cols, Some(&current));
        let labels: Vec<_> = targets
            .iter()
            .map(|t| (t.label.as_str(), t.locked))
            .collect();
        assert_eq!(labels, [("Work", true), ("d1", false)]);
        assert_eq!(transfer_targets(&cols, None).len(), 3);
    }
}
