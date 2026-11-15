//! Conflict row shared by the transfer preview dialog and the consolidation
//! preview: the target side on the left, the incoming side on the right,
//! each with its label, modification time, masked secret (eye to reveal)
//! and a choice button.
//!
//! Secrets are never held here: live sides are revealed through
//! [`Action::RevealPreviewSecret`] into `AppState::transfer_revealed`, the
//! offline side of a keyring file import comes from `AppState::file_items`.

use eframe::egui::{self, CornerRadius, RichText, Sense, Stroke, StrokeKind, Ui};
use kring_core::model::ItemId;
use kring_core::transfer::plan::Choice;
use time::UtcOffset;

use crate::app_state::AppState;
use crate::local_time;
use crate::secret_display::{SecretView, secret_display};
use crate::ui::glyphs::Ico;
use crate::ui::theme;
use crate::ui::widgets::{card_frame, chip, field_label, ico_button, muted, semibold};
use crate::views::Action;
use crate::views::item_detail::value_box;
use crate::worker::ConflictView;

/// Room taken by the eye button next to a secret.
const EYE_ROOM: f32 = 36.0;
/// Height of a choice button.
const CHOICE_HEIGHT: f32 = 30.0;
/// Radius of the radio mark of a choice button.
const RADIO_RADIUS: f32 = 6.0;
/// Chip marking the newer side of a conflict.
const CHIP_NEWER: &str = "newer";
/// Shown instead of a secret that only the worker holds (archive items).
const MSG_NOT_AVAILABLE: &str = "not available";
/// Explanation above a list of conflict rows.
pub const MSG_CONFLICTS: &str = "Same attributes with another secret. Choose the secret to keep \
     for each item.";
/// Shown instead of the secret of an item an earlier step creates.
pub const MSG_PLANNED: &str = "will be created by an earlier step";

/// Side of a conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The item already in the target.
    Existing,
    /// The item being copied or moved.
    Incoming,
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

/// Formats the modification times `(existing, incoming)` at `offset`; when
/// both fall in the same minute the seconds are shown, so the newer side is
/// visible.
pub fn modified_texts(existing: u64, incoming: u64, offset: UtcOffset) -> (String, String) {
    let pair = (
        local_time::format_unix(existing, offset),
        local_time::format_unix(incoming, offset),
    );
    if pair.0 != pair.1 {
        return pair;
    }
    (
        local_time::format_unix_seconds(existing, offset),
        local_time::format_unix_seconds(incoming, offset),
    )
}

/// What the user did on a conflict row.
pub enum RowEvent {
    /// Picked the choice.
    Choose(Choice),
    /// Clicked the eye of a hidden live side: reveal its secret.
    Reveal(ItemId),
    /// Clicked the eye of a revealed live side: hide its secret.
    Hide(ItemId),
    /// Clicked the eye of the offline incoming side.
    ToggleOffline,
}

impl RowEvent {
    /// Returns the app action of a reveal or hide click; `None` for the
    /// events the caller's view handles (choice, offline toggle).
    pub fn secret_action(self) -> Option<Action> {
        match self {
            Self::Reveal(id) => Some(Action::RevealPreviewSecret(id)),
            Self::Hide(id) => Some(Action::HideTransferSecret(id)),
            Self::Choose(_) | Self::ToggleOffline => None,
        }
    }
}

/// How one side of a conflict shows its secret.
enum SideSecret {
    /// A live item, revealed on demand; `Some` when revealed.
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
    /// Formatted modification time.
    modified: String,
    /// True when this side was modified later.
    newer: bool,
    /// Secret display.
    secret: SideSecret,
    /// Text of the choice button.
    choice_text: &'static str,
    /// True when this side is the chosen one.
    chosen: bool,
}

/// Builds the secret display of the target side of `c`; a side planned by
/// an earlier consolidation step is never revealable.
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

/// Builds the secret display of the incoming side of `c`.
fn _incoming_secret(state: &AppState, c: &ConflictView, offline_shown: bool) -> SideSecret {
    if !c.incoming_revealable {
        return SideSecret::Unavailable(MSG_NOT_AVAILABLE);
    }
    if let Some(id) = &c.incoming_item {
        let shown = state.transfer_secret(id).map(secret_display);
        return SideSecret::Live(id.clone(), shown);
    }
    let Some(secret) = state.offline_incoming_secret(c) else {
        return SideSecret::Unavailable(MSG_NOT_AVAILABLE);
    };
    let shown = offline_shown.then(|| secret_display(secret));
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
    muted(ui, &format!("Modified {}", side.modified));
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

/// Returns the action of an eye click on a live side.
fn _eye_action(secret: &SideSecret) -> Option<RowEvent> {
    match secret {
        SideSecret::Live(id, None) => Some(RowEvent::Reveal(id.clone())),
        SideSecret::Live(id, Some(_)) => Some(RowEvent::Hide(id.clone())),
        SideSecret::Offline(_) | SideSecret::Unavailable(_) => None,
    }
}

/// Renders conflict `c` as a card (target left, incoming right) with
/// `choice` selected; `offline_shown` shows the offline incoming secret.
/// Returns what the user did.
pub fn conflict_row(
    ui: &mut Ui,
    state: &AppState,
    c: &ConflictView,
    choice: Choice,
    offline_shown: bool,
    target_label: &str,
) -> Option<RowEvent> {
    let newer = newer_side(c);
    let (modified_existing, modified_incoming) = modified_texts(
        c.modified_existing,
        c.modified_incoming,
        local_time::offset(),
    );
    let existing = SideView {
        heading: format!("In {target_label}"),
        label: &c.label_existing,
        modified: modified_existing,
        newer: newer == Some(Side::Existing),
        secret: _existing_secret(state, c),
        choice_text: "Keep current",
        chosen: choice == Choice::KeepTarget,
    };
    let incoming = SideView {
        heading: "Incoming".to_string(),
        label: &c.label_incoming,
        modified: modified_incoming,
        newer: newer == Some(Side::Incoming),
        secret: _incoming_secret(state, c, offline_shown),
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
        (SideClick::Choice, _) => Some(RowEvent::Choose(Choice::KeepTarget)),
        (_, SideClick::Choice) => Some(RowEvent::Choose(Choice::UseIncoming)),
        (SideClick::Eye, _) => _eye_action(&existing.secret),
        (_, SideClick::Eye) if matches!(incoming.secret, SideSecret::Offline(_)) => {
            Some(RowEvent::ToggleOffline)
        }
        (_, SideClick::Eye) => _eye_action(&incoming.secret),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a conflict with the given modification times.
    fn conflict(existing: u64, incoming: u64) -> ConflictView {
        ConflictView {
            label_incoming: "in".into(),
            label_existing: "ex".into(),
            modified_incoming: incoming,
            modified_existing: existing,
            default_choice: Choice::KeepTarget,
            incoming_item: None,
            incoming_revealable: false,
            existing_item: None,
            existing_planned: false,
            offline_index: None,
        }
    }

    /// The newer side is marked; ties mark none.
    #[test]
    fn newer_side_marks_later_modification() {
        assert_eq!(newer_side(&conflict(1, 2)), Some(Side::Incoming));
        assert_eq!(newer_side(&conflict(5, 2)), Some(Side::Existing));
        assert_eq!(newer_side(&conflict(5, 5)), None);
    }

    /// Times in the same minute show seconds; other minutes do not.
    #[test]
    fn same_minute_shows_seconds() {
        let utc = UtcOffset::UTC;
        assert_eq!(
            modified_texts(1_759_363_201, 1_759_363_242, utc),
            (
                "2025-10-02 00:00:01".to_string(),
                "2025-10-02 00:00:42".to_string()
            )
        );
        assert_eq!(
            modified_texts(1_759_363_201, 1_759_363_261, utc),
            (
                "2025-10-02 00:00".to_string(),
                "2025-10-02 00:01".to_string()
            )
        );
        assert_eq!(
            modified_texts(0, 0, utc),
            ("-".to_string(), "-".to_string())
        );
    }
}
