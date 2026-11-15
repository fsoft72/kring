//! Items of the selected collection as expandable cards, with a toolbar.

use eframe::egui::{
    self, Align, CornerRadius, FontId, Layout, Sense, Stroke, StrokeKind, Ui,
    text::{LayoutJob, TextFormat, TextWrapping},
};
use kring_core::model::{Attributes, CollectionInfo, ItemInfo};
use kring_core::transfer::apply::TransferMode;

use crate::app_state::AppState;
use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;
use crate::ui::widgets::{
    card_frame, muted, primary_button, search_box, secondary_button, semibold,
};
use crate::views::collection::{
    MSG_UNLOCK_FIRST, attributes_summary, format_date, matches_filter, shown_name,
};
use crate::views::dialogs::DialogKind;
use crate::views::item_detail::{self, AttrEditor};
use crate::views::transfer::copy_blocked;
use crate::views::{Action, Gates};

/// Height of the clickable header row of a card.
const CARD_HEADER_HEIGHT: f32 = 24.0;
/// Vertical gap between cards.
pub const CARD_GAP: f32 = 8.0;
/// Horizontal gap between parts of a card header.
const HEADER_GAP: f32 = 12.0;
/// Side of the chevron and lock glyph boxes.
const GLYPH_BOX: f32 = 20.0;
/// Width of the item search box.
const SEARCH_WIDTH: f32 = 260.0;

/// Returns the selection count of the toolbar, e.g. `2 selected`, or
/// `3 selected (1 hidden)` when the search hides some checked items.
pub fn selection_label(n: usize, hidden: usize) -> String {
    if hidden == 0 {
        return format!("{n} selected");
    }
    format!("{n} selected ({hidden} hidden)")
}

/// Returns how many checked items the search `filter` hides.
pub fn hidden_selected(state: &AppState, filter: &str) -> usize {
    let shown = displayed_items(state, filter);
    state
        .selection
        .iter()
        .filter(|id| !shown.iter().any(|i| &i.id == *id))
        .count()
}

/// Returns the Copy to / Move to target picker for the checked items of `c`.
pub fn transfer_dialog(state: &AppState, c: &CollectionInfo, mode: TransferMode) -> DialogKind {
    let items = state.selection.clone();
    DialogKind::transfer_target(items, mode, &state.collections, &c.id)
}

/// Renders the selection actions: count, "Copy to...", "Move to..." and "Clear".
fn _selection_actions(
    ui: &mut Ui,
    state: &AppState,
    c: &CollectionInfo,
    hidden: usize,
    gates: Gates,
) -> Option<Action> {
    let mut action = None;
    let text = selection_label(state.selection.len(), hidden);
    ui.label(semibold(text, 14.0));
    let copy = copy_blocked(state, &c.id);
    if primary_button(ui, "Copy to...", copy) {
        action = Some(Action::Open(transfer_dialog(state, c, TransferMode::Copy)));
    }
    if secondary_button(ui, "Move to...", gates.write.or(copy)) {
        action = Some(Action::Open(transfer_dialog(state, c, TransferMode::Move)));
    }
    if secondary_button(ui, "Clear", None) {
        action = Some(Action::ClearSelection);
    }
    action
}

/// Renders "+ New item" and "Import archive" (or the selection actions while
/// items are checked) and the item search box.
fn _toolbar(
    ui: &mut Ui,
    state: &AppState,
    c: &CollectionInfo,
    filter: &mut String,
    gates: Gates,
) -> Option<Action> {
    let mut action = None;
    ui.horizontal(|ui| {
        if !state.selection.is_empty() {
            let hidden = hidden_selected(state, filter);
            action = _selection_actions(ui, state, c, hidden, gates);
        } else {
            let blocked = gates.write.or(c.locked.then_some(MSG_UNLOCK_FIRST));
            if primary_button(ui, "+  New item", blocked) {
                action = Some(Action::Open(DialogKind::new_item(c.id.clone())));
            }
            if secondary_button(ui, "Import archive", blocked) {
                let label = shown_name(&state.collections, c);
                action = Some(Action::Open(DialogKind::import_archive(c, label)));
            }
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.set_max_width(SEARCH_WIDTH);
            search_box(ui, filter, "Search items");
        });
    });
    action
}

/// Lays out `text` on one line, cut with an ellipsis beyond `max_width`.
fn _one_line(
    ui: &Ui,
    text: String,
    font: FontId,
    color: egui::Color32,
    max_width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = LayoutJob::single_section(
        text,
        TextFormat {
            font_id: font,
            color,
            ..Default::default()
        },
    );
    job.wrap = TextWrapping {
        max_width: max_width.max(0.0),
        max_rows: 1,
        break_anywhere: true,
        overflow_character: Some('\u{2026}'),
    };
    ui.painter().layout_job(job)
}

/// Paints the header row of a card: lock, label, attribute summary, date and
/// chevron. Returns true when clicked.
pub fn card_header(
    ui: &mut Ui,
    label: &str,
    attributes: &Attributes,
    modified: u64,
    locked: bool,
    expanded: bool,
) -> bool {
    let size = egui::vec2(ui.available_width(), CARD_HEADER_HEIGHT);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    let p = ui.painter().clone();
    let mid = rect.center().y;
    let mut x = rect.left();
    if locked {
        let r = egui::Rect::from_min_size(
            egui::pos2(x, mid - GLYPH_BOX / 2.0),
            egui::vec2(GLYPH_BOX, GLYPH_BOX),
        );
        glyphs::paint(&p, r, Ico::Lock, theme::LABEL);
        x += GLYPH_BOX + 6.0;
    }
    let chevron = if expanded {
        Ico::ChevronDown
    } else {
        Ico::ChevronRight
    };
    let chev_rect = egui::Rect::from_center_size(
        egui::pos2(rect.right() - GLYPH_BOX / 2.0, mid),
        egui::vec2(GLYPH_BOX, GLYPH_BOX),
    );
    let chev_color = if resp.hovered() {
        theme::TEXT
    } else {
        theme::LABEL
    };
    glyphs::paint(&p, chev_rect, chevron, chev_color);
    let date = p.layout_no_wrap(
        format_date(modified),
        FontId::proportional(12.0),
        theme::MUTED,
    );
    let date_x = chev_rect.left() - HEADER_GAP - date.size().x;
    p.galley(
        egui::pos2(date_x, mid - date.size().y / 2.0),
        date,
        theme::MUTED,
    );
    let label_max = (date_x - x) * 0.5;
    let label = _one_line(
        ui,
        label.to_string(),
        FontId::new(14.0, theme::semibold()),
        theme::TEXT,
        label_max,
    );
    let label_w = label.size().x;
    p.galley(
        egui::pos2(x, mid - label.size().y / 2.0),
        label,
        theme::TEXT,
    );
    x += label_w + HEADER_GAP;
    let summary_max = date_x - HEADER_GAP - x;
    let summary = attributes_summary(attributes);
    let summary = _one_line(
        ui,
        summary,
        FontId::monospace(12.0),
        theme::MUTED,
        summary_max,
    );
    p.galley(
        egui::pos2(x, mid - summary.size().y / 2.0),
        summary,
        theme::MUTED,
    );
    resp.clicked()
}

/// Renders one item card; the expanded card shows the item body.
fn _card(
    ui: &mut Ui,
    state: &AppState,
    c: &CollectionInfo,
    item: &ItemInfo,
    editor: &mut AttrEditor,
    gates: Gates,
) -> Option<Action> {
    let expanded = state.selected_item.as_ref() == Some(&item.id);
    let mut action = None;
    let frame = card_frame().inner_margin(egui::Margin::symmetric(16, 10));
    let resp = frame.show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        let mut clicked = false;
        ui.horizontal(|ui| {
            let mut checked = state.selection.contains(&item.id);
            let can_check = !c.locked && !item.locked;
            let check = ui.add_enabled(can_check, egui::Checkbox::without_text(&mut checked));
            if check
                .on_hover_text("Select for Copy to / Move to")
                .changed()
            {
                action = Some(Action::ToggleSelect(item.id.clone()));
            }
            clicked = card_header(
                ui,
                &item.label,
                &item.attributes,
                item.modified,
                item.locked,
                expanded,
            );
        });
        if clicked {
            action = Some(if expanded {
                Action::DeselectItem
            } else {
                Action::SelectItem(item.id.clone())
            });
        }
        if expanded {
            let body = item_detail::show(ui, state, c, item, editor, gates);
            action = body.or(action.take());
        }
    });
    card_border(ui, resp.response.rect, expanded);
    action
}

/// Paints the card border: PRIMARY when expanded, dimmed PRIMARY on hover.
pub fn card_border(ui: &Ui, rect: egui::Rect, expanded: bool) {
    let border = if expanded {
        Some(theme::PRIMARY)
    } else if ui.rect_contains_pointer(rect) {
        Some(theme::PRIMARY.gamma_multiply(0.6))
    } else {
        None
    };
    if let Some(color) = border {
        let r = CornerRadius::same(theme::RADIUS_CARD);
        ui.painter()
            .rect_stroke(rect, r, Stroke::new(1.0_f32, color), StrokeKind::Inside);
    }
}

/// Items matching `filter` in card order. The bus lists items in no stable
/// order, so cards are sorted by label (then id) and do not jump around.
pub fn displayed_items<'a>(state: &'a AppState, filter: &str) -> Vec<&'a ItemInfo> {
    let mut items: Vec<&ItemInfo> = state
        .items
        .iter()
        .filter(|i| matches_filter(i, filter))
        .collect();
    items.sort_by_cached_key(|i| (i.label.to_lowercase(), i.id.0.clone()));
    items
}

/// Renders the toolbar and the item cards of collection `c`.
pub fn show(
    ui: &mut Ui,
    state: &AppState,
    c: &CollectionInfo,
    filter: &mut String,
    editor: &mut AttrEditor,
    gates: Gates,
) -> Option<Action> {
    let mut action = _toolbar(ui, state, c, filter, gates);
    ui.add_space(4.0);
    let items = displayed_items(state, filter);
    if items.is_empty() {
        ui.add_space(24.0);
        let text = if filter.trim().is_empty() {
            "No items in this keyring yet."
        } else {
            "No matches."
        };
        ui.vertical_centered(|ui| muted(ui, text));
        return action;
    }
    egui::ScrollArea::vertical()
        .id_salt("kring-items")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = CARD_GAP;
            for item in items {
                let found = _card(ui, state, c, item, editor, gates);
                action = found.or(action.take());
            }
        });
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::Event;
    use kring_core::model::{CollectionId, ItemId};

    /// Builds an item of collection `/c/a`.
    fn item(id: &str, label: &str) -> ItemInfo {
        ItemInfo {
            id: ItemId(id.into()),
            collection: CollectionId("/c/a".into()),
            label: label.into(),
            attributes: Default::default(),
            locked: false,
            created: 0,
            modified: 0,
        }
    }

    /// Checked items hidden by the search are counted apart.
    #[test]
    fn selection_label_counts_hidden() {
        let coll = CollectionId("/c/a".into());
        let mut s = AppState::default();
        s.select_collection(coll.clone());
        s.apply(Event::Items(
            coll,
            vec![item("/c/a/1", "alpha"), item("/c/a/2", "beta")],
        ));
        s.selection = vec![ItemId("/c/a/1".into()), ItemId("/c/a/2".into())];
        assert_eq!(hidden_selected(&s, ""), 0);
        assert_eq!(hidden_selected(&s, "alp"), 1);
        assert_eq!(selection_label(2, 0), "2 selected");
        assert_eq!(selection_label(2, 1), "2 selected (1 hidden)");
    }
}
