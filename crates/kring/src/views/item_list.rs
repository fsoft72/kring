//! Items of the selected collection as expandable cards, with a toolbar.

use eframe::egui::{
    self, Align, CornerRadius, FontId, Layout, Sense, Stroke, StrokeKind, Ui,
    text::{LayoutJob, TextFormat, TextWrapping},
};
use kring_core::model::{CollectionInfo, ItemInfo};

use crate::app_state::AppState;
use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;
use crate::ui::widgets::{card_frame, muted, primary_button, search_box};
use crate::views::collection::{attributes_summary, format_date, matches_filter};
use crate::views::dialogs::DialogKind;
use crate::views::item_detail::{self, AttrEditor};
use crate::views::{Action, Gates};

/// Height of the clickable header row of a card.
const CARD_HEADER_HEIGHT: f32 = 24.0;
/// Vertical gap between cards.
const CARD_GAP: f32 = 8.0;
/// Horizontal gap between parts of a card header.
const HEADER_GAP: f32 = 12.0;
/// Side of the chevron and lock glyph boxes.
const GLYPH_BOX: f32 = 20.0;
/// Tooltip of "+ New item" while the collection is locked.
const MSG_LOCKED: &str = "Unlock the keyring first";
/// Width of the item search box.
const SEARCH_WIDTH: f32 = 260.0;

/// Renders "+ New item" and the item search box.
fn _toolbar(ui: &mut Ui, c: &CollectionInfo, filter: &mut String, gates: Gates) -> Option<Action> {
    let mut action = None;
    ui.horizontal(|ui| {
        let locked = c.locked.then_some(MSG_LOCKED);
        if primary_button(ui, "+  New item", gates.write.or(locked)) {
            action = Some(Action::Open(DialogKind::new_item(c.id.clone())));
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
fn _card_header(ui: &mut Ui, item: &ItemInfo, expanded: bool) -> bool {
    let size = egui::vec2(ui.available_width(), CARD_HEADER_HEIGHT);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    let p = ui.painter().clone();
    let mid = rect.center().y;
    let mut x = rect.left();
    if item.locked {
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
        format_date(item.modified),
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
        item.label.clone(),
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
    let summary = attributes_summary(&item.attributes);
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
        if _card_header(ui, item, expanded) {
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
    let rect = resp.response.rect;
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
    action
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
    let mut action = _toolbar(ui, c, filter, gates);
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
