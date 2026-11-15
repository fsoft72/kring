//! List panel "Keyrings": title with "+ New", search box, count and rows.

use eframe::egui::{self, Align, CornerRadius, Layout, RichText, Sense, Ui, UiBuilder};
use kring_core::model::CollectionInfo;

use crate::app_state::AppState;
use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;
use crate::ui::widgets::{chip, muted, muted_text, primary_button, search_box, semibold};
use crate::views::collection::{display_name, is_default};
use crate::views::dialogs::DialogKind;
use crate::views::{Action, Gates};

/// Height of a keyring row.
const ROW_HEIGHT: f32 = 44.0;
/// Horizontal padding inside a row.
const ROW_PADDING: f32 = 12.0;

/// Returns the muted count line, e.g. `4 keyrings - 1 locked`.
pub fn list_summary(state: &AppState) -> String {
    let total = state.collections.len();
    let locked = state.collections.iter().filter(|c| c.locked).count();
    let noun = if total == 1 { "keyring" } else { "keyrings" };
    format!("{total} {noun} - {locked} locked")
}

/// Returns true when the display name contains `filter` (case-insensitive).
pub fn keyring_matches(c: &CollectionInfo, filter: &str) -> bool {
    let needle = filter.trim().to_lowercase();
    needle.is_empty() || display_name(c).to_lowercase().contains(&needle)
}

/// Paints the row background: selected tint plus accent bar, or hover tint.
pub fn row_background(ui: &Ui, rect: egui::Rect, selected: bool, hovered: bool) {
    let r = CornerRadius::same(theme::RADIUS_CARD);
    if selected {
        ui.painter().rect_filled(rect, r, theme::INPUT_FILL_BLUE);
        let bar = egui::Rect::from_min_size(
            egui::pos2(rect.left(), rect.top() + 8.0),
            egui::vec2(3.0, rect.height() - 16.0),
        );
        ui.painter()
            .rect_filled(bar, CornerRadius::same(1), theme::PRIMARY);
    } else if hovered {
        ui.painter().rect_filled(rect, r, theme::FIELD_ROW_BG);
    }
}

/// Renders one keyring row; returns true when clicked.
fn _row(ui: &mut Ui, c: &CollectionInfo, selected: bool) -> bool {
    let size = egui::vec2(ui.available_width(), ROW_HEIGHT);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    row_background(ui, rect, selected, resp.hovered());
    let inner = rect.shrink2(egui::vec2(ROW_PADDING, 0.0));
    let builder = UiBuilder::new()
        .max_rect(inner)
        .layout(Layout::left_to_right(Align::Center));
    ui.scope_builder(builder, |ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let name = RichText::new(display_name(c))
            .family(theme::medium())
            .size(14.0)
            .color(theme::TEXT);
        ui.add(egui::Label::new(name).truncate().selectable(false));
        if is_default(c) {
            chip(ui, "default", theme::SECONDARY);
        }
        if c.is_login {
            chip(ui, "login", theme::SECONDARY);
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(muted_text(c.item_count.to_string()));
            if c.locked {
                let (r, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), Sense::hover());
                glyphs::paint(ui.painter(), r, Ico::Lock, theme::LABEL);
            }
        });
    });
    resp.clicked()
}

/// Renders the keyring list panel and returns the requested action.
pub fn show(ui: &mut Ui, state: &AppState, filter: &mut String, gates: Gates) -> Option<Action> {
    let mut action = None;
    ui.horizontal(|ui| {
        ui.label(semibold("Keyrings", 18.0));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if primary_button(ui, "+  New", gates.write_and_master()) {
                action = Some(Action::Open(DialogKind::create_collection()));
            }
        });
    });
    ui.add_space(2.0);
    search_box(ui, filter, "Search keyrings");
    muted(ui, &list_summary(state));
    ui.add_space(2.0);
    egui::ScrollArea::vertical()
        .id_salt("kring-collections")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            let rows = state
                .collections
                .iter()
                .filter(|c| keyring_matches(c, filter));
            for c in rows {
                let selected = state.selected.as_ref() == Some(&c.id);
                if _row(ui, c, selected) {
                    action = Some(Action::SelectCollection(c.id.clone()));
                }
            }
        });
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::Event;
    use kring_core::model::CollectionId;

    /// Builds a collection with the given label and lock state.
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

    /// The summary counts keyrings and locked ones.
    #[test]
    fn summary_counts_locked() {
        let mut s = AppState::default();
        s.apply(Event::Collections(vec![
            col("/c/a", "a", true),
            col("/c/b", "b", false),
            col("/c/c", "c", true),
        ]));
        assert_eq!(list_summary(&s), "3 keyrings - 2 locked");
        s.apply(Event::Collections(vec![col("/c/a", "a", false)]));
        assert_eq!(list_summary(&s), "1 keyring - 0 locked");
    }

    /// The filter matches the display name case-insensitively; blank matches all.
    #[test]
    fn filter_by_name() {
        let c = col("/org/freedesktop/secrets/collection/session", " ", false);
        assert!(keyring_matches(&c, ""));
        assert!(keyring_matches(&c, "SESS"));
        let w = col("/c/w", "Work", false);
        assert!(keyring_matches(&w, " work "));
        assert!(!keyring_matches(&w, "login"));
    }
}
