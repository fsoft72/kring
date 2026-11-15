//! Read-only cards of the items read offline from a keyring file.
//!
//! The secrets are already in `AppState::file_items`; showing one only flips
//! local state here (hidden by default). Nothing can be edited or deleted.

use std::collections::BTreeSet;

use eframe::egui::{self, Align, Layout, RichText};
use kring_core::keyring_file::textual::OfflineItem;

use crate::app_state::AppState;
use crate::secret_display::secret_display;
use crate::ui::glyphs::Ico;
use crate::ui::theme;
use crate::ui::widgets::{card_frame, field_label, ico_button, muted, search_box};
use crate::views::Action;
use crate::views::collection::format_date;
use crate::views::item_detail::{divider, value_box};
use crate::views::item_list::{CARD_GAP, card_border, card_header};

/// Room taken by each icon button next to the secret.
const SECRET_BUTTONS_ROOM: f32 = 36.0;
/// Shown instead of the secret controls when the file has no secret for the item.
const MSG_NO_SECRET: &str = "No secret in file";
/// Tooltip of Copy for binary secrets.
const MSG_BINARY: &str = "Binary secrets cannot be copied";
/// Width of the item search box.
const SEARCH_WIDTH: f32 = 260.0;

/// Card state of the selected file: expanded card, shown secrets and the filter.
#[derive(Debug, Default)]
pub struct FileView {
    file: Option<String>,
    count: usize,
    /// Index (into `AppState::file_items`) of the expanded card.
    pub expanded: Option<usize>,
    revealed: BTreeSet<usize>,
    /// Item search text.
    pub filter: String,
}

impl FileView {
    /// Resets the cards when another file is selected or its items are reloaded.
    pub fn sync(&mut self, state: &AppState) {
        let same = self.file == state.selected_file && self.count == state.file_items.len();
        if same {
            return;
        }
        if self.file != state.selected_file {
            self.filter.clear();
        }
        self.file = state.selected_file.clone();
        self.count = state.file_items.len();
        self.expanded = None;
        self.revealed.clear();
    }

    /// Expands card `index` (hiding other secrets), or collapses it (hiding its
    /// secret) when expanded.
    pub fn toggle_expanded(&mut self, index: usize) {
        if self.expanded == Some(index) {
            self.expanded = None;
            self.revealed.remove(&index);
            return;
        }
        self.expanded = Some(index);
        self.revealed.clear();
    }

    /// Shows or hides the secret of card `index`.
    pub fn toggle_revealed(&mut self, index: usize) {
        if !self.revealed.remove(&index) {
            self.revealed.insert(index);
        }
    }

    /// Returns true when the secret of card `index` is shown.
    pub fn is_revealed(&self, index: usize) -> bool {
        self.revealed.contains(&index)
    }
}

/// Returns true when the label or an attribute contains `filter` (case-insensitive).
fn _matches(item: &OfflineItem, filter: &str) -> bool {
    let needle = filter.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    let hit = |text: &str| text.to_lowercase().contains(&needle);
    hit(&item.label) || item.attributes.iter().any(|(k, v)| hit(k) || hit(v))
}

/// Indices of the items matching `filter`, sorted by label (then index).
pub fn displayed_file_items(items: &[OfflineItem], filter: &str) -> Vec<usize> {
    let mut shown: Vec<usize> = (0..items.len())
        .filter(|i| _matches(&items[*i], filter))
        .collect();
    shown.sort_by_cached_key(|i| (items[*i].label.to_lowercase(), *i));
    shown
}

/// Renders the secret box with Show/Hide and Copy.
fn _secret_row(
    ui: &mut egui::Ui,
    item: &OfflineItem,
    index: usize,
    view: &mut FileView,
) -> Option<Action> {
    let shown = view.is_revealed(index);
    let display = shown.then(|| secret_display(&item.secret));
    let mut action = None;
    field_label(ui, "Secret");
    ui.horizontal(|ui| {
        let width = ui.available_width() - 2.0 * SECRET_BUTTONS_ROOM;
        value_box(ui, display.as_ref(), width);
        let (ico, tip) = if shown {
            (Ico::EyeOff, "Hide")
        } else {
            (Ico::Eye, "Show")
        };
        if ico_button(ui, ico, tip, None, false) {
            view.toggle_revealed(index);
        }
        let binary = item.secret.as_text().is_none().then_some(MSG_BINARY);
        if ico_button(ui, Ico::Copy, "Copy (clears in 30 s)", binary, false) {
            action = Some(Action::CopyFileSecret(index));
        }
    });
    action
}

/// Renders the attributes as read-only key/value lines.
fn _attributes(ui: &mut egui::Ui, item: &OfflineItem) {
    field_label(ui, "Attributes");
    if item.attributes.is_empty() {
        muted(ui, "No attributes");
        return;
    }
    egui::Grid::new(("kring-file-attrs", &item.label))
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            for (k, v) in &item.attributes {
                ui.label(RichText::new(k).monospace().size(12.5).color(theme::LABEL));
                ui.add(
                    egui::Label::new(RichText::new(v).monospace().size(12.5).color(theme::TEXT))
                        .wrap(),
                );
                ui.end_row();
            }
        });
}

/// Renders one read-only item card; the expanded card shows secret and attributes
/// (a muted note instead of the secret controls when the file had no secret).
fn _card(
    ui: &mut egui::Ui,
    item: &OfflineItem,
    index: usize,
    view: &mut FileView,
) -> Option<Action> {
    let expanded = view.expanded == Some(index);
    let mut action = None;
    let frame = card_frame().inner_margin(egui::Margin::symmetric(16, 10));
    let resp = frame.show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        if card_header(
            ui,
            &item.label,
            &item.attributes,
            item.modified,
            false,
            expanded,
        ) {
            view.toggle_expanded(index);
        }
        if !expanded {
            return;
        }
        ui.add_space(6.0);
        divider(ui);
        ui.add_space(6.0);
        if item.secret_missing {
            field_label(ui, "Secret");
            muted(ui, MSG_NO_SECRET);
        } else {
            action = _secret_row(ui, item, index, view);
        }
        ui.add_space(6.0);
        _attributes(ui, item);
        ui.add_space(4.0);
        let dates = format!(
            "Created {} - modified {}",
            format_date(item.created),
            format_date(item.modified)
        );
        muted(ui, &dates);
    });
    card_border(ui, resp.response.rect, expanded);
    action
}

/// Renders the search box and the read-only item cards of the selected file.
pub fn show(ui: &mut egui::Ui, state: &AppState, view: &mut FileView) -> Option<Action> {
    let mut action = None;
    let mut filter = std::mem::take(&mut view.filter);
    ui.horizontal(|ui| {
        let noun = if state.file_items.len() == 1 {
            "item"
        } else {
            "items"
        };
        muted(ui, &format!("{} {noun}, read only", state.file_items.len()));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.set_max_width(SEARCH_WIDTH);
            search_box(ui, &mut filter, "Search items");
        });
    });
    view.filter = filter;
    ui.add_space(4.0);
    let shown = displayed_file_items(&state.file_items, &view.filter);
    if shown.is_empty() {
        ui.add_space(24.0);
        let text = if view.filter.trim().is_empty() {
            "No items in this file."
        } else {
            "No matches."
        };
        ui.vertical_centered(|ui| muted(ui, text));
        return None;
    }
    egui::ScrollArea::vertical()
        .id_salt("kring-file-items")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = CARD_GAP;
            for index in shown {
                let found = _card(ui, &state.file_items[index], index, view);
                action = found.or(action.take());
            }
        });
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::Event;
    use kring_core::keyring_file::KeyringFileInfo;
    use kring_core::model::SecretValue;

    /// Builds an offline item.
    fn item(label: &str, attrs: &[(&str, &str)]) -> OfflineItem {
        OfflineItem {
            label: label.into(),
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            secret: SecretValue::from_text("s"),
            created: 0,
            modified: 0,
            secret_missing: false,
        }
    }

    /// Builds a state with file `name` selected and `n` items loaded.
    fn state(name: &str, n: usize) -> AppState {
        let mut s = AppState::default();
        let info = KeyringFileInfo {
            path: format!("/k/{name}.keyring").into(),
            name: name.into(),
            format: kring_core::keyring_file::KeyringFormat::Textual,
            size: 0,
            modified: 0,
            display_name: None,
            item_count: Some(n),
            daemon_readable: Some(true),
            plaintext: true,
            error: None,
        };
        s.apply(Event::Files(vec![info]));
        s.select_file(name.into());
        s.apply(Event::FileItems {
            name: name.into(),
            items: (0..n).map(|i| item(&format!("i{i}"), &[])).collect(),
            warnings: vec![],
        });
        s
    }

    /// Secrets are hidden by default; collapsing a card hides its secret.
    #[test]
    fn reveal_is_local_and_hidden_by_default() {
        let s = state("a", 2);
        let mut v = FileView::default();
        v.sync(&s);
        assert!(!v.is_revealed(0) && v.expanded.is_none());
        v.toggle_expanded(0);
        v.toggle_revealed(0);
        assert!(v.is_revealed(0) && !v.is_revealed(1));
        v.toggle_revealed(0);
        assert!(!v.is_revealed(0));
        v.toggle_revealed(0);
        v.toggle_expanded(0);
        assert!(v.expanded.is_none() && !v.is_revealed(0));
        v.toggle_expanded(1);
        v.toggle_revealed(1);
        v.toggle_expanded(0);
        assert_eq!(v.expanded, Some(0));
        assert!(!v.is_revealed(1));
    }

    /// Another file or reloaded items reset the cards; the same state keeps them.
    #[test]
    fn sync_resets_on_change() {
        let mut v = FileView::default();
        v.sync(&state("a", 2));
        v.toggle_expanded(1);
        v.toggle_revealed(1);
        v.filter = "x".into();
        v.sync(&state("a", 2));
        assert!(v.is_revealed(1) && v.expanded == Some(1));
        v.sync(&state("a", 3));
        assert!(!v.is_revealed(1) && v.expanded.is_none());
        v.toggle_revealed(0);
        v.sync(&state("b", 3));
        assert!(!v.is_revealed(0) && v.filter.is_empty());
        v.toggle_revealed(0);
        v.sync(&AppState::default());
        assert!(!v.is_revealed(0));
    }

    /// Items are sorted by label and filtered by label or attributes.
    #[test]
    fn displayed_sorted_and_filtered() {
        let items = [
            item("zeta", &[("service", "gh")]),
            item("Alpha", &[]),
            item("beta", &[("user", "Dev")]),
        ];
        assert_eq!(displayed_file_items(&items, ""), [1, 2, 0]);
        assert_eq!(displayed_file_items(&items, "dev"), [2]);
        assert_eq!(displayed_file_items(&items, "GH"), [0]);
        assert!(displayed_file_items(&items, "none").is_empty());
    }
}
