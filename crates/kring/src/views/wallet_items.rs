//! Read-only cards of the entries of an open KWallet wallet, grouped by folder.
//!
//! The secrets are already in `AppState::wallet_items`; showing one only
//! flips local state here (hidden by default). Nothing can be edited.

use std::collections::BTreeSet;

use eframe::egui::{self, Align, Layout, RichText, Sense};

use crate::app_state::{AppState, count_noun};
use crate::secret_display::secret_display;
use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;
use crate::ui::widgets::{card_frame, chip, field_label, ico_button, muted, search_box};
use crate::views::Action;
use crate::views::collection::format_date;
use crate::views::item_detail::{divider, value_box};
use crate::views::item_list::{CARD_GAP, card_border, card_header};
use crate::worker::{OfflineItemView, WalletEntryKind};

/// Room taken by each icon button next to the secret.
const SECRET_BUTTONS_ROOM: f32 = 36.0;
/// Tooltip of Copy for binary secrets.
const MSG_BINARY: &str = "Binary secrets cannot be copied";
/// Tooltip of the "app entry" chip.
const MSG_APP_ENTRY: &str =
    "Stored by an app through the Secret Service: its original attributes are restored";
/// Width of the entry search box.
const SEARCH_WIDTH: f32 = 260.0;
/// Height of a folder group header.
const GROUP_HEIGHT: f32 = 30.0;
/// Side of the chevron of a folder group header.
const GROUP_GLYPH: f32 = 18.0;

/// Card state of the open wallet: collapsed folders, expanded card, shown
/// secrets and the filter.
#[derive(Debug, Default)]
pub struct WalletView {
    wallet: Option<String>,
    count: usize,
    /// Index (into `AppState::wallet_items`) of the expanded card.
    pub expanded: Option<usize>,
    revealed: BTreeSet<usize>,
    collapsed: BTreeSet<String>,
    /// Entry search text.
    pub filter: String,
}

impl WalletView {
    /// Resets the cards when another wallet is selected or its entries change.
    pub fn sync(&mut self, state: &AppState) {
        let same = self.wallet == state.selected_wallet && self.count == state.wallet_items.len();
        if same {
            return;
        }
        if self.wallet != state.selected_wallet {
            self.filter.clear();
            self.collapsed.clear();
        }
        self.wallet = state.selected_wallet.clone();
        self.count = state.wallet_items.len();
        self.expanded = None;
        self.revealed.clear();
    }

    /// Expands card `index` (hiding other secrets), or collapses it (hiding
    /// its secret) when expanded.
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

    /// Collapses or expands folder group `folder`; collapsing hides the
    /// secrets of its cards (`items` are the wallet entries).
    pub fn toggle_folder(&mut self, folder: &str, items: &[OfflineItemView]) {
        if self.collapsed.remove(folder) {
            return;
        }
        self.collapsed.insert(folder.to_string());
        let inside = |i: &usize| items.get(*i).is_some_and(|it| it.folder == folder);
        self.revealed.retain(|i| !inside(i));
        if self.expanded.as_ref().is_some_and(inside) {
            self.expanded = None;
        }
    }

    /// Returns true when folder group `folder` is collapsed.
    pub fn is_collapsed(&self, folder: &str) -> bool {
        self.collapsed.contains(folder)
    }
}

/// Returns the chip text of an entry kind.
pub fn kind_label(kind: WalletEntryKind) -> &'static str {
    match kind {
        WalletEntryKind::Password => "password",
        WalletEntryKind::Map => "map",
        WalletEntryKind::Stream => "stream",
    }
}

/// Returns true when the label, folder, key or an attribute contains
/// `filter` (case-insensitive).
fn _matches(item: &OfflineItemView, filter: &str) -> bool {
    let needle = filter.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    let hit = |text: &str| text.to_lowercase().contains(&needle);
    hit(&item.label)
        || hit(&item.folder)
        || hit(&item.key)
        || item.attributes.iter().any(|(k, v)| hit(k) || hit(v))
}

/// Groups the entries matching `filter` by folder: folders sorted by name
/// (case-insensitive), the indices of each sorted by label (then index).
pub fn wallet_groups(items: &[OfflineItemView], filter: &str) -> Vec<(String, Vec<usize>)> {
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        if !_matches(item, filter) {
            continue;
        }
        match groups.iter_mut().find(|(f, _)| *f == item.folder) {
            Some((_, list)) => list.push(i),
            None => groups.push((item.folder.clone(), vec![i])),
        }
    }
    groups.sort_by_cached_key(|(f, _)| (f.to_lowercase(), f.clone()));
    for (_, list) in &mut groups {
        list.sort_by_cached_key(|i| (items[*i].label.to_lowercase(), *i));
    }
    groups
}

/// Returns the muted count line, e.g. `7 entries in 4 folders, read only`.
pub fn entries_summary(items: &[OfflineItemView]) -> String {
    let folders: BTreeSet<&str> = items.iter().map(|i| i.folder.as_str()).collect();
    let noun = if items.len() == 1 { "entry" } else { "entries" };
    format!(
        "{} {noun} in {}, read only",
        items.len(),
        count_noun(folders.len(), "folder")
    )
}

/// Renders a folder group header (chevron, name, count); returns true when clicked.
fn _group_header(ui: &mut egui::Ui, folder: &str, count: usize, collapsed: bool) -> bool {
    let size = egui::vec2(ui.available_width(), GROUP_HEIGHT);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    let p = ui.painter();
    let mid = rect.center().y;
    let chevron = if collapsed {
        Ico::ChevronRight
    } else {
        Ico::ChevronDown
    };
    let color = if resp.hovered() {
        theme::TEXT
    } else {
        theme::LABEL
    };
    let glyph = egui::Rect::from_min_size(
        egui::pos2(rect.left(), mid - GROUP_GLYPH / 2.0),
        egui::vec2(GROUP_GLYPH, GROUP_GLYPH),
    );
    glyphs::paint(p, glyph, chevron, color);
    let name = p.text(
        egui::pos2(glyph.right() + 6.0, mid),
        egui::Align2::LEFT_CENTER,
        folder.to_uppercase(),
        egui::FontId::new(12.0, theme::semibold()),
        color,
    );
    p.text(
        egui::pos2(name.right() + 8.0, mid),
        egui::Align2::LEFT_CENTER,
        count.to_string(),
        egui::FontId::proportional(12.0),
        theme::MUTED,
    );
    resp.clicked()
}

/// Renders the secret box with Show/Hide and Copy.
fn _secret_row(
    ui: &mut egui::Ui,
    item: &OfflineItemView,
    index: usize,
    view: &mut WalletView,
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
            action = Some(Action::CopyWalletSecret(index));
        }
    });
    action
}

/// Renders the attributes the import gives the entry, as key/value lines.
fn _attributes(ui: &mut egui::Ui, item: &OfflineItemView) {
    field_label(ui, "Attributes after import");
    if item.attributes.is_empty() {
        muted(ui, "No attributes");
        return;
    }
    egui::Grid::new(("kring-wallet-attrs", &item.folder, &item.key))
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

/// Renders one read-only entry card: kind and app chips, then the header;
/// the expanded card shows secret, attributes and where it is in the wallet.
fn _card(
    ui: &mut egui::Ui,
    item: &OfflineItemView,
    index: usize,
    view: &mut WalletView,
) -> Option<Action> {
    let expanded = view.expanded == Some(index);
    let mut action = None;
    let frame = card_frame().inner_margin(egui::Margin::symmetric(16, 10));
    let resp = frame.show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        let mut clicked = false;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            chip(ui, kind_label(item.kind), theme::SECONDARY);
            if item.app_entry {
                chip(ui, "app entry", theme::OK);
            }
            ui.add_space(4.0);
            clicked = card_header(
                ui,
                &item.label,
                &item.attributes,
                item.modified,
                false,
                expanded,
            );
        });
        if clicked {
            view.toggle_expanded(index);
        }
        if !expanded {
            return;
        }
        ui.add_space(6.0);
        divider(ui);
        ui.add_space(6.0);
        action = _secret_row(ui, item, index, view);
        ui.add_space(6.0);
        _attributes(ui, item);
        ui.add_space(4.0);
        let place = format!(
            "Folder {} - key {} - modified {}",
            item.folder,
            item.key,
            format_date(item.modified)
        );
        muted(ui, &place);
        if item.app_entry {
            muted(ui, MSG_APP_ENTRY);
        }
    });
    card_border(ui, resp.response.rect, expanded);
    action
}

/// Renders the search box and the folder groups of the open wallet.
pub fn show(ui: &mut egui::Ui, state: &AppState, view: &mut WalletView) -> Option<Action> {
    let mut action = None;
    let mut filter = std::mem::take(&mut view.filter);
    ui.horizontal(|ui| {
        muted(ui, &entries_summary(&state.wallet_items));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.set_max_width(SEARCH_WIDTH);
            search_box(ui, &mut filter, "Search entries");
        });
    });
    view.filter = filter;
    ui.add_space(4.0);
    let groups = wallet_groups(&state.wallet_items, &view.filter);
    if groups.is_empty() {
        ui.add_space(24.0);
        let text = if view.filter.trim().is_empty() {
            "No entries in this wallet."
        } else {
            "No matches."
        };
        ui.vertical_centered(|ui| muted(ui, text));
        return None;
    }
    egui::ScrollArea::vertical()
        .id_salt("kring-wallet-items")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = CARD_GAP;
            for (folder, indices) in groups {
                let collapsed = view.is_collapsed(&folder);
                if _group_header(ui, &folder, indices.len(), collapsed) {
                    view.toggle_folder(&folder, &state.wallet_items);
                }
                if view.is_collapsed(&folder) {
                    continue;
                }
                for index in indices {
                    let found = _card(ui, &state.wallet_items[index], index, view);
                    action = found.or(action.take());
                }
            }
        });
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::Event;
    use kring_core::model::SecretValue;

    /// Builds a wallet entry view.
    fn item(folder: &str, label: &str, attrs: &[(&str, &str)]) -> OfflineItemView {
        OfflineItemView {
            label: label.into(),
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            folder: folder.into(),
            key: label.into(),
            kind: WalletEntryKind::Password,
            app_entry: false,
            modified: 0,
            secret: SecretValue::from_text("s"),
        }
    }

    /// Builds a state with wallet `name` selected and `items` loaded.
    fn state(name: &str, items: Vec<OfflineItemView>) -> AppState {
        let mut s = AppState::default();
        s.select_wallet(name.into());
        s.apply(Event::WalletItems {
            name: name.into(),
            items,
        });
        s
    }

    /// Folders sorted by name, entries by label; the filter also matches
    /// folder, key and attributes.
    #[test]
    fn groups_sorted_and_filtered() {
        let items = [
            item("Secret Service", "zeta", &[("service", "gh")]),
            item("Passwords", "site", &[]),
            item("Secret Service", "Alpha", &[]),
            item("apps", "carol", &[("user", "Dev")]),
        ];
        let groups = wallet_groups(&items, "");
        let names: Vec<&str> = groups.iter().map(|(f, _)| f.as_str()).collect();
        assert_eq!(names, ["apps", "Passwords", "Secret Service"]);
        assert_eq!(groups[2].1, [2, 0]);
        assert_eq!(
            wallet_groups(&items, "dev"),
            [("apps".to_string(), vec![3])]
        );
        assert_eq!(wallet_groups(&items, "GH")[0].1, [0]);
        assert_eq!(wallet_groups(&items, "passw")[0].1, [1]);
        assert!(wallet_groups(&items, "none").is_empty());
    }

    /// The summary counts entries and folders.
    #[test]
    fn summary_counts() {
        let items = [
            item("a", "x", &[]),
            item("b", "y", &[]),
            item("b", "z", &[]),
        ];
        assert_eq!(entries_summary(&items), "3 entries in 2 folders, read only");
        assert_eq!(
            entries_summary(&items[..1]),
            "1 entry in 1 folder, read only"
        );
        assert_eq!(kind_label(WalletEntryKind::Map), "map");
    }

    /// Secrets are hidden by default; collapsing a card or its folder hides them.
    #[test]
    fn reveal_is_local_and_hidden_by_default() {
        let items = vec![item("a", "x", &[]), item("b", "y", &[])];
        let s = state("w", items.clone());
        let mut v = WalletView::default();
        v.sync(&s);
        assert!(!v.is_revealed(0) && v.expanded.is_none());
        v.toggle_expanded(0);
        v.toggle_revealed(0);
        assert!(v.is_revealed(0));
        v.toggle_expanded(0);
        assert!(!v.is_revealed(0) && v.expanded.is_none());
        v.toggle_expanded(1);
        v.toggle_revealed(1);
        v.toggle_folder("a", &items);
        assert!(v.is_collapsed("a") && v.is_revealed(1), "other folder kept");
        v.toggle_folder("b", &items);
        assert!(!v.is_revealed(1) && v.expanded.is_none());
        v.toggle_folder("b", &items);
        assert!(!v.is_collapsed("b"));
    }

    /// Another wallet or reloaded entries reset the cards; the same state keeps them.
    #[test]
    fn sync_resets_on_change() {
        let mut v = WalletView::default();
        let two = vec![item("a", "x", &[]), item("a", "y", &[])];
        v.sync(&state("w", two.clone()));
        v.toggle_expanded(1);
        v.toggle_revealed(1);
        v.filter = "x".into();
        v.toggle_folder("z", &two);
        v.sync(&state("w", two.clone()));
        assert!(v.is_revealed(1) && v.expanded == Some(1));
        let mut three = two.clone();
        three.push(item("a", "z", &[]));
        v.sync(&state("w", three.clone()));
        assert!(!v.is_revealed(1) && v.expanded.is_none());
        assert_eq!(v.filter, "x");
        v.toggle_revealed(0);
        v.sync(&state("other", three));
        assert!(!v.is_revealed(0) && v.filter.is_empty() && !v.is_collapsed("z"));
        v.toggle_revealed(0);
        v.sync(&AppState::default());
        assert!(!v.is_revealed(0));
    }
}
