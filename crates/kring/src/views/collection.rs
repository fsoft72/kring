//! The selected collection: header, actions and item table.

use eframe::egui;
use kring_core::model::{Attributes, CollectionInfo, ItemInfo};

use crate::app_state::AppState;
use crate::views::dialogs::DialogKind;
use crate::views::{Action, Gates, gated_button};
use crate::worker::Command;

/// Alias of the default collection.
const DEFAULT_ALIAS: &str = "default";
/// Maximum characters of the attributes summary in the item table.
const MAX_SUMMARY_CHARS: usize = 40;
/// Height of the item table.
const TABLE_HEIGHT: f32 = 220.0;
/// Tooltip of item actions while the collection is locked.
const MSG_LOCKED: &str = "Unlock the collection first";
/// Tooltip of item actions without a selected item.
const MSG_NO_ITEM: &str = "Select an item first";
/// Warning shown when PAM does not unlock the login keyring.
const MSG_PAM_MISSING: &str = "PAM does not unlock this keyring at login";
/// Information always shown on the login keyring.
const MSG_LOGIN_PASSWORD: &str =
    "Auto-unlock works only if this keyring password equals your login password";

/// Returns the badges of a collection header.
pub fn badges(c: &CollectionInfo) -> Vec<&'static str> {
    let flags = [
        (is_default(c), "[default]"),
        (c.is_login, "[login keyring]"),
        (c.locked, "[locked]"),
    ];
    flags
        .into_iter()
        .filter_map(|(on, badge)| on.then_some(badge))
        .collect()
}

/// Returns the label, or the last object path segment when the label is blank.
pub fn display_name(c: &CollectionInfo) -> String {
    if !c.label.trim().is_empty() {
        return c.label.clone();
    }
    c.id.0.rsplit('/').next().unwrap_or_default().to_string()
}

/// Returns true when the collection is the default one.
pub fn is_default(c: &CollectionInfo) -> bool {
    c.aliases.iter().any(|a| a == DEFAULT_ALIAS)
}

/// Summarises attributes as `key=value, ...`, truncated for the table.
pub fn attributes_summary(attributes: &Attributes) -> String {
    let joined = attributes
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ");
    if joined.chars().count() <= MAX_SUMMARY_CHARS {
        return joined;
    }
    let mut short: String = joined.chars().take(MAX_SUMMARY_CHARS).collect();
    short.push_str("...");
    short
}

/// Formats unix seconds as `YYYY-MM-DD` (UTC); `-` when unknown.
pub fn format_date(secs: u64) -> String {
    if secs == 0 {
        return "-".into();
    }
    i64::try_from(secs)
        .ok()
        .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
        .map_or_else(|| "-".into(), |dt| dt.date().to_string())
}

/// Returns true when the label or an attribute contains `filter` (case-insensitive).
pub fn matches_filter(item: &ItemInfo, filter: &str) -> bool {
    let needle = filter.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    let hit = |text: &str| text.to_lowercase().contains(&needle);
    hit(&item.label) || item.attributes.iter().any(|(k, v)| hit(k) || hit(v))
}

/// Renders header, badges and notices of a collection.
fn _header(ui: &mut egui::Ui, state: &AppState, c: &CollectionInfo) {
    ui.horizontal_wrapped(|ui| {
        ui.heading(display_name(c));
        for badge in badges(c) {
            ui.label(egui::RichText::new(badge).strong());
        }
    });
    if !c.is_login {
        return;
    }
    if state.pam.as_ref().is_some_and(|p| !p.configured) {
        ui.colored_label(ui.visuals().warn_fg_color, MSG_PAM_MISSING);
    }
    ui.weak(MSG_LOGIN_PASSWORD);
}

/// Renders the collection action buttons.
fn _collection_actions(ui: &mut egui::Ui, c: &CollectionInfo, gates: Gates) -> Option<Action> {
    let mut action = None;
    ui.horizontal_wrapped(|ui| {
        if c.locked {
            if gated_button(ui, "Unlock", gates.master) {
                let kind = DialogKind::unlock(c.id.clone(), display_name(c));
                action = Some(Action::Open(kind));
            }
        } else if ui.button("Lock").clicked() {
            action = Some(Action::Send(Command::Lock(c.id.clone())));
        }
        let already = is_default(c).then_some("Already the default collection");
        if gated_button(ui, "Set as default", gates.write.or(already)) {
            action = Some(Action::Send(Command::SetDefault(c.id.clone())));
        }
        if gated_button(ui, "Rename", gates.write) {
            action = Some(Action::Open(DialogKind::Rename {
                collection: c.id.clone(),
                label: c.label.clone(),
            }));
        }
        if gated_button(ui, "Change password", gates.write_and_master()) {
            let kind = DialogKind::change_password(c.id.clone(), display_name(c));
            action = Some(Action::Open(kind));
        }
        if gated_button(ui, "Delete", gates.write) {
            action = Some(Action::Open(DialogKind::DeleteCollection {
                collection: c.id.clone(),
                label: display_name(c),
                item_count: c.item_count,
            }));
        }
    });
    action
}

/// Renders the item table; returns the clicked item action.
fn _item_table(ui: &mut egui::Ui, state: &AppState, filter: &str) -> Option<Action> {
    let mut action = None;
    egui::ScrollArea::vertical()
        .id_salt("kring-items")
        .max_height(TABLE_HEIGHT)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            egui::Grid::new("kring-item-grid")
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Label");
                    ui.strong("Attributes");
                    ui.strong("Modified");
                    ui.end_row();
                    for item in state.items.iter().filter(|i| matches_filter(i, filter)) {
                        let selected = state.selected_item.as_ref() == Some(&item.id);
                        if ui.selectable_label(selected, &item.label).clicked() {
                            action = Some(Action::SelectItem(item.id.clone()));
                        }
                        ui.label(attributes_summary(&item.attributes));
                        ui.label(format_date(item.modified));
                        ui.end_row();
                    }
                });
        });
    action
}

/// Renders the item action buttons.
fn _item_actions(
    ui: &mut egui::Ui,
    state: &AppState,
    c: &CollectionInfo,
    gates: Gates,
) -> Option<Action> {
    let locked = c.locked.then_some(MSG_LOCKED);
    let selected = state
        .selected_item
        .as_ref()
        .and_then(|id| state.items.iter().find(|i| &i.id == id));
    let no_item = selected.is_none().then_some(MSG_NO_ITEM);
    let mut action = None;
    ui.horizontal(|ui| {
        if gated_button(ui, "New item", gates.write.or(locked)) {
            action = Some(Action::Open(DialogKind::new_item(c.id.clone())));
        }
        let blocked = gates.write.or(locked).or(no_item);
        if gated_button(ui, "Edit", blocked)
            && let Some(item) = selected
        {
            let kind = DialogKind::edit_item(item.id.clone(), item.label.clone());
            action = Some(Action::Open(kind));
        }
        if gated_button(ui, "Delete item", blocked)
            && let Some(item) = selected
        {
            action = Some(Action::Open(DialogKind::DeleteItem {
                item: item.id.clone(),
                label: item.label.clone(),
            }));
        }
    });
    action
}

/// Renders the selected collection (without the item detail).
pub fn show(ui: &mut egui::Ui, state: &AppState, filter: &str, gates: Gates) -> Option<Action> {
    let Some(c) = state
        .selected
        .as_ref()
        .and_then(|id| state.collections.iter().find(|c| &c.id == id))
    else {
        ui.weak("Select a collection");
        return None;
    };
    _header(ui, state, c);
    let mut action = _collection_actions(ui, c, gates);
    ui.separator();
    action = _item_table(ui, state, filter).or(action);
    action = _item_actions(ui, state, c, gates).or(action);
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use kring_core::model::{CollectionId, ItemId, LOGIN_COLLECTION_PATH};

    /// Builds a collection.
    fn col(path: &str, aliases: &[&str], locked: bool) -> CollectionInfo {
        CollectionInfo {
            id: CollectionId(path.into()),
            label: "x".into(),
            locked,
            item_count: 0,
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            is_login: path == LOGIN_COLLECTION_PATH,
            created: 0,
            modified: 0,
        }
    }

    /// Badges follow default alias, login and lock state, in that order.
    #[test]
    fn badges_in_order() {
        let login = col(LOGIN_COLLECTION_PATH, &["default", "login"], true);
        assert_eq!(badges(&login), ["[default]", "[login keyring]", "[locked]"]);
        assert!(badges(&col("/c/w", &[], false)).is_empty());
        assert_eq!(badges(&col("/c/w", &["default"], false)), ["[default]"]);
    }

    /// Attributes are joined and long summaries are truncated with an ellipsis.
    #[test]
    fn summary_joins_and_truncates() {
        let attrs: Attributes =
            [("a".to_string(), "1".to_string()), ("b".into(), "2".into())].into();
        assert_eq!(attributes_summary(&attrs), "a=1, b=2");
        let long: Attributes = [("k".to_string(), "v".repeat(100))].into();
        let s = attributes_summary(&long);
        assert_eq!(s.chars().count(), MAX_SUMMARY_CHARS + 3);
        assert!(s.ends_with("..."));
        assert_eq!(attributes_summary(&Attributes::new()), "");
    }

    /// Blank labels (such as the session collection) fall back to the path segment.
    #[test]
    fn display_name_falls_back_to_path() {
        let mut c = col("/org/freedesktop/secrets/collection/session", &[], false);
        c.label = " ".into();
        assert_eq!(display_name(&c), "session");
        c.label = "Mine".into();
        assert_eq!(display_name(&c), "Mine");
    }

    /// Dates are shown as YYYY-MM-DD; zero is unknown.
    #[test]
    fn dates_formatted() {
        assert_eq!(format_date(1_759_363_200), "2025-10-02");
        assert_eq!(format_date(0), "-");
    }

    /// The filter matches label, keys and values case-insensitively; empty matches all.
    #[test]
    fn filter_matches_label_and_attributes() {
        let item = ItemInfo {
            id: ItemId("/c/a/1".into()),
            collection: CollectionId("/c/a".into()),
            label: "GitHub token".into(),
            attributes: [("service".to_string(), "gh".to_string())].into(),
            locked: false,
            created: 0,
            modified: 0,
        };
        assert!(matches_filter(&item, ""));
        assert!(matches_filter(&item, "github"));
        assert!(matches_filter(&item, "SERVICE"));
        assert!(matches_filter(&item, "gh"));
        assert!(!matches_filter(&item, "gitlab"));
    }
}
