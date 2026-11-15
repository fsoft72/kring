//! The selected collection: header, actions and item table.

use eframe::egui;
use kring_core::model::{Attributes, CollectionInfo, ItemInfo, decode_path_segment};

use crate::app_state::AppState;
use crate::ui::glyphs::Ico;
use crate::ui::theme;
use crate::ui::widgets::{chip, glyph_tile, heading, ico_button, muted, note, semibold};
use crate::views::dialogs::DialogKind;
use crate::views::item_detail::AttrEditor;
use crate::views::{Action, Gates, item_list};
use crate::worker::Command;

/// Alias of the default collection.
const DEFAULT_ALIAS: &str = "default";
/// Maximum characters of the attributes summary on an item card.
const MAX_SUMMARY_CHARS: usize = 64;
/// Chip of the default collection.
const BADGE_DEFAULT: &str = "DEFAULT";
/// Chip of the login collection.
const BADGE_LOGIN: &str = "LOGIN";
/// Chip of a locked collection.
const BADGE_LOCKED: &str = "LOCKED";
/// Tooltip of "Set as default" on the default collection.
const MSG_ALREADY_DEFAULT: &str = "Already the default keyring";
/// Warning shown when PAM does not unlock the login keyring.
const MSG_PAM_MISSING: &str = "PAM does not unlock this keyring at login";
/// Information always shown on the login keyring.
const MSG_LOGIN_PASSWORD: &str =
    "Auto-unlock works only if this keyring password equals your login password";

/// Delete warning for the login keyring.
const MSG_DELETE_LOGIN: &str = "This is your login keyring, unlocked at login";
/// Delete warning for the default keyring.
const MSG_DELETE_DEFAULT: &str = "This is the default keyring";

/// Returns the chips of a collection header (default, login, locked).
pub fn badges(c: &CollectionInfo) -> Vec<&'static str> {
    let flags = [
        (is_default(c), BADGE_DEFAULT),
        (c.is_login, BADGE_LOGIN),
        (c.locked, BADGE_LOCKED),
    ];
    flags
        .into_iter()
        .filter_map(|(on, badge)| on.then_some(badge))
        .collect()
}

/// Returns the label, or the decoded last object path segment when the label is blank.
pub fn display_name(c: &CollectionInfo) -> String {
    if !c.label.trim().is_empty() {
        return c.label.clone();
    }
    let segment = c.id.0.rsplit('/').next().unwrap_or_default();
    decode_path_segment(segment).unwrap_or_else(|_| segment.to_string())
}

/// Returns the extra warnings of the delete confirmation (login and default keyring).
pub fn delete_warnings(c: &CollectionInfo) -> Vec<&'static str> {
    let flags = [
        (c.is_login, MSG_DELETE_LOGIN),
        (is_default(c), MSG_DELETE_DEFAULT),
    ];
    flags
        .into_iter()
        .filter_map(|(on, warning)| on.then_some(warning))
        .collect()
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

/// Returns the muted subline of the header, e.g. `3 items - unlocked`.
pub fn header_subline(c: &CollectionInfo) -> String {
    let noun = if c.item_count == 1 { "item" } else { "items" };
    let lock = if c.locked { "locked" } else { "unlocked" };
    format!("{} {noun} - {lock}", c.item_count)
}

/// Renders the chips of a collection header.
fn _chips(ui: &mut egui::Ui, c: &CollectionInfo) {
    for badge in badges(c) {
        let color = if badge == BADGE_LOCKED {
            theme::TERTIARY
        } else {
            theme::SECONDARY
        };
        chip(ui, badge, color);
    }
}

/// Renders the right-aligned icon actions of a collection header.
fn _collection_actions(ui: &mut egui::Ui, c: &CollectionInfo, gates: Gates) -> Option<Action> {
    let mut action = None;
    let delete = Action::Open(DialogKind::DeleteCollection {
        collection: c.id.clone(),
        label: display_name(c),
        item_count: c.item_count,
        warnings: delete_warnings(c),
    });
    if ico_button(ui, Ico::Trash, "Delete keyring", gates.write, true) {
        action = Some(delete);
    }
    if ico_button(
        ui,
        Ico::Key,
        "Change password",
        gates.write_and_master(),
        false,
    ) {
        let kind = DialogKind::change_password(c.id.clone(), display_name(c));
        action = Some(Action::Open(kind));
    }
    if ico_button(ui, Ico::Pencil, "Rename", gates.write, false) {
        action = Some(Action::Open(DialogKind::Rename {
            collection: c.id.clone(),
            label: c.label.clone(),
        }));
    }
    let already = is_default(c).then_some(MSG_ALREADY_DEFAULT);
    if ico_button(
        ui,
        Ico::Star,
        "Set as default",
        gates.write.or(already),
        false,
    ) {
        action = Some(Action::Send(Command::SetDefault(c.id.clone())));
    }
    if c.locked {
        if ico_button(ui, Ico::Unlock, "Unlock", gates.master, false) {
            let kind = DialogKind::unlock(c.id.clone(), display_name(c));
            action = Some(Action::Open(kind));
        }
    } else if ico_button(ui, Ico::Lock, "Lock", None, false) {
        action = Some(Action::Send(Command::Lock(c.id.clone())));
    }
    action
}

/// Renders title, chips, subline and icon actions of a collection.
fn _header(ui: &mut egui::Ui, c: &CollectionInfo, gates: Gates) -> Option<Action> {
    let mut action = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.add(egui::Label::new(semibold(display_name(c), 22.0)).truncate());
        _chips(ui, c);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            action = _collection_actions(ui, c, gates);
        });
    });
    muted(ui, &header_subline(c));
    action
}

/// Renders the login keyring notes (PAM warning, password information).
fn _notes(ui: &mut egui::Ui, state: &AppState, c: &CollectionInfo) {
    if !c.is_login {
        return;
    }
    ui.add_space(4.0);
    if state.pam.as_ref().is_some_and(|p| !p.configured) {
        note(ui, theme::TERTIARY, MSG_PAM_MISSING, theme::TERTIARY);
    }
    note(ui, theme::SECONDARY, MSG_LOGIN_PASSWORD, theme::MUTED);
}

/// Renders the empty state shown when no keyring is selected.
pub fn empty_state(ui: &mut egui::Ui, state: &AppState) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        glyph_tile(ui, Ico::Lock, 64.0);
        ui.add_space(8.0);
        heading(ui, "Select a keyring");
        muted(ui, "Choose a keyring on the left or create a new one.");
        ui.add_space(12.0);
        let items: usize = state.collections.iter().map(|c| c.item_count).sum();
        let locked = state.collections.iter().filter(|c| c.locked).count();
        let total = state.collections.len();
        muted(
            ui,
            &format!("{total} keyrings - {locked} locked - {items} items"),
        );
    });
}

/// Renders the selected collection with its item cards.
pub fn show(
    ui: &mut egui::Ui,
    state: &AppState,
    filter: &mut String,
    editor: &mut AttrEditor,
    gates: Gates,
) -> Option<Action> {
    let Some(c) = state
        .selected
        .as_ref()
        .and_then(|id| state.collections.iter().find(|c| &c.id == id))
    else {
        empty_state(ui, state);
        return None;
    };
    let mut action = _header(ui, c, gates);
    _notes(ui, state, c);
    ui.add_space(10.0);
    action = item_list::show(ui, state, c, filter, editor, gates).or(action);
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
        assert_eq!(badges(&login), ["DEFAULT", "LOGIN", "LOCKED"]);
        assert!(badges(&col("/c/w", &[], false)).is_empty());
        assert_eq!(badges(&col("/c/w", &["default"], false)), ["DEFAULT"]);
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

    /// Login and default collections get their warnings, others none.
    #[test]
    fn delete_warnings_for_login_and_default() {
        let login = col(LOGIN_COLLECTION_PATH, &["default"], false);
        assert_eq!(
            delete_warnings(&login),
            [MSG_DELETE_LOGIN, MSG_DELETE_DEFAULT]
        );
        let def = col("/c/w", &["default"], false);
        assert_eq!(delete_warnings(&def), [MSG_DELETE_DEFAULT]);
        assert!(delete_warnings(&col("/c/w", &[], false)).is_empty());
    }

    /// Blank labels (such as the session collection) fall back to the path segment.
    #[test]
    fn display_name_falls_back_to_path() {
        let mut c = col("/org/freedesktop/secrets/collection/session", &[], false);
        c.label = " ".into();
        assert_eq!(display_name(&c), "session");
        let mut escaped = col("/org/freedesktop/secrets/collection/My_5fKeys", &[], false);
        escaped.label = " ".into();
        assert_eq!(display_name(&escaped), "My_Keys");
        c.label = "Mine".into();
        assert_eq!(display_name(&c), "Mine");
    }

    /// The subline counts items and states the lock.
    #[test]
    fn subline_counts_and_lock() {
        let mut c = col("/c/w", &[], true);
        assert_eq!(header_subline(&c), "0 items - locked");
        c.item_count = 1;
        c.locked = false;
        assert_eq!(header_subline(&c), "1 item - unlocked");
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
