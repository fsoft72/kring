//! Detail of the selected item: secret and editable attributes.

use eframe::egui::{self, RichText};
use kring_core::model::{CollectionInfo, ItemId, ItemInfo};
use kring_core::transfer::apply::TransferMode;
use kring_core::validate;

use crate::app_state::AppState;
use crate::secret_display::{SecretView, can_copy, secret_display};
use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;
use crate::ui::widgets::{
    add_button, danger_button, field_label, ico_button, input, primary_button, secondary_button,
};
use crate::views::attr_diff::attribute_diff;
use crate::views::collection::display_name;
use crate::views::dialogs::DialogKind;
use crate::views::transfer::copy_blocked;
use crate::views::{Action, Gates};
use crate::worker::Command;

/// Text shown instead of a hidden secret.
const MASK: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";
/// Body text of a card whose keyring is locked.
const MSG_UNLOCK_TO_SEE: &str = "Unlock the keyring to see secrets";
/// Room taken by the trash button of an attribute row.
const TRASH_ROOM: f32 = 36.0;
/// Share of an attribute row taken by the key field.
const KEY_SHARE: f32 = 0.38;
/// Room taken by each icon button next to the secret.
const SECRET_BUTTONS_ROOM: f32 = 36.0;
/// Error shown when saving unchanged attributes.
const MSG_NO_CHANGES: &str = "No attribute changes";
/// Tooltip of Copy for binary secrets.
const MSG_BINARY: &str = "Binary secrets cannot be copied";

/// Edited attribute rows of the selected item.
#[derive(Default)]
pub struct AttrEditor {
    item: Option<ItemId>,
    modified: u64,
    rows: Vec<(String, String)>,
    error: Option<String>,
}

impl AttrEditor {
    /// Reloads the rows when another item is selected or the item changed on the bus.
    pub fn sync(&mut self, item: &ItemInfo) {
        if self.item.as_ref() == Some(&item.id) && self.modified == item.modified {
            return;
        }
        self.item = Some(item.id.clone());
        self.modified = item.modified;
        self.rows = item
            .attributes
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        self.error = None;
    }

    /// Returns true when the rows differ from the stored attributes (invalid
    /// rows count as changed, so Save can report the validation error).
    pub fn is_dirty(&self, item: &ItemInfo) -> bool {
        match validate::attributes(&self.rows) {
            Ok(attributes) => attributes != item.attributes,
            Err(_) => true,
        }
    }

    /// Validates the rows and builds the confirmation listing every attribute change.
    pub fn confirm_dialog(&self, item: &ItemInfo) -> Result<DialogKind, String> {
        let attributes = validate::attributes(&self.rows).map_err(|e| e.to_string())?;
        let diff = attribute_diff(&item.attributes, &attributes);
        if diff.is_empty() {
            return Err(MSG_NO_CHANGES.into());
        }
        Ok(DialogKind::SaveAttributes {
            item: item.id.clone(),
            label: item.label.clone(),
            attributes,
            changes: diff.lines(),
        })
    }
}

/// Editable key/value rows with trash buttons and an "Add attribute" button.
pub fn attribute_rows(ui: &mut egui::Ui, id_salt: &str, rows: &mut Vec<(String, String)>) {
    let mut remove = None;
    ui.push_id(id_salt, |ui| {
        for (index, (key, value)) in rows.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                let free = ui.available_width() - TRASH_ROOM;
                let key_width = (free * KEY_SHARE).max(80.0);
                ui.add(input(key).hint_text("key").desired_width(key_width));
                let value_width = ui.available_width() - TRASH_ROOM;
                ui.add(input(value).hint_text("value").desired_width(value_width));
                if ico_button(ui, Ico::Trash, "Remove attribute", None, true) {
                    remove = Some(index);
                }
            });
        }
    });
    if let Some(index) = remove {
        rows.remove(index);
    }
    if add_button(ui, "Add attribute", None) {
        rows.push((String::new(), String::new()));
    }
}

/// Renders the secret value box with Show/Hide and Copy.
fn _secret_row(ui: &mut egui::Ui, state: &AppState, item: &ItemInfo) -> Option<Action> {
    let view = state
        .revealed
        .as_ref()
        .filter(|(id, _)| *id == item.id)
        .map(|(_, secret)| secret_display(secret));
    let mut action = None;
    field_label(ui, "Secret");
    ui.horizontal(|ui| {
        let width = ui.available_width() - 2.0 * SECRET_BUTTONS_ROOM;
        value_box(ui, view.as_ref(), width);
        if view.is_some() {
            if ico_button(ui, Ico::EyeOff, "Hide", None, false) {
                action = Some(Action::HideSecret);
            }
        } else if ico_button(ui, Ico::Eye, "Show", None, false) {
            action = Some(Action::Send(Command::RevealSecret(item.id.clone())));
        }
        let binary = view
            .as_ref()
            .is_some_and(|v| !can_copy(v))
            .then_some(MSG_BINARY);
        if ico_button(ui, Ico::Copy, "Copy (clears in 30 s)", binary, false) {
            action = Some(Action::CopySecret);
        }
    });
    action
}

/// Sunken box showing the masked, revealed or binary secret in monospace.
pub fn value_box(ui: &mut egui::Ui, view: Option<&SecretView>, width: f32) {
    egui::Frame::new()
        .fill(theme::INPUT_FILL)
        .stroke(egui::Stroke::new(1.0_f32, theme::FIELD_ROW_BORDER))
        .corner_radius(egui::CornerRadius::same(theme::RADIUS_CTRL))
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.set_width(width - 22.0);
            let text = match view {
                None => RichText::new(MASK).color(theme::MUTED),
                Some(SecretView::Text(text)) => RichText::new(text.as_str()).color(theme::TEXT),
                Some(SecretView::Binary { len, hex }) => {
                    RichText::new(format!("binary ({len} bytes)  {}", hex.as_str()))
                        .color(theme::TEXT)
                }
            };
            ui.add(egui::Label::new(text.monospace()).wrap());
        });
}

/// Renders the body of a card whose keyring is locked.
fn _locked_body(ui: &mut egui::Ui, c: &CollectionInfo, gates: Gates) -> Option<Action> {
    let mut action = None;
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
        glyphs::paint(ui.painter(), r, Ico::Lock, theme::LABEL);
        ui.label(RichText::new(MSG_UNLOCK_TO_SEE).color(theme::MUTED));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if primary_button(ui, "Unlock", gates.master) {
                let kind = DialogKind::unlock(c.id.clone(), display_name(c));
                action = Some(Action::Open(kind));
            }
        });
    });
    action
}

/// Renders "Copy to..." and "Move to..." for this one item.
fn _transfer_buttons(
    ui: &mut egui::Ui,
    state: &AppState,
    c: &CollectionInfo,
    item: &ItemInfo,
    gates: Gates,
) -> Option<Action> {
    let copy = copy_blocked(state, &c.id);
    let picker = |mode| {
        let items = vec![item.id.clone()];
        Action::Open(DialogKind::transfer_target(
            items,
            mode,
            &state.collections,
            &c.id,
        ))
    };
    let mut action = None;
    if secondary_button(ui, "Copy to...", copy) {
        action = Some(picker(TransferMode::Copy));
    }
    if secondary_button(ui, "Move to...", gates.write.or(copy)) {
        action = Some(picker(TransferMode::Move));
    }
    action
}

/// Renders Copy to / Move to on the left and Edit, Delete and Save on the right.
fn _footer(
    ui: &mut egui::Ui,
    state: &AppState,
    c: &CollectionInfo,
    item: &ItemInfo,
    editor: &mut AttrEditor,
    gates: Gates,
) -> Option<Action> {
    let mut action = None;
    let size = egui::vec2(ui.available_width(), ui.spacing().interact_size.y);
    let layout = egui::Layout::right_to_left(egui::Align::Center);
    ui.allocate_ui_with_layout(size, layout, |ui| {
        let unchanged = (!editor.is_dirty(item)).then_some(MSG_NO_CHANGES);
        if primary_button(ui, "Save", gates.write.or(unchanged)) {
            match editor.confirm_dialog(item) {
                Ok(kind) => {
                    editor.error = None;
                    action = Some(Action::Open(kind));
                }
                Err(e) => editor.error = Some(e),
            }
        }
        if danger_button(ui, "Delete", gates.write) {
            action = Some(Action::Open(DialogKind::DeleteItem {
                item: item.id.clone(),
                label: item.label.clone(),
            }));
        }
        if secondary_button(ui, "Edit label / secret", gates.write) {
            let kind = DialogKind::edit_item(item.id.clone(), item.label.clone());
            action = Some(Action::Open(kind));
        }
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            let found = _transfer_buttons(ui, state, c, item, gates);
            action = found.or(action.take());
        });
    });
    action
}

/// Renders the expanded body of the selected item card.
pub fn show(
    ui: &mut egui::Ui,
    state: &AppState,
    c: &CollectionInfo,
    item: &ItemInfo,
    editor: &mut AttrEditor,
    gates: Gates,
) -> Option<Action> {
    ui.add_space(6.0);
    divider(ui);
    ui.add_space(6.0);
    if item.locked || c.locked {
        return _locked_body(ui, c, gates);
    }
    editor.sync(item);
    let mut action = _secret_row(ui, state, item);
    ui.add_space(6.0);
    field_label(ui, "Attributes");
    attribute_rows(ui, "kring-item-attrs", &mut editor.rows);
    if let Some(err) = &editor.error {
        ui.label(RichText::new(err).color(theme::ERROR));
    }
    ui.add_space(4.0);
    action = _footer(ui, state, c, item, editor, gates).or(action);
    action
}

/// Hairline separator in FIELD_ROW_BORDER across the available width.
pub fn divider(ui: &mut egui::Ui) {
    let (r, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
    ui.painter().rect_filled(r, 0.0, theme::FIELD_ROW_BORDER);
}

#[cfg(test)]
mod tests {
    use super::*;
    use kring_core::model::CollectionId;

    /// Builds an item with one attribute.
    fn item(id: &str, modified: u64, value: &str) -> ItemInfo {
        ItemInfo {
            id: ItemId(id.into()),
            collection: CollectionId("/c/a".into()),
            label: "x".into(),
            attributes: [("k".to_string(), value.to_string())].into(),
            locked: false,
            created: 0,
            modified,
        }
    }

    /// Edits survive frames of the same item and reset on another item or a bus change.
    #[test]
    fn sync_keeps_edits_until_item_changes() {
        let mut e = AttrEditor::default();
        e.sync(&item("/c/a/1", 1, "v"));
        assert_eq!(e.rows, vec![("k".to_string(), "v".to_string())]);
        e.rows[0].1 = "edited".into();
        e.sync(&item("/c/a/1", 1, "v"));
        assert_eq!(e.rows[0].1, "edited");
        e.sync(&item("/c/a/1", 2, "w"));
        assert_eq!(e.rows[0].1, "w");
        e.rows[0].1 = "edited".into();
        e.sync(&item("/c/a/2", 2, "z"));
        assert_eq!(e.rows[0].1, "z");
    }

    /// Edited, added or invalid rows make the editor dirty; synced rows do not.
    #[test]
    fn dirty_tracks_changes() {
        let it = item("/c/a/1", 1, "v");
        let mut e = AttrEditor::default();
        e.sync(&it);
        assert!(!e.is_dirty(&it));
        e.rows[0].1 = "w".into();
        assert!(e.is_dirty(&it));
        e.rows[0].1 = "v".into();
        assert!(!e.is_dirty(&it));
        e.rows.push((String::new(), String::new()));
        assert!(e.is_dirty(&it));
    }

    /// Saving opens a confirmation listing the changes; no changes is an error.
    #[test]
    fn confirm_lists_changes() {
        let it = item("/c/a/1", 1, "v");
        let mut e = AttrEditor::default();
        e.sync(&it);
        assert_eq!(e.confirm_dialog(&it).err().as_deref(), Some(MSG_NO_CHANGES));
        e.rows.push((" ".into(), "x".into()));
        assert!(e.confirm_dialog(&it).is_err());
        e.rows.pop();
        e.rows[0].1 = "w".into();
        e.rows.push(("n".into(), "1".into()));
        match e.confirm_dialog(&it).unwrap() {
            DialogKind::SaveAttributes {
                item,
                attributes,
                changes,
                ..
            } => {
                assert_eq!(item, it.id);
                assert_eq!(attributes.get("k").unwrap(), "w");
                assert_eq!(changes, ["Changed: k: v -> w", "Added: n = 1"]);
            }
            _ => panic!("expected SaveAttributes"),
        }
    }
}
