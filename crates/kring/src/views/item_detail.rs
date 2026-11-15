//! Detail of the selected item: secret and editable attributes.

use eframe::egui;
use kring_core::model::{ItemId, ItemInfo, ItemUpdate};
use kring_core::validate;

use crate::app_state::AppState;
use crate::secret_display::{SecretView, can_copy, secret_display};
use crate::views::{Action, Gates, gated_button};
use crate::worker::Command;

/// Text shown instead of a hidden secret.
const MASK: &str = "********";
/// Tooltip of secret actions on a locked item.
const MSG_LOCKED: &str = "Unlock the collection first";
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

    /// Validates the rows and builds the update command.
    pub fn save_command(&self) -> Result<Command, String> {
        let Some(item) = &self.item else {
            return Err("no item selected".into());
        };
        let attributes = validate::attributes(&self.rows).map_err(|e| e.to_string())?;
        Ok(Command::UpdateItem {
            item: item.clone(),
            update: ItemUpdate {
                attributes: Some(attributes),
                ..ItemUpdate::default()
            },
        })
    }
}

/// Editable key/value rows with remove buttons and an "Add attribute" button.
pub fn attribute_rows(ui: &mut egui::Ui, id_salt: &str, rows: &mut Vec<(String, String)>) {
    let mut remove = None;
    egui::Grid::new(id_salt).num_columns(3).show(ui, |ui| {
        for (index, (key, value)) in rows.iter_mut().enumerate() {
            ui.add(egui::TextEdit::singleline(key).hint_text("key"));
            ui.add(egui::TextEdit::singleline(value).hint_text("value"));
            if ui.small_button("x").on_hover_text("Remove").clicked() {
                remove = Some(index);
            }
            ui.end_row();
        }
    });
    if let Some(index) = remove {
        rows.remove(index);
    }
    if ui.small_button("Add attribute").clicked() {
        rows.push((String::new(), String::new()));
    }
}

/// Renders the secret row with Show/Hide and Copy.
fn _secret_row(ui: &mut egui::Ui, state: &AppState, item: &ItemInfo) -> Option<Action> {
    let locked = item.locked.then_some(MSG_LOCKED);
    let view = state
        .revealed
        .as_ref()
        .filter(|(id, _)| *id == item.id)
        .map(|(_, secret)| secret_display(secret));
    let mut action = None;
    ui.horizontal(|ui| {
        ui.label("Secret:");
        match &view {
            None => ui.monospace(MASK),
            Some(SecretView::Text(text)) => ui.monospace(text.as_str()),
            Some(SecretView::Binary { len, hex }) => {
                ui.monospace(format!("binary, {len} bytes: {}", hex.as_str()))
            }
        };
        if view.is_some() {
            if ui.button("Hide").clicked() {
                action = Some(Action::HideSecret);
            }
        } else if gated_button(ui, "Show", locked) {
            action = Some(Action::Send(Command::RevealSecret(item.id.clone())));
        }
        let binary = view
            .as_ref()
            .is_some_and(|v| !can_copy(v))
            .then_some(MSG_BINARY);
        if gated_button(ui, "Copy", locked.or(binary)) {
            action = Some(Action::CopySecret);
        }
    });
    action
}

/// Renders the detail of the selected item.
pub fn show(
    ui: &mut egui::Ui,
    state: &AppState,
    editor: &mut AttrEditor,
    gates: Gates,
) -> Option<Action> {
    let selected = state.selected_item.as_ref()?;
    let item = state.items.iter().find(|i| &i.id == selected)?;
    editor.sync(item);
    ui.heading(&item.label);
    let mut action = _secret_row(ui, state, item);
    ui.add_space(6.0);
    ui.label("Attributes:");
    attribute_rows(ui, "kring-item-attrs", &mut editor.rows);
    if let Some(err) = &editor.error {
        ui.colored_label(ui.visuals().error_fg_color, err);
    }
    let blocked = gates.write.or(item.locked.then_some(MSG_LOCKED));
    if gated_button(ui, "Save attributes", blocked) {
        match editor.save_command() {
            Ok(cmd) => {
                editor.error = None;
                action = Some(Action::Send(cmd));
            }
            Err(e) => editor.error = Some(e),
        }
    }
    action
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

    /// Saving validates keys and updates only the attributes.
    #[test]
    fn save_validates_and_updates_attributes_only() {
        let mut e = AttrEditor::default();
        e.sync(&item("/c/a/1", 1, "v"));
        e.rows.push((" ".into(), "x".into()));
        assert!(e.save_command().is_err());
        e.rows.pop();
        match e.save_command().unwrap() {
            Command::UpdateItem { item, update } => {
                assert_eq!(item, ItemId("/c/a/1".into()));
                assert!(update.label.is_none() && update.secret.is_none());
                assert_eq!(update.attributes.unwrap().get("k").unwrap(), "v");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
