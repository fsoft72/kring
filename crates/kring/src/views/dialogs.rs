//! Modal dialogs: password prompts, forms and confirmations.

use eframe::egui;
use kring_core::model::{Attributes, CollectionId, ItemId};
use zeroize::Zeroizing;

use crate::ui::password_field::{forget_fields, new_buffer};
use crate::ui::theme;
use crate::ui::widgets::{danger_button, primary_button, secondary_button};
use crate::views::dialog_body::{FIELD_WIDTH, body};
use crate::views::dialog_submit::command_for;
use crate::worker::Command;

/// Id of the (single) open modal.
const MODAL_ID: &str = "kring-dialog";
/// Width of dialog content.
const DIALOG_WIDTH: f32 = FIELD_WIDTH;
/// Inner margin of dialogs.
const DIALOG_MARGIN: i8 = 24;
/// Opacity of the backdrop behind a dialog.
const BACKDROP_ALPHA: u8 = 150;

/// The content of a dialog. Password buffers are zeroized when it is dropped.
pub enum DialogKind {
    /// Unlock a collection with its password.
    Unlock {
        collection: CollectionId,
        label: String,
        password: Zeroizing<String>,
    },
    /// Create a password protected collection.
    CreateCollection {
        label: String,
        password: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    /// Rename a collection.
    Rename {
        collection: CollectionId,
        label: String,
    },
    /// Change the password of a collection.
    ChangePassword {
        collection: CollectionId,
        label: String,
        old: Zeroizing<String>,
        new: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    /// Confirm the deletion of a collection.
    DeleteCollection {
        collection: CollectionId,
        label: String,
        item_count: usize,
        /// Extra warnings (login or default keyring).
        warnings: Vec<&'static str>,
    },
    /// Create an item.
    NewItem {
        collection: CollectionId,
        label: String,
        secret: Zeroizing<String>,
        rows: Vec<(String, String)>,
    },
    /// Edit the label and (optionally) the secret of an item.
    EditItem {
        item: ItemId,
        label: String,
        secret: Zeroizing<String>,
    },
    /// Confirm replacing the attributes of an item, listing every change.
    SaveAttributes {
        item: ItemId,
        label: String,
        attributes: Attributes,
        changes: Vec<String>,
    },
    /// Confirm the deletion of an item.
    DeleteItem { item: ItemId, label: String },
    /// Choose a passphrase for a backup containing plaintext keyrings.
    Passphrase {
        command: Box<Command>,
        passphrase: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
}

impl DialogKind {
    /// Unlock dialog for a collection.
    pub fn unlock(collection: CollectionId, label: String) -> Self {
        Self::Unlock {
            collection,
            label,
            password: new_buffer(),
        }
    }

    /// New collection dialog.
    pub fn create_collection() -> Self {
        Self::CreateCollection {
            label: String::new(),
            password: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// Change password dialog for a collection.
    pub fn change_password(collection: CollectionId, label: String) -> Self {
        Self::ChangePassword {
            collection,
            label,
            old: new_buffer(),
            new: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// New item dialog for a collection.
    pub fn new_item(collection: CollectionId) -> Self {
        Self::NewItem {
            collection,
            label: String::new(),
            secret: new_buffer(),
            rows: Vec::new(),
        }
    }

    /// Edit dialog for an item; an empty secret keeps the current one.
    pub fn edit_item(item: ItemId, label: String) -> Self {
        Self::EditItem {
            item,
            label,
            secret: new_buffer(),
        }
    }

    /// Passphrase dialog that resends `command` with the chosen passphrase.
    pub fn passphrase(command: Command) -> Self {
        Self::Passphrase {
            command: Box::new(command),
            passphrase: new_buffer(),
            confirm: new_buffer(),
        }
    }
}

/// What happened to a dialog this frame.
pub enum Outcome {
    /// Still open.
    Open,
    /// Closed without action.
    Cancelled,
    /// Closed, the command must be sent.
    Submitted(Command),
}

/// An open dialog with its last validation error.
pub struct Dialog {
    kind: DialogKind,
    error: Option<String>,
}

impl Dialog {
    /// Opens a dialog.
    pub fn new(kind: DialogKind) -> Self {
        Self { kind, error: None }
    }

    /// Validates the fields and builds the command to send.
    pub fn submit(&self) -> Result<Command, String> {
        command_for(&self.kind)
    }

    /// Renders the dialog and reports whether it closed.
    pub fn show(&mut self, ctx: &egui::Context) -> Outcome {
        let mut submit = false;
        let mut cancel = false;
        let frame = egui::Frame::new()
            .fill(theme::SURFACE)
            .stroke(egui::Stroke::new(1.0_f32, theme::FIELD_ROW_BORDER))
            .corner_radius(egui::CornerRadius::same(theme::RADIUS_WINDOW))
            .shadow(ctx.global_style().visuals.window_shadow)
            .inner_margin(egui::Margin::same(DIALOG_MARGIN));
        let modal = egui::Modal::new(egui::Id::unique(MODAL_ID))
            .frame(frame)
            .backdrop_color(egui::Color32::from_black_alpha(BACKDROP_ALPHA));
        let response = modal.show(ctx, |ui| {
            ui.set_width(DIALOG_WIDTH);
            let main = body(ui, &mut self.kind);
            if let Some(err) = &self.error {
                ui.label(egui::RichText::new(err).color(theme::ERROR));
            }
            ui.add_space(8.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                submit = if main.danger {
                    danger_button(ui, main.text, None)
                } else {
                    primary_button(ui, main.text, None)
                };
                cancel = secondary_button(ui, "Cancel", None);
            });
        });
        if cancel || response.should_close() {
            forget_fields(ctx);
            return Outcome::Cancelled;
        }
        if !submit {
            return Outcome::Open;
        }
        match self.submit() {
            Ok(cmd) => {
                forget_fields(ctx);
                Outcome::Submitted(cmd)
            }
            Err(e) => {
                self.error = Some(e);
                Outcome::Open
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::dialog_submit::with_backup_passphrase;
    use kring_core::model::SecretValue;

    /// Fills a zeroizing buffer with text.
    fn buf(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_string())
    }

    /// Mismatched new passwords are rejected; a valid change carries both passwords.
    #[test]
    fn change_password_validates_confirmation() {
        let id = CollectionId("/c/work".into());
        let mut d = Dialog::new(DialogKind::ChangePassword {
            collection: id.clone(),
            label: "Work".into(),
            old: buf("old"),
            new: buf("a"),
            confirm: buf("b"),
        });
        assert!(d.submit().is_err());
        if let DialogKind::ChangePassword { confirm, .. } = &mut d.kind {
            *confirm = buf("a");
        }
        match d.submit().unwrap() {
            Command::ChangePassword {
                collection,
                old,
                new,
            } => {
                assert_eq!(collection, id);
                assert_eq!(old.as_text(), Some("old"));
                assert_eq!(new.as_text(), Some("a"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// A blank collection name is rejected and names are trimmed.
    #[test]
    fn create_collection_validates_label() {
        let mut d = Dialog::new(DialogKind::CreateCollection {
            label: "  ".into(),
            password: buf("p"),
            confirm: buf("p"),
        });
        assert!(d.submit().is_err());
        if let DialogKind::CreateCollection { label, .. } = &mut d.kind {
            *label = " Work ".into();
        }
        match d.submit().unwrap() {
            Command::CreateCollection { label, password } => {
                assert_eq!(label, "Work");
                assert_eq!(password.as_text(), Some("p"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Duplicate attribute keys are rejected; valid rows become attributes.
    #[test]
    fn new_item_validates_attributes() {
        let coll = CollectionId("/c/a".into());
        let mut d = Dialog::new(DialogKind::NewItem {
            collection: coll.clone(),
            label: "site".into(),
            secret: buf("s3"),
            rows: vec![("k".into(), "1".into()), ("k".into(), "2".into())],
        });
        assert!(d.submit().is_err());
        if let DialogKind::NewItem { rows, .. } = &mut d.kind {
            rows.pop();
        }
        match d.submit().unwrap() {
            Command::CreateItem { collection, item } => {
                assert_eq!(collection, coll);
                assert_eq!(item.label, "site");
                assert_eq!(item.attributes.get("k").map(String::as_str), Some("1"));
                assert_eq!(item.secret.as_text(), Some("s3"));
                assert!(!item.replace);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// An empty secret in the edit dialog keeps the current secret.
    #[test]
    fn edit_item_empty_secret_unchanged() {
        let d = Dialog::new(DialogKind::edit_item(ItemId("/c/a/1".into()), "new".into()));
        match d.submit().unwrap() {
            Command::UpdateItem { update, .. } => {
                assert_eq!(update.label.as_deref(), Some("new"));
                assert!(update.secret.is_none());
                assert!(update.attributes.is_none());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// The passphrase dialog resends the original command with the passphrase set.
    #[test]
    fn passphrase_resends_command() {
        let original = Command::DeleteCollection {
            collection: CollectionId("/c/a".into()),
            backup_passphrase: None,
        };
        let mut d = Dialog::new(DialogKind::passphrase(original));
        assert!(d.submit().is_err(), "empty passphrase rejected");
        if let DialogKind::Passphrase {
            passphrase,
            confirm,
            ..
        } = &mut d.kind
        {
            *passphrase = buf("pp");
            *confirm = buf("pp");
        }
        match d.submit().unwrap() {
            Command::DeleteCollection {
                backup_passphrase, ..
            } => assert_eq!(backup_passphrase.unwrap().as_text(), Some("pp")),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Confirming attribute changes updates only the attributes.
    #[test]
    fn save_attributes_updates_attributes_only() {
        let d = Dialog::new(DialogKind::SaveAttributes {
            item: ItemId("/c/a/1".into()),
            label: "x".into(),
            attributes: [("k".to_string(), "v".to_string())].into(),
            changes: vec!["Added: k = v".into()],
        });
        match d.submit().unwrap() {
            Command::UpdateItem { item, update } => {
                assert_eq!(item, ItemId("/c/a/1".into()));
                assert!(update.label.is_none() && update.secret.is_none());
                assert_eq!(update.attributes.unwrap().get("k").unwrap(), "v");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Delete item carries the passphrase too; other commands are unchanged.
    #[test]
    fn with_backup_passphrase_only_for_deletes() {
        let cmd = with_backup_passphrase(
            Command::DeleteItem {
                item: ItemId("/c/a/1".into()),
                backup_passphrase: None,
            },
            SecretValue::from_text("x"),
        );
        assert!(matches!(
            cmd,
            Command::DeleteItem {
                backup_passphrase: Some(_),
                ..
            }
        ));
        let cmd = with_backup_passphrase(Command::Refresh, SecretValue::from_text("x"));
        assert!(matches!(cmd, Command::Refresh));
    }
}
