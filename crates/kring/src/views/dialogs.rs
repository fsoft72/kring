//! Modal dialogs: password prompts, forms and confirmations.

use eframe::egui;
use kring_core::model::{CollectionId, ItemId, ItemUpdate, NewItem, SecretValue};
use kring_core::validate;
use zeroize::Zeroizing;

use crate::views::dialog_body::{FIELD_WIDTH, body};
use crate::widgets::password_field::{forget_fields, new_buffer};
use crate::worker::Command;

/// Id of the (single) open modal.
const MODAL_ID: &str = "kring-dialog";
/// Width of dialogs: field width plus room for the field labels.
const DIALOG_WIDTH: f32 = FIELD_WIDTH + 140.0;

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

/// Rejects a blank item label.
fn _item_label(label: &str) -> Result<(), String> {
    if label.trim().is_empty() {
        return Err("label must not be empty".into());
    }
    Ok(())
}

/// Returns `cmd` with its backup passphrase set (only delete commands carry one).
pub fn with_backup_passphrase(cmd: Command, passphrase: SecretValue) -> Command {
    match cmd {
        Command::DeleteItem { item, .. } => Command::DeleteItem {
            item,
            backup_passphrase: Some(passphrase),
        },
        Command::DeleteCollection { collection, .. } => Command::DeleteCollection {
            collection,
            backup_passphrase: Some(passphrase),
        },
        other => other,
    }
}

/// Converts an edited password buffer to a secret.
fn _secret(buffer: &Zeroizing<String>) -> SecretValue {
    SecretValue::from_text(buffer)
}

/// Validates a new password and its confirmation.
fn _new_password(
    new: &Zeroizing<String>,
    confirm: &Zeroizing<String>,
) -> Result<SecretValue, String> {
    let new = _secret(new);
    validate::new_password(&new, &_secret(confirm)).map_err(|e| e.to_string())?;
    Ok(new)
}

impl Dialog {
    /// Opens a dialog.
    pub fn new(kind: DialogKind) -> Self {
        Self { kind, error: None }
    }

    /// Validates the fields and builds the command to send.
    pub fn submit(&self) -> Result<Command, String> {
        let invalid = |e: kring_core::KringError| e.to_string();
        let cmd = match &self.kind {
            DialogKind::Unlock {
                collection,
                password,
                ..
            } => Command::Unlock {
                collection: collection.clone(),
                password: _secret(password),
            },
            DialogKind::CreateCollection {
                label,
                password,
                confirm,
            } => {
                validate::collection_label(label).map_err(invalid)?;
                Command::CreateCollection {
                    label: label.trim().to_string(),
                    password: _new_password(password, confirm)?,
                }
            }
            DialogKind::Rename { collection, label } => {
                validate::collection_label(label).map_err(invalid)?;
                Command::RenameCollection {
                    collection: collection.clone(),
                    label: label.trim().to_string(),
                }
            }
            DialogKind::ChangePassword {
                collection,
                old,
                new,
                confirm,
                ..
            } => Command::ChangePassword {
                collection: collection.clone(),
                old: _secret(old),
                new: _new_password(new, confirm)?,
            },
            DialogKind::DeleteCollection { collection, .. } => Command::DeleteCollection {
                collection: collection.clone(),
                backup_passphrase: None,
            },
            DialogKind::NewItem {
                collection,
                label,
                secret,
                rows,
            } => {
                _item_label(label)?;
                Command::CreateItem {
                    collection: collection.clone(),
                    item: NewItem {
                        label: label.trim().to_string(),
                        attributes: validate::attributes(rows).map_err(invalid)?,
                        secret: _secret(secret),
                        replace: false,
                    },
                }
            }
            DialogKind::EditItem {
                item,
                label,
                secret,
            } => {
                _item_label(label)?;
                Command::UpdateItem {
                    item: item.clone(),
                    update: ItemUpdate {
                        label: Some(label.trim().to_string()),
                        attributes: None,
                        secret: (!secret.is_empty()).then(|| _secret(secret)),
                    },
                }
            }
            DialogKind::DeleteItem { item, .. } => Command::DeleteItem {
                item: item.clone(),
                backup_passphrase: None,
            },
            DialogKind::Passphrase {
                command,
                passphrase,
                confirm,
            } => {
                let passphrase = _new_password(passphrase, confirm)?;
                with_backup_passphrase((**command).clone(), passphrase)
            }
        };
        Ok(cmd)
    }

    /// Renders the dialog and reports whether it closed.
    pub fn show(&mut self, ctx: &egui::Context) -> Outcome {
        let mut submit = false;
        let mut cancel = false;
        let response = egui::Modal::new(egui::Id::unique(MODAL_ID)).show(ctx, |ui| {
            ui.set_width(DIALOG_WIDTH);
            let primary = body(ui, &mut self.kind);
            if let Some(err) = &self.error {
                ui.colored_label(ui.visuals().error_fg_color, err);
            }
            ui.separator();
            ui.horizontal(|ui| {
                submit = ui.button(primary).clicked();
                cancel = ui.button("Cancel").clicked();
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
