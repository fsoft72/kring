//! Validation of dialog fields and the command each dialog sends.

use kring_core::model::{ItemUpdate, NewItem, SecretValue};
use kring_core::validate;
use zeroize::Zeroizing;

use crate::views::dialogs::DialogKind;
use crate::worker::Command;

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

/// Validates the fields of a dialog and builds the command to send.
pub fn command_for(kind: &DialogKind) -> Result<Command, String> {
    let invalid = |e: kring_core::KringError| e.to_string();
    let cmd = match kind {
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
        DialogKind::SaveAttributes {
            item, attributes, ..
        } => Command::UpdateItem {
            item: item.clone(),
            update: ItemUpdate {
                attributes: Some(attributes.clone()),
                ..ItemUpdate::default()
            },
        },
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
