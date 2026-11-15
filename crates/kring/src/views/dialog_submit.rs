//! Validation of dialog fields and the command each dialog sends.

use std::path::{Path, PathBuf};

use kring_core::model::{ItemUpdate, NewItem, SecretValue};
use kring_core::validate;
use zeroize::Zeroizing;

use crate::app_state::FileAction;
use crate::views::dialogs::DialogKind;
use crate::views::dialogs::RestorePassphrase;
use crate::worker::Command;

/// Error of an import without a target keyring.
const MSG_NO_TARGET: &str = "Choose a keyring to import into";
/// Error of an import into a locked keyring.
const MSG_TARGET_LOCKED: &str = "The chosen keyring is locked, unlock it first";
/// Error of an empty file password.
const MSG_NO_PASSWORD: &str = "Enter the password of the keyring file";

/// Error of an empty archive path.
pub const MSG_NO_PATH: &str = "Enter the path of the archive file";
/// Error of a path that is not absolute.
pub const MSG_RELATIVE_PATH: &str = "Enter an absolute path (or one starting with ~/)";
/// Error of an empty archive passphrase.
pub const MSG_NO_ARCHIVE_PASSPHRASE: &str = "Enter the passphrase of the archive";
/// Error of an empty backup passphrase.
const MSG_NO_BACKUP_PASSPHRASE: &str = "Enter the passphrase of the backup";

/// Parses a path typed by the user: strips surrounding whitespace and quotes
/// (ported from Paranoid's `clean_path`).
pub fn clean_path(s: &str) -> PathBuf {
    PathBuf::from(s.trim().trim_matches('"').trim_matches('\''))
}

/// Resolves a typed path: cleaned (quotes, spaces), `~` and `~/...` expanded
/// with `home`; the result must be absolute.
pub fn typed_path(text: &str, home: Option<&Path>) -> Result<PathBuf, String> {
    let path = clean_path(text);
    if path.as_os_str().is_empty() {
        return Err(MSG_NO_PATH.into());
    }
    let path = match (path.strip_prefix("~"), home) {
        (Ok(rest), Some(home)) => home.join(rest),
        _ => path,
    };
    if !path.is_absolute() {
        return Err(MSG_RELATIVE_PATH.into());
    }
    Ok(path)
}

/// Resolves a typed path against the `HOME` of the process.
fn _user_path(text: &str) -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    typed_path(text, home.as_deref())
}

/// Returns the passphrase as a secret, or `message` when it is empty.
fn _required(buffer: &Zeroizing<String>, message: &str) -> Result<SecretValue, String> {
    if buffer.is_empty() {
        return Err(message.into());
    }
    Ok(_secret(buffer))
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
        Command::RestoreBackup { dir, files, .. } => Command::RestoreBackup {
            dir,
            files,
            passphrase: Some(passphrase),
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
        DialogKind::FilePassword {
            name,
            action,
            password,
        } => {
            if password.is_empty() {
                return Err(MSG_NO_PASSWORD.into());
            }
            let password = Some(_secret(password));
            match action {
                FileAction::Open => Command::OpenFile {
                    name: name.clone(),
                    password,
                },
                FileAction::Import { target } => Command::ImportFile {
                    name: name.clone(),
                    password,
                    target: target.clone(),
                },
            }
        }
        DialogKind::ImportFile {
            name,
            targets,
            target,
        } => {
            let Some(target) = target else {
                return Err(MSG_NO_TARGET.into());
            };
            let usable = targets.iter().any(|t| &t.id == target && !t.locked);
            if !usable {
                return Err(MSG_TARGET_LOCKED.into());
            }
            Command::ImportFile {
                name: name.clone(),
                password: None,
                target: target.clone(),
            }
        }
        DialogKind::RetireFile {
            name,
            passphrase,
            confirm,
            ..
        } => Command::RetireFile {
            name: name.clone(),
            backup_passphrase: _new_password(passphrase, confirm)?,
        },
        DialogKind::RestoreBackup {
            dir,
            files,
            mode,
            passphrase,
            confirm,
            ..
        } => {
            let passphrase = match mode {
                RestorePassphrase::NotNeeded => None,
                RestorePassphrase::Existing => {
                    Some(_required(passphrase, MSG_NO_BACKUP_PASSPHRASE)?)
                }
                RestorePassphrase::New => Some(_new_password(passphrase, confirm)?),
            };
            Command::RestoreBackup {
                dir: dir.clone(),
                files: files.clone(),
                passphrase,
            }
        }
        DialogKind::ExportCollection {
            collection,
            path,
            passphrase,
            confirm,
            ..
        } => Command::ExportCollection {
            collection: collection.clone(),
            path: _user_path(path)?,
            passphrase: _new_password(passphrase, confirm)?,
        },
        DialogKind::ImportArchive {
            target,
            path,
            passphrase,
            ..
        } => Command::ImportArchive {
            path: _user_path(path)?,
            passphrase: _required(passphrase, MSG_NO_ARCHIVE_PASSPHRASE)?,
            target: target.clone(),
        },
        DialogKind::Passphrase {
            command,
            passphrase,
            confirm,
        } => {
            // A restore asks here only to encrypt the backup of a plaintext
            // keyring it overwrites: a new passphrase, confirmed like the others.
            let passphrase = _new_password(passphrase, confirm)?;
            with_backup_passphrase((**command).clone(), passphrase)
        }
    };
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::dialogs::RestorePassphrase;
    use kring_core::model::{CollectionId, CollectionInfo};
    use std::path::{Path, PathBuf};

    /// Fills a zeroizing buffer with text.
    fn buf(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_string())
    }

    /// Builds a collection.
    fn col(label: &str) -> CollectionInfo {
        CollectionInfo {
            id: CollectionId("/c/w".into()),
            label: label.into(),
            locked: false,
            item_count: 0,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        }
    }

    /// A restore fallback with a mismatched confirmation is rejected.
    #[test]
    fn passphrase_dialog_restore_rejects_mismatch() {
        let mut kind = restore_fallback();
        if let DialogKind::Passphrase {
            passphrase,
            confirm,
            ..
        } = &mut kind
        {
            *passphrase = buf("pp");
            *confirm = buf("pq");
        }
        assert!(command_for(&kind).is_err());
        if let DialogKind::Passphrase { confirm, .. } = &mut kind {
            confirm.clear();
        }
        assert!(command_for(&kind).is_err(), "missing confirmation rejected");
    }

    /// Whitespace and surrounding quotes are removed, inner text is kept.
    #[test]
    fn clean_path_strips_quotes_and_spaces() {
        assert_eq!(
            clean_path("  /tmp/a b.age \n"),
            PathBuf::from("/tmp/a b.age")
        );
        assert_eq!(clean_path("\"/tmp/x.age\""), PathBuf::from("/tmp/x.age"));
        assert_eq!(clean_path("'/tmp/x.age'"), PathBuf::from("/tmp/x.age"));
        assert_eq!(clean_path(" \"'/tmp/q'\" "), PathBuf::from("/tmp/q"));
        assert_eq!(clean_path("/tmp/it's.age"), PathBuf::from("/tmp/it's.age"));
        assert_eq!(clean_path("   "), PathBuf::from(""));
    }

    /// Typed paths are cleaned, `~` expands to home, relative paths are refused.
    #[test]
    fn typed_paths() {
        let home = Some(Path::new("/home/me"));
        assert_eq!(
            typed_path(" '/tmp/a.age' ", home),
            Ok(PathBuf::from("/tmp/a.age"))
        );
        assert_eq!(
            typed_path("~/x.age", home),
            Ok(PathBuf::from("/home/me/x.age"))
        );
        assert_eq!(typed_path("~", home), Ok(PathBuf::from("/home/me")));
        assert_eq!(typed_path("  ", home), Err(MSG_NO_PATH.to_string()));
        assert_eq!(
            typed_path("x.age", home),
            Err(MSG_RELATIVE_PATH.to_string())
        );
        assert_eq!(typed_path("~/x", None), Err(MSG_RELATIVE_PATH.to_string()));
        assert_eq!(
            typed_path("~bob/x", home),
            Err(MSG_RELATIVE_PATH.to_string())
        );
    }

    /// Export suggests a sanitized path and needs a confirmed passphrase.
    #[test]
    fn export_validates() {
        let mut kind = DialogKind::export_collection(&col("My keys"), Path::new("/h"), "20261115");
        let DialogKind::ExportCollection { path, .. } = &kind else {
            panic!("expected ExportCollection");
        };
        assert_eq!(path, "/h/kring-My_keys-20261115.kring.age");
        assert!(command_for(&kind).is_err(), "empty passphrase rejected");
        if let DialogKind::ExportCollection {
            passphrase,
            confirm,
            path,
            ..
        } = &mut kind
        {
            *passphrase = buf("pp");
            *confirm = buf("pq");
            *path = "\"/tmp/out.kring.age\"".into();
        }
        assert!(command_for(&kind).is_err(), "mismatch rejected");
        if let DialogKind::ExportCollection { confirm, .. } = &mut kind {
            *confirm = buf("pp");
        }
        match command_for(&kind).unwrap() {
            Command::ExportCollection {
                collection,
                path,
                passphrase,
            } => {
                assert_eq!(collection.0, "/c/w");
                assert_eq!(path, PathBuf::from("/tmp/out.kring.age"));
                assert_eq!(passphrase.as_text(), Some("pp"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Archive import needs a path and a passphrase and targets the collection.
    #[test]
    fn import_archive_validates() {
        let mut kind = DialogKind::import_archive(&col("Work"));
        assert_eq!(command_for(&kind).unwrap_err(), MSG_NO_PATH);
        if let DialogKind::ImportArchive { path, .. } = &mut kind {
            *path = "/tmp/in.kring.age".into();
        }
        assert_eq!(command_for(&kind).unwrap_err(), MSG_NO_ARCHIVE_PASSPHRASE);
        if let DialogKind::ImportArchive { passphrase, .. } = &mut kind {
            *passphrase = buf("pp");
        }
        match command_for(&kind).unwrap() {
            Command::ImportArchive {
                path,
                passphrase,
                target,
            } => {
                assert_eq!(path, PathBuf::from("/tmp/in.kring.age"));
                assert_eq!(passphrase.as_text(), Some("pp"));
                assert_eq!(target.0, "/c/w");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Builds a restore dialog in `mode`.
    fn restore(mode: RestorePassphrase) -> DialogKind {
        DialogKind::restore_backup(
            "/b/1".into(),
            vec!["/x/a.keyring".into()],
            vec!["/k/a.keyring".into()],
            mode,
        )
    }

    /// Restore sends no passphrase, the backup one, or a confirmed new one.
    #[test]
    fn restore_passphrase_modes() {
        match command_for(&restore(RestorePassphrase::NotNeeded)).unwrap() {
            Command::RestoreBackup {
                dir,
                files,
                passphrase,
            } => {
                assert_eq!(dir, PathBuf::from("/b/1"));
                assert_eq!(files, [PathBuf::from("/x/a.keyring")]);
                assert!(passphrase.is_none());
            }
            other => panic!("unexpected {other:?}"),
        }
        let mut existing = restore(RestorePassphrase::Existing);
        assert!(command_for(&existing).is_err(), "empty passphrase rejected");
        if let DialogKind::RestoreBackup { passphrase, .. } = &mut existing {
            *passphrase = buf("pp");
        }
        assert!(matches!(
            command_for(&existing).unwrap(),
            Command::RestoreBackup { passphrase: Some(p), .. } if p.as_text() == Some("pp")
        ));
        let mut new = restore(RestorePassphrase::New);
        if let DialogKind::RestoreBackup { passphrase, .. } = &mut new {
            *passphrase = buf("pp");
        }
        assert!(
            command_for(&new).is_err(),
            "unconfirmed new passphrase rejected"
        );
        if let DialogKind::RestoreBackup { confirm, .. } = &mut new {
            *confirm = buf("pp");
        }
        assert!(command_for(&new).is_ok());
    }

    /// Builds the fallback passphrase dialog of a restore.
    fn restore_fallback() -> DialogKind {
        DialogKind::passphrase(Command::RestoreBackup {
            dir: "/b/1".into(),
            files: vec!["/x/a.keyring".into()],
            passphrase: None,
        })
    }

    /// The fallback passphrase dialog encrypts a new backup: it resends the
    /// restore only with a confirmed passphrase.
    #[test]
    fn passphrase_dialog_resends_restore() {
        let mut kind = restore_fallback();
        assert!(command_for(&kind).is_err(), "empty passphrase rejected");
        if let DialogKind::Passphrase {
            passphrase,
            confirm,
            ..
        } = &mut kind
        {
            *passphrase = buf("pp");
            *confirm = buf("pp");
        }
        assert!(matches!(
            command_for(&kind).unwrap(),
            Command::RestoreBackup { passphrase: Some(p), .. } if p.as_text() == Some("pp")
        ));
    }
}
