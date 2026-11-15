//! Validation of dialog fields and the command each dialog sends.

use std::path::{Path, PathBuf};

use kring_core::model::{ItemUpdate, NewItem, SecretValue};
use kring_core::validate;
use zeroize::Zeroizing;

use crate::app_state::FileAction;
use crate::views::dialogs::DialogKind;
use crate::views::dialogs::RestorePassphrase;
use crate::worker::Command;

/// Error of an import or transfer without a target keyring.
const MSG_NO_TARGET: &str = "Choose a target keyring";
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
/// Why Delete is disabled while the typed name does not match (no backup).
pub const MSG_TYPE_NAME: &str = "Type the file name to confirm";
/// Why a delete without backup is refused for a loaded keyring holding items.
pub const MSG_BACKUP_MANDATORY: &str = "Loaded keyrings are always backed up before deletion";

/// Returns true when `typed` is exactly the file name `name` (no trimming, case sensitive).
pub fn delete_confirm_ok(typed: &str, name: &str) -> bool {
    typed == name
}

/// Returns why the main button of a delete dialog is disabled: without a
/// backup (only when optional) the exact file name must be typed. `None`
/// for other dialogs.
pub fn delete_dialog_blocked(kind: &DialogKind) -> Option<&'static str> {
    let DialogKind::DeleteFile {
        name,
        spec,
        backup,
        typed,
        ..
    } = kind
    else {
        return None;
    };
    if *backup {
        return None;
    }
    if !spec.backup_optional {
        return Some(MSG_BACKUP_MANDATORY);
    }
    if delete_confirm_ok(typed, name) {
        return None;
    }
    Some(MSG_TYPE_NAME)
}

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
        Command::DeleteFile { name, backup, .. } => Command::DeleteFile {
            name,
            backup,
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
        DialogKind::DeleteFile {
            name,
            spec,
            backup,
            passphrase,
            confirm,
            ..
        } => {
            if let Some(reason) = delete_dialog_blocked(kind) {
                return Err(reason.into());
            }
            let backup_passphrase = match (*backup, spec.needs_passphrase) {
                (true, true) => Some(_new_password(passphrase, confirm)?),
                _ => None,
            };
            Command::DeleteFile {
                name: name.clone(),
                backup: *backup,
                backup_passphrase,
            }
        }
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
        DialogKind::TransferTarget {
            items,
            mode,
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
            Command::PlanTransfer {
                items: items.clone(),
                target: target.clone(),
                mode: *mode,
            }
        }
        DialogKind::ApplyPassphrase {
            plan_id,
            choices,
            passphrase,
            confirm,
        } => Command::ApplyTransfer {
            plan_id: *plan_id,
            choices: choices.clone(),
            // It encrypts a new backup: a new passphrase, typed twice.
            backup_passphrase: Some(_new_password(passphrase, confirm)?),
        },
        DialogKind::ConsolidatePassphrases {
            plan_id,
            choices,
            ask_backup,
            ask_orphan_files,
            backup,
            backup_confirm,
            orphan_files,
            orphan_files_confirm,
            kept_backup,
            kept_orphan_files,
        } => {
            // Both encrypt new backups: new passphrases, typed twice.
            let backup_passphrase = if *ask_backup {
                Some(_new_password(backup, backup_confirm)?)
            } else {
                kept_backup.clone()
            };
            let orphan_files_passphrase = if *ask_orphan_files {
                Some(_new_password(orphan_files, orphan_files_confirm)?)
            } else {
                kept_orphan_files.clone()
            };
            Command::ApplyConsolidation {
                plan_id: *plan_id,
                choices: choices.clone(),
                backup_passphrase,
                orphan_files_passphrase,
            }
        }
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
        let mut kind = DialogKind::export_collection(
            &col("My keys"),
            "My keys".into(),
            Path::new("/h"),
            "20261115",
        );
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
        let mut kind = DialogKind::import_archive(&col("Work"), "Work".into());
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

    /// The consolidation dialog validates only the asked passphrases and
    /// resends the kept one with the choices.
    #[test]
    fn consolidate_passphrases_keep_given_ones() {
        use crate::views::consolidate::PassphraseNeeds;
        use kring_core::transfer::plan::Choice;
        let missing = PassphraseNeeds {
            backup: true,
            orphan_files: false,
        };
        let choices = vec![vec![Choice::UseIncoming]];
        let mut kind = DialogKind::consolidate_passphrases(
            3,
            choices.clone(),
            missing,
            None,
            Some(SecretValue::from_text("orphan")),
        );
        assert!(
            command_for(&kind).is_err(),
            "empty backup passphrase rejected"
        );
        if let DialogKind::ConsolidatePassphrases {
            backup,
            backup_confirm,
            ..
        } = &mut kind
        {
            *backup = buf("bp");
            *backup_confirm = buf("bx");
        }
        assert!(
            command_for(&kind).is_err(),
            "unconfirmed passphrase rejected"
        );
        if let DialogKind::ConsolidatePassphrases { backup_confirm, .. } = &mut kind {
            *backup_confirm = buf("bp");
        }
        match command_for(&kind).unwrap() {
            Command::ApplyConsolidation {
                plan_id,
                choices: sent,
                backup_passphrase,
                orphan_files_passphrase,
            } => {
                assert_eq!(plan_id, 3);
                assert_eq!(sent, choices);
                assert_eq!(backup_passphrase.unwrap().as_text(), Some("bp"));
                assert_eq!(orphan_files_passphrase.unwrap().as_text(), Some("orphan"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Builds a delete spec.
    fn spec(needs_passphrase: bool, backup_optional: bool) -> crate::views::dialogs::DeleteSpec {
        crate::views::dialogs::DeleteSpec {
            lines: vec!["x".into()],
            needs_passphrase,
            passphrase_note: "note",
            backup_optional,
        }
    }

    /// Sets the backup flag, typed name and passphrases of a delete dialog.
    fn fill_delete(kind: &mut DialogKind, backup_on: bool, name: &str, pass: (&str, &str)) {
        let DialogKind::DeleteFile {
            backup,
            typed,
            passphrase,
            confirm,
            ..
        } = kind
        else {
            panic!("expected DeleteFile");
        };
        *backup = backup_on;
        *typed = name.to_string();
        *passphrase = buf(pass.0);
        *confirm = buf(pass.1);
    }

    /// The typed confirmation must equal the file name exactly.
    #[test]
    fn delete_confirm_requires_exact_name() {
        assert!(delete_confirm_ok("Default_keyring_3", "Default_keyring_3"));
        assert!(!delete_confirm_ok("", "Default_keyring_3"));
        assert!(!delete_confirm_ok("default_keyring_3", "Default_keyring_3"));
        assert!(!delete_confirm_ok(
            " Default_keyring_3",
            "Default_keyring_3"
        ));
        assert!(!delete_confirm_ok(
            "Default_keyring_3.keyring",
            "Default_keyring_3"
        ));
    }

    /// The backup checkbox starts checked; a binary file needs no passphrase.
    #[test]
    fn delete_binary_with_backup() {
        let kind = DialogKind::delete_file("b".into(), spec(false, true));
        assert!(matches!(kind, DialogKind::DeleteFile { backup: true, .. }));
        match command_for(&kind).unwrap() {
            Command::DeleteFile {
                name,
                backup,
                backup_passphrase,
            } => {
                assert_eq!(name, "b");
                assert!(backup);
                assert!(backup_passphrase.is_none());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// A plaintext file backed up needs a confirmed new passphrase.
    #[test]
    fn delete_plaintext_with_backup_needs_passphrase() {
        let mut kind = DialogKind::delete_file("p".into(), spec(true, true));
        assert!(command_for(&kind).is_err(), "empty passphrase rejected");
        fill_delete(&mut kind, true, "", ("pp", "pq"));
        assert!(command_for(&kind).is_err(), "mismatch rejected");
        fill_delete(&mut kind, true, "", ("pp", "pp"));
        match command_for(&kind).unwrap() {
            Command::DeleteFile {
                name,
                backup,
                backup_passphrase,
            } => {
                assert_eq!(name, "p");
                assert!(backup);
                assert_eq!(backup_passphrase.unwrap().as_text(), Some("pp"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Without a backup the exact file name must be typed; no passphrase is sent.
    #[test]
    fn delete_without_backup_needs_typed_name() {
        let mut kind = DialogKind::delete_file("p".into(), spec(true, true));
        fill_delete(&mut kind, false, "P", ("pp", "pp"));
        assert!(command_for(&kind).is_err(), "wrong name rejected");
        assert_eq!(delete_dialog_blocked(&kind), Some(MSG_TYPE_NAME));
        fill_delete(&mut kind, false, "p", ("pp", "pp"));
        assert_eq!(delete_dialog_blocked(&kind), None);
        match command_for(&kind).unwrap() {
            Command::DeleteFile {
                name,
                backup,
                backup_passphrase,
            } => {
                assert_eq!(name, "p");
                assert!(!backup);
                assert!(backup_passphrase.is_none());
            }
            other => panic!("unexpected {other:?}"),
        }
        fill_delete(&mut kind, true, "", ("", ""));
        assert_eq!(
            delete_dialog_blocked(&kind),
            None,
            "backup on: never blocked"
        );
    }

    /// When the backup is mandatory (loaded keyring with items) it cannot be skipped.
    #[test]
    fn delete_mandatory_backup_cannot_be_skipped() {
        let mut kind = DialogKind::delete_file("Default_10".into(), spec(false, false));
        fill_delete(&mut kind, false, "Default_10", ("", ""));
        assert_eq!(delete_dialog_blocked(&kind), Some(MSG_BACKUP_MANDATORY));
        assert_eq!(command_for(&kind).unwrap_err(), MSG_BACKUP_MANDATORY);
        fill_delete(&mut kind, true, "", ("", ""));
        match command_for(&kind).unwrap() {
            Command::DeleteFile {
                backup,
                backup_passphrase,
                ..
            } => assert!(backup && backup_passphrase.is_none()),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// The passphrase resend of a delete keeps the name and the backup flag.
    #[test]
    fn with_backup_passphrase_sets_delete_file() {
        let cmd = with_backup_passphrase(
            Command::DeleteFile {
                name: "p".into(),
                backup: true,
                backup_passphrase: None,
            },
            SecretValue::from_text("x"),
        );
        match cmd {
            Command::DeleteFile {
                name,
                backup,
                backup_passphrase,
            } => {
                assert_eq!(name, "p");
                assert!(backup);
                assert_eq!(backup_passphrase.unwrap().as_text(), Some("x"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
