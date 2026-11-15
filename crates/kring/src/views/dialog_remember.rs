//! "Remember for this session" support of the passphrase dialogs: which
//! dialogs offer it, the passphrase to remember from the sent command, and
//! how a remembered passphrase fills a dialog (no confirmation typed).

use eframe::egui::{self, RichText};
use kring_core::model::SecretValue;
use zeroize::Zeroizing;

use crate::session_secret::{MSG_REMEMBER, MSG_REMEMBER_WARNING};
use crate::ui::theme;
use crate::ui::widgets::secondary_button;
use crate::views::dialogs::{DialogKind, RestorePassphrase};
use crate::worker::Command;

/// Note shown instead of the passphrase fields when the remembered one is used.
pub const MSG_USING_REMEMBERED: &str = "Using the remembered passphrase";
/// Button showing the passphrase fields again.
const MSG_TYPE_ANOTHER: &str = "Type another";

/// Returns true when the dialog currently shows a passphrase (or unlock
/// password) field whose value may be remembered.
pub fn asks_passphrase(kind: &DialogKind) -> bool {
    match kind {
        DialogKind::Unlock { .. }
        | DialogKind::RetireFile { .. }
        | DialogKind::ExportCollection { .. }
        | DialogKind::ImportArchive { .. }
        | DialogKind::ApplyPassphrase { .. }
        | DialogKind::ConsolidatePassphrases { .. }
        | DialogKind::Passphrase { .. } => true,
        DialogKind::DeleteFile { spec, backup, .. } => *backup && spec.needs_passphrase,
        DialogKind::RestoreBackup { mode, .. } => *mode != RestorePassphrase::NotNeeded,
        _ => false,
    }
}

/// Returns true when a dialog opened by the user may use the remembered
/// passphrase instead of its fields: every passphrase dialog except the
/// unlock one (an unlock is first tried with it, its dialog opens only
/// after that failed).
pub fn uses_remembered(kind: &DialogKind) -> bool {
    !matches!(kind, DialogKind::Unlock { .. }) && asks_passphrase(kind)
}

/// Replaces `buffer` with `text`.
fn _set(buffer: &mut Zeroizing<String>, text: &str) {
    buffer.clear();
    buffer.push_str(text);
}

/// Fills every passphrase field of the dialog (and its confirmation) with
/// `secret`, so a new-backup passphrase needs no confirmation typed. A
/// non-text secret leaves the fields as they are.
pub fn fill_passphrases(kind: &mut DialogKind, secret: &SecretValue) {
    let Some(text) = secret.as_text() else {
        return;
    };
    match kind {
        DialogKind::RetireFile {
            passphrase,
            confirm,
            ..
        }
        | DialogKind::DeleteFile {
            passphrase,
            confirm,
            ..
        }
        | DialogKind::RestoreBackup {
            passphrase,
            confirm,
            ..
        }
        | DialogKind::ExportCollection {
            passphrase,
            confirm,
            ..
        }
        | DialogKind::ApplyPassphrase {
            passphrase,
            confirm,
            ..
        }
        | DialogKind::Passphrase {
            passphrase,
            confirm,
            ..
        } => {
            _set(passphrase, text);
            _set(confirm, text);
        }
        DialogKind::ImportArchive { passphrase, .. } => _set(passphrase, text),
        DialogKind::ConsolidatePassphrases {
            backup,
            backup_confirm,
            orphan_files,
            orphan_files_confirm,
            ..
        } => {
            for buffer in [backup, backup_confirm, orphan_files, orphan_files_confirm] {
                _set(buffer, text);
            }
        }
        _ => {}
    }
}

/// Returns the passphrase (or unlock password) carried by a command sent
/// from a passphrase dialog, the value to remember.
pub fn passphrase_of(cmd: &Command) -> Option<&SecretValue> {
    match cmd {
        Command::Unlock { password, .. } => Some(password),
        Command::RetireFile {
            backup_passphrase, ..
        }
        | Command::ExportCollection {
            passphrase: backup_passphrase,
            ..
        }
        | Command::ImportArchive {
            passphrase: backup_passphrase,
            ..
        } => Some(backup_passphrase),
        Command::DeleteItem {
            backup_passphrase, ..
        }
        | Command::DeleteCollection {
            backup_passphrase, ..
        }
        | Command::DeleteFile {
            backup_passphrase, ..
        }
        | Command::ApplyTransfer {
            backup_passphrase, ..
        }
        | Command::RestoreBackup {
            passphrase: backup_passphrase,
            ..
        } => backup_passphrase.as_ref(),
        Command::ApplyConsolidation {
            backup_passphrase,
            orphan_files_passphrase,
            ..
        } => backup_passphrase
            .as_ref()
            .or(orphan_files_passphrase.as_ref()),
        _ => None,
    }
}

/// Renders the "Remember for this session" checkbox and its TERTIARY warning.
pub fn remember_row(ui: &mut egui::Ui, remember: &mut bool) {
    ui.add_space(4.0);
    ui.checkbox(remember, RichText::new(MSG_REMEMBER).color(theme::TEXT));
    ui.label(
        RichText::new(MSG_REMEMBER_WARNING)
            .color(theme::TERTIARY)
            .size(12.5),
    );
}

/// Renders the note shown instead of the passphrase fields; returns true
/// when "Type another" was clicked (show the fields again).
pub fn remembered_row(ui: &mut egui::Ui) -> bool {
    ui.add_space(4.0);
    let mut clicked = false;
    ui.horizontal(|ui| {
        ui.label(RichText::new(MSG_USING_REMEMBERED).color(theme::TERTIARY));
        clicked = secondary_button(ui, MSG_TYPE_ANOTHER, None);
    });
    clicked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::dialog_submit::command_for;
    use crate::views::dialogs::DeleteSpec;
    use kring_core::model::{CollectionId, ItemId};
    use std::path::PathBuf;

    /// Remembered test value.
    const PASS: &str = "remembered-pass";

    /// Delete dialog of a file, with or without passphrase need.
    fn delete_file(needs_passphrase: bool) -> DialogKind {
        DialogKind::delete_file(
            "p".into(),
            DeleteSpec {
                lines: vec![],
                needs_passphrase,
                passphrase_note: "",
                backup_optional: true,
            },
        )
    }

    /// Passphrase dialogs offer it; others (or one without a passphrase) do not.
    #[test]
    fn which_dialogs_ask() {
        let unlock = DialogKind::unlock(CollectionId("/c/a".into()), "a".into());
        assert!(asks_passphrase(&unlock));
        assert!(!uses_remembered(&unlock));
        assert!(uses_remembered(&DialogKind::retire_file(
            "p".into(),
            vec![]
        )));
        assert!(uses_remembered(&delete_file(true)));
        assert!(!asks_passphrase(&delete_file(false)));
        let mut no_backup = delete_file(true);
        if let DialogKind::DeleteFile { backup, .. } = &mut no_backup {
            *backup = false;
        }
        assert!(!asks_passphrase(&no_backup));
        let restore = |mode| DialogKind::restore_backup(PathBuf::new(), vec![], vec![], mode);
        assert!(!asks_passphrase(&restore(RestorePassphrase::NotNeeded)));
        assert!(uses_remembered(&restore(RestorePassphrase::Existing)));
        assert!(!asks_passphrase(&DialogKind::DeleteItem {
            item: ItemId("/c/a/1".into()),
            label: "x".into(),
        }));
        assert!(!asks_passphrase(&DialogKind::create_collection()));
    }

    /// A filled new-backup dialog submits without a typed confirmation.
    #[test]
    fn fill_skips_confirmation() {
        let mut kind = DialogKind::retire_file("p".into(), vec![]);
        assert!(command_for(&kind).is_err());
        fill_passphrases(&mut kind, &SecretValue::from_text(PASS));
        let Ok(Command::RetireFile {
            backup_passphrase, ..
        }) = command_for(&kind)
        else {
            panic!("expected a retire");
        };
        assert_eq!(backup_passphrase.as_text(), Some(PASS));
    }

    /// Both consolidation passphrases are filled.
    #[test]
    fn fill_consolidation() {
        let needs = crate::views::consolidate::PassphraseNeeds {
            backup: true,
            orphan_files: true,
        };
        let mut kind = DialogKind::consolidate_passphrases(1, vec![], needs, None, None);
        fill_passphrases(&mut kind, &SecretValue::from_text(PASS));
        let Ok(cmd) = command_for(&kind) else {
            panic!("expected an apply");
        };
        let Command::ApplyConsolidation {
            backup_passphrase,
            orphan_files_passphrase,
            ..
        } = &cmd
        else {
            panic!("expected an apply");
        };
        assert_eq!(backup_passphrase.as_ref().unwrap().as_text(), Some(PASS));
        assert_eq!(
            orphan_files_passphrase.as_ref().unwrap().as_text(),
            Some(PASS)
        );
        assert_eq!(passphrase_of(&cmd).unwrap().as_text(), Some(PASS));
    }

    /// The value to remember comes from the passphrase fields of the command.
    #[test]
    fn passphrase_of_commands() {
        let pass = || SecretValue::from_text(PASS);
        let unlock = Command::Unlock {
            collection: CollectionId("/c/a".into()),
            password: pass(),
        };
        assert_eq!(passphrase_of(&unlock).unwrap().as_text(), Some(PASS));
        let restore = Command::RestoreBackup {
            dir: PathBuf::new(),
            files: vec![],
            passphrase: Some(pass()),
        };
        assert_eq!(passphrase_of(&restore).unwrap().as_text(), Some(PASS));
        let none = Command::DeleteItem {
            item: ItemId("/c/a/1".into()),
            backup_passphrase: None,
        };
        assert!(passphrase_of(&none).is_none());
        assert!(passphrase_of(&Command::Refresh).is_none());
    }
}
