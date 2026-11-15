//! "Remember for this session" support of the passphrase dialogs: which
//! dialogs offer it, the passphrase to remember from the sent command, and
//! how a remembered passphrase fills a dialog (no confirmation typed).

use eframe::egui::{self, RichText};
use kring_core::model::SecretValue;
use zeroize::Zeroizing;

use crate::session_secret::{MSG_REMEMBER, MSG_REMEMBER_WARNING};
use crate::ui::theme;
use crate::ui::widgets::secondary_button;
use crate::views::dialog_gpg::GpgDialog;
use crate::views::dialog_ssh::SshDialog;
use crate::views::dialogs::{DialogKind, RestorePassphrase, WalletTarget};
use crate::worker::Command;

/// Note shown instead of the passphrase fields when the remembered one is used.
pub const MSG_USING_REMEMBERED: &str = "Using the remembered passphrase";

/// Note shown in place of hidden backup passphrase fields.
pub const MSG_BACKUP_REMEMBERED: &str = "The backup is encrypted with the remembered passphrase";

/// Returns true when the backup note replaces the backup fields: they are
/// hidden (`hide`) and the dialog asks a backup passphrase (`backup_asked`).
pub fn shows_backup_note(hide: bool, backup_asked: bool) -> bool {
    hide && backup_asked
}
/// Button showing the passphrase fields again.
const MSG_TYPE_ANOTHER: &str = "Type another";

/// Returns true when the dialog currently shows a passphrase (or unlock
/// password) field whose value may be remembered.
pub fn asks_passphrase(kind: &DialogKind) -> bool {
    match kind {
        DialogKind::Unlock { .. }
        | DialogKind::FilePassword { .. }
        | DialogKind::WalletPassword { .. }
        | DialogKind::RetireFile { .. }
        | DialogKind::ExportCollection { .. }
        | DialogKind::ImportArchive { .. }
        | DialogKind::ApplyPassphrase { .. }
        | DialogKind::ConsolidatePassphrases { .. }
        | DialogKind::Passphrase { .. } => true,
        DialogKind::DeleteFile { spec, backup, .. } => *backup && spec.needs_passphrase,
        DialogKind::RestoreBackup { mode, .. } => *mode != RestorePassphrase::NotNeeded,
        DialogKind::ImportWallet { target, .. } => *target == Some(WalletTarget::Create),
        DialogKind::Ssh(dialog) => dialog.asks_passphrase(),
        DialogKind::Gpg(dialog) => dialog.asks_passphrase(),
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

/// Returns true for the password dialogs that reopen (fields empty, "Wrong
/// passphrase, try again") after a wrong password, even when typed: the
/// binary keyring file and KWallet wallet passwords, and the SSH and GPG
/// dialogs sending a key passphrase (they also reopen when the key turned
/// out to need one, see [`needing_key_passphrase`]).
pub fn reopens_when_wrong(kind: &DialogKind) -> bool {
    match kind {
        DialogKind::FilePassword { .. } | DialogKind::WalletPassword { .. } => true,
        DialogKind::Ssh(dialog) => dialog.reopens_when_wrong(),
        DialogKind::Gpg(dialog) => dialog.reopens_when_wrong(),
        _ => false,
    }
}

/// Returns a copy of `kind` with every passphrase field emptied (for the
/// SSH and GPG dialogs the new key passphrases too).
pub fn cleared(kind: &DialogKind) -> DialogKind {
    let mut kind = kind.clone();
    fill_passphrases(&mut kind, &SecretValue::from_text(""));
    match &mut kind {
        DialogKind::Ssh(dialog) => dialog.clear_secrets(),
        DialogKind::Gpg(dialog) => dialog.clear_secrets(),
        _ => {}
    }
    kind
}

/// Returns `kind` asking the key passphrase: an SSH or GPG dialog sent
/// without one for a key the worker found protected. Other dialogs are
/// unchanged.
pub fn needing_key_passphrase(kind: DialogKind) -> DialogKind {
    match kind {
        DialogKind::Ssh(dialog) => DialogKind::Ssh(dialog.needing_key_passphrase()),
        DialogKind::Gpg(dialog) => DialogKind::Gpg(dialog.needing_key_passphrase()),
        other => other,
    }
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
        }
        | DialogKind::ImportWallet {
            new_password: passphrase,
            confirm,
            ..
        } => {
            _set(passphrase, text);
            _set(confirm, text);
        }
        DialogKind::ImportArchive { passphrase, .. }
        | DialogKind::FilePassword {
            password: passphrase,
            ..
        }
        | DialogKind::WalletPassword {
            password: passphrase,
            ..
        } => _set(passphrase, text),
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
        DialogKind::Ssh(dialog) => dialog.fill(text),
        DialogKind::Gpg(dialog) => dialog.fill(text),
        _ => {}
    }
}

/// Returns the passphrase (or unlock password) carried by a command sent
/// from a passphrase dialog, the value to remember.
pub fn passphrase_of(cmd: &Command) -> Option<&SecretValue> {
    match cmd {
        Command::Unlock { password, .. }
        | Command::CreateWalletCollection { password, .. }
        | Command::OpenWallet { password, .. } => Some(password),
        Command::OpenFile { password, .. } | Command::ImportFile { password, .. } => {
            password.as_ref()
        }
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
        Command::AgentAdd { passphrase, .. } | Command::ExportSshPrivate { passphrase, .. } => {
            passphrase.as_ref()
        }
        // Nothing is remembered for ChangeSshPassphrase: the old passphrase no
        // longer opens the key after success and the backup one is single use.
        Command::DeleteSshKey {
            backup_passphrase, ..
        } => backup_passphrase.as_ref(),
        // As for SSH, nothing is remembered for ChangeGpgPassphrase.
        Command::ExportGpgSecret { passphrase, .. } => passphrase.as_ref(),
        Command::DeleteGpgKey {
            key_passphrase,
            backup_passphrase,
            ..
        } => key_passphrase.as_ref().or(backup_passphrase.as_ref()),
        _ => None,
    }
}

/// Returns true when the dialog offers the "Remember for this session"
/// checkbox: it asks a passphrase whose value is actually stored on submit.
/// Changing an SSH or GPG key passphrase stores nothing (see [`passphrase_of`]),
/// so no checkbox is shown there even though the remembered value can still
/// fill the old passphrase.
pub fn offers_remember(kind: &DialogKind) -> bool {
    if matches!(
        kind,
        DialogKind::Ssh(SshDialog::ChangePassphrase { .. })
            | DialogKind::Gpg(GpgDialog::ChangePassphrase { .. })
    ) {
        return false;
    }
    asks_passphrase(kind)
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

    /// The backup note replaces hidden backup fields only.
    #[test]
    fn backup_note_rules() {
        assert!(shows_backup_note(true, true));
        assert!(!shows_backup_note(true, false));
        assert!(!shows_backup_note(false, true));
        assert!(!shows_backup_note(false, false));
    }

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

    /// The wallet import dialog offers remembering only the password of the
    /// keyring it creates; the wallet password is never remembered.
    #[test]
    fn wallet_import_remembers_new_keyring_password() {
        use crate::views::dialogs::WalletTarget;
        let mut kind = DialogKind::import_wallet(
            "kdewallet".into(),
            SecretValue::from_text("wallet-pw"),
            &[],
            None,
            None,
        );
        assert!(uses_remembered(&kind));
        fill_passphrases(&mut kind, &SecretValue::from_text(PASS));
        let cmd = command_for(&kind).unwrap();
        assert!(matches!(cmd, Command::CreateWalletCollection { .. }));
        assert_eq!(passphrase_of(&cmd).unwrap().as_text(), Some(PASS));
        if let DialogKind::ImportWallet { target, .. } = &mut kind {
            *target = Some(WalletTarget::Keyring(CollectionId("/c/a".into())));
        }
        assert!(!asks_passphrase(&kind));
        let import = Command::PlanWalletImport {
            name: "kdewallet".into(),
            password: SecretValue::from_text("wallet-pw"),
            target: CollectionId("/c/a".into()),
        };
        assert!(passphrase_of(&import).is_none());
    }

    /// The wallet and keyring file password dialogs take the remembered
    /// value, offer remembering what was typed and reopen when wrong.
    #[test]
    fn password_dialogs_remember() {
        use crate::app_state::FileAction;
        let kinds = [
            DialogKind::wallet_password("w".into()),
            DialogKind::file_password("f".into(), FileAction::Open),
        ];
        for mut kind in kinds {
            assert!(uses_remembered(&kind) && reopens_when_wrong(&kind));
            fill_passphrases(&mut kind, &SecretValue::from_text(PASS));
            let cmd = command_for(&kind).unwrap();
            if matches!(cmd, Command::ChangeSshPassphrase { .. }) {
                assert!(passphrase_of(&cmd).is_none());
            } else {
                assert_eq!(passphrase_of(&cmd).unwrap().as_text(), Some(PASS));
            }
            assert!(command_for(&cleared(&kind)).is_err(), "fields emptied");
        }
        assert!(!reopens_when_wrong(&DialogKind::retire_file(
            "p".into(),
            vec![]
        )));
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

    /// The SSH change-passphrase dialog stores nothing, so it offers no
    /// "Remember" checkbox; other passphrase dialogs still do.
    #[test]
    fn change_ssh_passphrase_offers_no_remember() {
        let key = crate::views::dialog_ssh::tests::key("id", Some(true));
        let change = DialogKind::Ssh(SshDialog::change_passphrase(&key));
        assert!(asks_passphrase(&change));
        assert!(!offers_remember(&change));
        let add = DialogKind::Ssh(SshDialog::agent_add(&key));
        assert!(offers_remember(&add));
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

    /// The SSH key passphrase dialogs take the remembered passphrase and
    /// reopen when wrong; the backup passphrase of an unencrypted key is
    /// remembered too; a new key passphrase never is.
    #[test]
    fn ssh_dialogs_remember() {
        use crate::views::dialog_ssh::SshDialog;
        use crate::views::dialog_ssh::tests::key;
        let encrypted = key("k", Some(true));
        let plain = key("p", Some(false));
        let kinds = [
            (SshDialog::agent_add(&encrypted), true),
            (SshDialog::change_passphrase(&encrypted), true),
            (SshDialog::change_passphrase(&plain), true),
            (SshDialog::delete(&plain, false), false),
        ];
        for (dialog, reopens) in kinds {
            let mut kind = DialogKind::Ssh(dialog);
            assert!(uses_remembered(&kind));
            assert_eq!(reopens_when_wrong(&kind), reopens);
            fill_passphrases(&mut kind, &SecretValue::from_text(PASS));
            if let DialogKind::Ssh(SshDialog::ChangePassphrase { new, confirm, .. }) = &mut kind {
                _set(new, "new-key-pass");
                _set(confirm, "new-key-pass");
            }
            let cmd = command_for(&kind).unwrap();
            if matches!(cmd, Command::ChangeSshPassphrase { .. }) {
                assert!(passphrase_of(&cmd).is_none(), "nothing remembered");
            } else {
                assert_eq!(passphrase_of(&cmd).unwrap().as_text(), Some(PASS));
            }
            assert!(command_for(&cleared(&kind)).is_err(), "fields emptied");
        }
        let change = Command::ChangeSshPassphrase {
            name: "k".into(),
            old: Some(SecretValue::from_text(PASS)),
            new: None,
            allow_unencrypted: true,
            backup_passphrase: Some(SecretValue::from_text(PASS)),
        };
        assert!(passphrase_of(&change).is_none(), "nothing remembered");
        let mut export = SshDialog::export(&encrypted);
        if let SshDialog::Export { reencrypt, .. } = &mut export {
            *reencrypt = true;
        }
        let kind = DialogKind::Ssh(export);
        assert!(uses_remembered(&kind) && reopens_when_wrong(&kind));
        let generate = DialogKind::Ssh(SshDialog::generate(&[]));
        assert!(!asks_passphrase(&generate) && !reopens_when_wrong(&generate));
        let agent = Command::AgentAdd {
            name: "k".into(),
            passphrase: Some(SecretValue::from_text(PASS)),
            lifetime_secs: None,
        };
        assert_eq!(passphrase_of(&agent).unwrap().as_text(), Some(PASS));
    }

    /// The GPG key dialogs take the remembered passphrase (key and backup
    /// fields) and reopen when wrong; a GPG key passphrase change stores
    /// nothing; deleting a public key asks no passphrase.
    #[test]
    fn gpg_dialogs_remember() {
        use crate::views::dialog_gpg::GpgDialog;
        use crate::views::dialog_gpg::tests::{public_key, secret_key};
        let key = secret_key();
        for dialog in [GpgDialog::export_secret(&key), GpgDialog::delete(&key)] {
            let mut kind = DialogKind::Gpg(dialog);
            assert!(uses_remembered(&kind) && reopens_when_wrong(&kind));
            assert!(offers_remember(&kind));
            fill_passphrases(&mut kind, &SecretValue::from_text(PASS));
            let cmd = command_for(&kind).unwrap();
            assert_eq!(passphrase_of(&cmd).unwrap().as_text(), Some(PASS));
            let cleared = cleared(&kind);
            let again = command_for(&cleared);
            assert!(again.is_err() || passphrase_of(&again.unwrap()).is_none());
        }
        let change = DialogKind::Gpg(GpgDialog::change_passphrase(&key));
        assert!(uses_remembered(&change) && reopens_when_wrong(&change));
        assert!(!offers_remember(&change), "nothing stored");
        let change_cmd = Command::ChangeGpgPassphrase {
            fpr: key.fingerprint.clone(),
            old: Some(SecretValue::from_text(PASS)),
            new: Some(SecretValue::from_text("n")),
            backup_passphrase: Some(SecretValue::from_text(PASS)),
        };
        assert!(passphrase_of(&change_cmd).is_none());
        let public = DialogKind::Gpg(GpgDialog::delete(&public_key()));
        assert!(!asks_passphrase(&public) && !reopens_when_wrong(&public));
        let required = needing_key_passphrase(DialogKind::Gpg(GpgDialog::export_secret(&key)));
        assert!(matches!(
            required,
            DialogKind::Gpg(GpgDialog::ExportSecret {
                key_required: true,
                ..
            })
        ));
    }
}
