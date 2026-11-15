//! Field layout of each dialog kind.

use eframe::egui::{self, RichText};
use kring_core::model::CollectionId;
use kring_core::transfer::apply::TransferMode;
use zeroize::Zeroizing;

use crate::app_state::FileAction;
use crate::ui::password_field::{
    FIELD_CONFIRM, FIELD_OLD, FIELD_PASSWORD, FIELD_SECOND, FIELD_SECOND_CONFIRM, FIELD_SECRET,
    password_field,
};
use crate::ui::theme;
use crate::ui::widgets::{field_label, input, semibold};
use crate::views::dialog_submit::delete_dialog_blocked;
use crate::views::dialogs::RestorePassphrase;
use crate::views::dialogs::{DialogKind, ImportTarget, WalletTarget};
use crate::views::item_detail::attribute_rows;
use crate::views::wallet_detail::{create_option_label, wallet_keyring_info};
use crate::worker::Command;

/// Width of dialog content.
pub const FIELD_WIDTH: f32 = 380.0;
/// Passphrase request of a restore overwriting a plaintext keyring.
const MSG_RESTORE_PLAINTEXT: &str =
    "A plaintext keyring will be overwritten: its backup is encrypted, choose a passphrase";
/// Hint of the archive path fields.
const MSG_PATH_HINT: &str = "Full path, e.g. ~/kring-export.kring.age";
/// Note of the import dialogs about conflicts.
const MSG_IMPORT_CONFLICTS: &str = "Identical items are skipped. Items whose attributes exist \
     with another secret are shown for review before anything changes.";
/// Note of the move target picker.
const MSG_MOVE_NOTE: &str = "Each item is removed from this keyring once it is safely in the \
     target. A backup of both keyrings is taken first.";
/// Note of the copy target picker.
const MSG_COPY_NOTE: &str = "Items are added to the target; this keyring is not changed. \
     Conflicts are shown for review first.";
/// Passphrase request of a consolidation backup holding plaintext keyrings.
const MSG_CONSOLIDATE_BACKUP: &str = "A backup of all keyring files is taken first. It \
     contains plaintext keyrings, choose a passphrase to encrypt it.";
/// Passphrase request of the retired orphan files.
const MSG_CONSOLIDATE_ORPHANS: &str = "The empty plaintext files are retired with one \
     encrypted backup, choose its passphrase.";
/// Warning of a delete without backup.
const MSG_DELETE_NO_BACKUP: &str = "Permanent deletion: no backup will be made";
/// Note of the wallet import dialog when the keyring is created first.
const MSG_CREATE_THEN_IMPORT: &str = "The keyring is created and unlocked, then the import \
     continues into it.";
/// Size of dialog titles.
const TITLE_SIZE: f32 = 18.0;

/// Main action of a dialog: button text and whether it is destructive.
pub struct MainAction {
    /// Button text.
    pub text: &'static str,
    /// True for destructive actions (danger button instead of primary).
    pub danger: bool,
    /// Why the button is disabled (shown as its tooltip), `None` when enabled.
    pub blocked: Option<&'static str>,
}

/// Non-destructive main action.
fn _primary(text: &'static str) -> MainAction {
    MainAction {
        text,
        danger: false,
        blocked: None,
    }
}

/// Destructive main action (danger button).
fn _danger(text: &'static str) -> MainAction {
    MainAction {
        text,
        danger: true,
        blocked: None,
    }
}

/// Adds the dialog title.
fn _title(ui: &mut egui::Ui, text: &str) {
    ui.label(semibold(text, TITLE_SIZE));
    ui.add_space(4.0);
}

/// Adds body text in TEXT colour.
fn _text(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::TEXT));
}

/// Adds muted body text.
fn _muted(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::MUTED).size(12.5));
}

/// Adds a field label above a single-line text field.
fn _text_field(ui: &mut egui::Ui, label: &str, text: &mut String) {
    field_label(ui, label);
    ui.add(input(text).desired_width(f32::INFINITY));
}

/// Adds a field label above a single-line monospace path field.
fn _path_field(ui: &mut egui::Ui, label: &str, text: &mut String, hint: &str) {
    field_label(ui, label);
    ui.add(
        input(text)
            .font(egui::TextStyle::Monospace)
            .hint_text(RichText::new(hint).color(theme::MUTED.gamma_multiply(0.7)))
            .desired_width(f32::INFINITY),
    );
}

/// Adds a field label above a password field with an eye toggle; nothing
/// when `hide` (the remembered passphrase is used instead).
fn _password_field(
    ui: &mut egui::Ui,
    hide: bool,
    label: &str,
    field: &str,
    buffer: &mut Zeroizing<String>,
) {
    if hide {
        return;
    }
    field_label(ui, label);
    password_field(ui, field, buffer, "");
}

/// Combo of import targets; locked keyrings are shown disabled with "(locked)".
fn _target_combo(ui: &mut egui::Ui, targets: &[ImportTarget], target: &mut Option<CollectionId>) {
    let selected = targets
        .iter()
        .find(|t| Some(&t.id) == target.as_ref())
        .map_or_else(|| "Choose a keyring".to_string(), |t| t.label.clone());
    egui::ComboBox::from_id_salt("kring-import-target")
        .selected_text(selected)
        .width(FIELD_WIDTH)
        .show_ui(ui, |ui| {
            for t in targets {
                let text = if t.locked {
                    format!("{} (locked)", t.label)
                } else {
                    t.label.clone()
                };
                let checked = Some(&t.id) == target.as_ref();
                ui.add_enabled_ui(!t.locked, |ui| {
                    if ui.selectable_label(checked, text).clicked() {
                        *target = Some(t.id.clone());
                    }
                });
            }
        });
}

/// Combo of wallet import targets: "Create keyring '<wallet>'" first when
/// `offer_create` (disabled with `create_blocked` as tooltip), then every
/// keyring, locked ones disabled with "(locked)".
fn _wallet_target_combo(
    ui: &mut egui::Ui,
    name: &str,
    targets: &[ImportTarget],
    target: &mut Option<WalletTarget>,
    offer_create: bool,
    create_blocked: Option<&'static str>,
) {
    let create = create_option_label(name);
    let selected = match target.as_ref() {
        Some(WalletTarget::Create) => create.clone(),
        Some(WalletTarget::Keyring(id)) => targets
            .iter()
            .find(|t| &t.id == id)
            .map_or_else(|| "Choose a keyring".to_string(), |t| t.label.clone()),
        None => "Choose a keyring".to_string(),
    };
    egui::ComboBox::from_id_salt("kring-wallet-target")
        .selected_text(selected)
        .width(FIELD_WIDTH)
        .show_ui(ui, |ui| {
            if offer_create {
                let checked = *target == Some(WalletTarget::Create);
                let resp = ui
                    .add_enabled_ui(create_blocked.is_none(), |ui| {
                        ui.selectable_label(checked, create.as_str())
                    })
                    .inner;
                if resp.clicked() {
                    *target = Some(WalletTarget::Create);
                }
                if let Some(reason) = create_blocked {
                    resp.on_disabled_hover_text(reason);
                }
            }
            for t in targets {
                let text = if t.locked {
                    format!("{} (locked)", t.label)
                } else {
                    t.label.clone()
                };
                let checked = *target == Some(WalletTarget::Keyring(t.id.clone()));
                ui.add_enabled_ui(!t.locked, |ui| {
                    if ui.selectable_label(checked, text).clicked() {
                        *target = Some(WalletTarget::Keyring(t.id.clone()));
                    }
                });
            }
        });
}

/// Renders the wallet import dialog: target combo, the info line when no
/// keyring is labelled like the wallet, then the new keyring password
/// fields (Create) or the conflicts note (import). `hide` leaves out the
/// password fields (the remembered passphrase is used).
fn _import_wallet(ui: &mut egui::Ui, kind: &mut DialogKind, hide: bool) -> MainAction {
    let DialogKind::ImportWallet {
        name,
        targets,
        target,
        offer_create,
        create_blocked,
        new_password,
        confirm,
        ..
    } = kind
    else {
        return _primary("Import");
    };
    _title(ui, &format!("Import \"{name}\""));
    _text(ui, "Copy the entries of this wallet into a keyring.");
    field_label(ui, "Target keyring");
    _wallet_target_combo(ui, name, targets, target, *offer_create, *create_blocked);
    if *offer_create {
        ui.label(
            RichText::new(wallet_keyring_info(name))
                .color(theme::TERTIARY)
                .size(12.5),
        );
    }
    if *target != Some(WalletTarget::Create) {
        _muted(ui, MSG_IMPORT_CONFLICTS);
        return _primary("Import");
    }
    _password_field(
        ui,
        hide,
        "New keyring password",
        FIELD_PASSWORD,
        new_password,
    );
    _password_field(ui, hide, "Confirm password", FIELD_CONFIRM, confirm);
    _muted(ui, MSG_CREATE_THEN_IMPORT);
    MainAction {
        blocked: *create_blocked,
        .._primary("Create keyring")
    }
}

/// Renders the fields of a dialog and returns its main action; `hide`
/// leaves out the passphrase fields (the remembered passphrase is used);
/// `retry` (reopened after a wrong remembered passphrase) drops the
/// new-passphrase wording of the backup passphrase dialog.
pub fn body(ui: &mut egui::Ui, kind: &mut DialogKind, hide: bool, retry: bool) -> MainAction {
    match kind {
        DialogKind::Unlock {
            label, password, ..
        } => {
            _title(ui, &format!("Unlock \"{label}\""));
            _password_field(ui, false, "Password", FIELD_PASSWORD, password);
            _primary("Unlock")
        }
        DialogKind::CreateCollection {
            label,
            password,
            confirm,
        } => {
            _title(ui, "New keyring");
            _text_field(ui, "Name", label);
            _password_field(ui, false, "Password", FIELD_PASSWORD, password);
            _password_field(ui, false, "Confirm password", FIELD_CONFIRM, confirm);
            _primary("Create")
        }
        DialogKind::Rename { label, .. } => {
            _title(ui, "Rename keyring");
            _text_field(ui, "Name", label);
            _primary("Rename")
        }
        DialogKind::ChangePassword {
            label,
            old,
            new,
            confirm,
            ..
        } => {
            _title(ui, &format!("Change password of \"{label}\""));
            _password_field(ui, false, "Current password", FIELD_OLD, old);
            _password_field(ui, false, "New password", FIELD_PASSWORD, new);
            _password_field(ui, false, "Confirm new password", FIELD_CONFIRM, confirm);
            _primary("Change password")
        }
        DialogKind::DeleteCollection {
            label,
            item_count,
            warnings,
            ..
        } => {
            _title(ui, "Delete keyring");
            _text(
                ui,
                &format!("Delete the keyring \"{label}\" and its {item_count} item(s)?"),
            );
            for warning in warnings.iter() {
                ui.label(RichText::new(*warning).color(theme::TERTIARY));
            }
            _muted(ui, "A backup of the keyring files is created first.");
            _danger("Delete")
        }
        DialogKind::NewItem {
            label,
            secret,
            rows,
            ..
        } => {
            _title(ui, "New item");
            _text_field(ui, "Label", label);
            _password_field(ui, false, "Secret", FIELD_SECRET, secret);
            field_label(ui, "Attributes");
            attribute_rows(ui, "kring-new-item-attrs", rows);
            _primary("Create")
        }
        DialogKind::EditItem { label, secret, .. } => {
            _title(ui, "Edit item");
            _text_field(ui, "Label", label);
            _password_field(ui, false, "New secret", FIELD_SECRET, secret);
            _muted(ui, "Leave the secret empty to keep the current one.");
            _primary("Save")
        }
        DialogKind::SaveAttributes { label, changes, .. } => {
            _title(ui, "Save attributes");
            _text(ui, &format!("Replace the attributes of \"{label}\":"));
            for change in changes.iter() {
                ui.label(
                    RichText::new(change)
                        .monospace()
                        .size(12.5)
                        .color(theme::TEXT),
                );
            }
            _primary("Save")
        }
        DialogKind::DeleteItem { label, .. } => {
            _title(ui, "Delete item");
            _text(ui, &format!("Delete the item \"{label}\"?"));
            _muted(ui, "A backup of the keyring files is created first.");
            _danger("Delete")
        }
        DialogKind::FilePassword {
            name,
            action,
            password,
        } => {
            let verb = match action {
                FileAction::Open => "Open",
                FileAction::Import { .. } => "Import",
            };
            _title(ui, &format!("{verb} \"{name}.keyring\""));
            _muted(
                ui,
                "This keyring file is encrypted. Its password is not kept unless you remember it below.",
            );
            _password_field(ui, hide, "Keyring password", FIELD_PASSWORD, password);
            _primary(verb)
        }
        DialogKind::ImportFile {
            name,
            targets,
            target,
        } => {
            _title(ui, &format!("Import \"{name}.keyring\""));
            _text(ui, "Copy the items of this file into a keyring.");
            field_label(ui, "Target keyring");
            _target_combo(ui, targets, target);
            _muted(ui, MSG_IMPORT_CONFLICTS);
            _primary("Import")
        }
        DialogKind::WalletPassword { name, password } => {
            _title(ui, &format!("Open \"{name}\""));
            _muted(
                ui,
                "kring decrypts the wallet file itself, KWallet is not used. The password \
                 stays in memory until the wallet is closed.",
            );
            _password_field(ui, hide, "Wallet password", FIELD_PASSWORD, password);
            _primary("Open")
        }
        DialogKind::ImportWallet { .. } => _import_wallet(ui, kind, hide),
        DialogKind::RetireFile {
            name,
            lines,
            passphrase,
            confirm,
        } => {
            _title(ui, &format!("Retire \"{name}.keyring\""));
            for line in lines.iter() {
                _text(ui, line);
            }
            _password_field(ui, hide, "Backup passphrase", FIELD_PASSWORD, passphrase);
            _password_field(ui, hide, "Confirm passphrase", FIELD_CONFIRM, confirm);
            _danger("Retire")
        }
        DialogKind::DeleteFile { .. } => {
            let blocked = delete_dialog_blocked(kind);
            _delete_file(ui, kind, hide);
            MainAction {
                blocked,
                .._danger("Delete")
            }
        }
        DialogKind::RestoreBackup {
            destinations,
            mode,
            passphrase,
            confirm,
            ..
        } => {
            _title(ui, "Restore backup");
            _text(
                ui,
                "These files will be overwritten (new ones are created):",
            );
            for dest in destinations.iter() {
                ui.label(
                    RichText::new(dest)
                        .monospace()
                        .size(12.5)
                        .color(theme::TEXT),
                );
            }
            _muted(
                ui,
                "The current versions are backed up first. Restart gnome-keyring afterwards.",
            );
            match mode {
                RestorePassphrase::NotNeeded => {}
                RestorePassphrase::Existing => {
                    _password_field(ui, hide, "Backup passphrase", FIELD_PASSWORD, passphrase);
                    _muted(
                        ui,
                        "Encrypted copies need the passphrase they were backed up with. It \
                         also encrypts the backup of plaintext files overwritten now.",
                    );
                }
                RestorePassphrase::New => {
                    ui.label(RichText::new(MSG_RESTORE_PLAINTEXT).color(theme::TERTIARY));
                    _password_field(ui, hide, "Passphrase", FIELD_PASSWORD, passphrase);
                    _password_field(ui, hide, "Confirm passphrase", FIELD_CONFIRM, confirm);
                }
            }
            _danger("Restore")
        }
        DialogKind::ExportCollection {
            label,
            path,
            passphrase,
            confirm,
            ..
        } => {
            _title(ui, &format!("Export \"{label}\""));
            _text(
                ui,
                "Every item, with its secret, is written to an age-encrypted archive.",
            );
            _path_field(ui, "Archive file", path, MSG_PATH_HINT);
            _password_field(ui, hide, "Archive passphrase", FIELD_PASSWORD, passphrase);
            _password_field(ui, hide, "Confirm passphrase", FIELD_CONFIRM, confirm);
            _muted(ui, "An existing file is never overwritten.");
            _primary("Export")
        }
        DialogKind::ImportArchive {
            label,
            path,
            passphrase,
            ..
        } => {
            _title(ui, &format!("Import an archive into \"{label}\""));
            _path_field(ui, "Archive file", path, MSG_PATH_HINT);
            _password_field(ui, hide, "Archive passphrase", FIELD_PASSWORD, passphrase);
            _muted(ui, MSG_IMPORT_CONFLICTS);
            _primary("Import")
        }
        DialogKind::TransferTarget {
            items,
            mode,
            targets,
            target,
        } => {
            let noun = if items.len() == 1 { "item" } else { "items" };
            let (verb, note) = match mode {
                TransferMode::Copy => ("Copy", MSG_COPY_NOTE),
                TransferMode::Move => ("Move", MSG_MOVE_NOTE),
            };
            _title(ui, &format!("{verb} {} {noun} to...", items.len()));
            field_label(ui, "Target keyring");
            _target_combo(ui, targets, target);
            _muted(ui, note);
            _primary("Preview")
        }
        DialogKind::ApplyPassphrase {
            passphrase,
            confirm,
            ..
        } => {
            _title(ui, "Backup passphrase");
            ui.label(
                RichText::new(
                    "A backup is taken before applying. It contains plaintext keyrings, \
                     choose a passphrase to encrypt it.",
                )
                .color(theme::TERTIARY),
            );
            _password_field(ui, hide, "Passphrase", FIELD_PASSWORD, passphrase);
            _password_field(ui, hide, "Confirm passphrase", FIELD_CONFIRM, confirm);
            _danger("Apply (backup first)")
        }
        DialogKind::ConsolidatePassphrases {
            ask_backup,
            ask_orphan_files,
            backup,
            backup_confirm,
            orphan_files,
            orphan_files_confirm,
            ..
        } => {
            _title(ui, "Consolidation passphrases");
            if *ask_backup {
                ui.label(RichText::new(MSG_CONSOLIDATE_BACKUP).color(theme::TERTIARY));
                _password_field(ui, hide, "Backup passphrase", FIELD_PASSWORD, backup);
                _password_field(
                    ui,
                    hide,
                    "Confirm passphrase",
                    FIELD_CONFIRM,
                    backup_confirm,
                );
            }
            if *ask_orphan_files {
                ui.add_space(4.0);
                ui.label(RichText::new(MSG_CONSOLIDATE_ORPHANS).color(theme::TERTIARY));
                _password_field(
                    ui,
                    hide,
                    "Orphan files passphrase",
                    FIELD_SECOND,
                    orphan_files,
                );
                _password_field(
                    ui,
                    hide,
                    "Confirm passphrase",
                    FIELD_SECOND_CONFIRM,
                    orphan_files_confirm,
                );
            }
            _danger("Consolidate (backup first)")
        }
        DialogKind::Ssh(dialog) => dialog.body(ui, hide),
        DialogKind::Passphrase {
            command,
            passphrase,
            confirm,
        } => {
            _title(ui, "Backup passphrase");
            let text = if matches!(**command, Command::RestoreBackup { .. }) {
                MSG_RESTORE_PLAINTEXT
            } else {
                "Backup contains plaintext keyrings, choose a passphrase"
            };
            if !retry {
                ui.label(RichText::new(text).color(theme::TERTIARY));
            }
            _password_field(ui, hide, "Passphrase", FIELD_PASSWORD, passphrase);
            _password_field(ui, hide, "Confirm passphrase", FIELD_CONFIRM, confirm);
            _primary("Continue")
        }
    }
}

/// Renders the delete confirmation of a keyring file: the body lines, the
/// backup checkbox (only when the backup is optional), then either the
/// backup passphrase (when the backup needs one) or the red warning and the
/// typed name confirmation (no backup). `hide` leaves out the passphrase fields.
fn _delete_file(ui: &mut egui::Ui, kind: &mut DialogKind, hide: bool) {
    let DialogKind::DeleteFile {
        name,
        spec,
        backup,
        typed,
        passphrase,
        confirm,
    } = kind
    else {
        return;
    };
    _title(ui, &format!("Delete {name}"));
    for line in spec.lines.iter() {
        _text(ui, line);
    }
    if spec.backup_optional {
        ui.checkbox(
            backup,
            RichText::new("Back up the file before deleting").color(theme::TEXT),
        );
    } else {
        *backup = true;
    }
    if *backup {
        if spec.needs_passphrase {
            ui.label(RichText::new(spec.passphrase_note).color(theme::TERTIARY));
            _password_field(ui, hide, "Backup passphrase", FIELD_PASSWORD, passphrase);
            _password_field(ui, hide, "Confirm passphrase", FIELD_CONFIRM, confirm);
        }
        return;
    }
    ui.label(RichText::new(MSG_DELETE_NO_BACKUP).color(theme::ERROR));
    ui.add_space(4.0);
    // Not a `field_label`: it uppercases, and the name must be typed with its exact case.
    _text(ui, &format!("Type {name} to confirm"));
    ui.add(input(typed).desired_width(f32::INFINITY));
}
