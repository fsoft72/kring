//! Field layout of each dialog kind.

use eframe::egui::{self, RichText};
use kring_core::model::CollectionId;
use zeroize::Zeroizing;

use crate::app_state::FileAction;
use crate::ui::password_field::{
    FIELD_CONFIRM, FIELD_OLD, FIELD_PASSWORD, FIELD_SECRET, password_field,
};
use crate::ui::theme;
use crate::ui::widgets::{field_label, input, semibold};
use crate::views::dialogs::{DialogKind, ImportTarget};
use crate::views::item_detail::attribute_rows;

/// Width of dialog content.
pub const FIELD_WIDTH: f32 = 380.0;
/// Size of dialog titles.
const TITLE_SIZE: f32 = 18.0;

/// Main action of a dialog: button text and whether it is destructive.
pub struct MainAction {
    /// Button text.
    pub text: &'static str,
    /// True for destructive actions (danger button instead of primary).
    pub danger: bool,
}

/// Non-destructive main action.
fn _primary(text: &'static str) -> MainAction {
    MainAction {
        text,
        danger: false,
    }
}

/// Destructive main action (danger button).
fn _danger(text: &'static str) -> MainAction {
    MainAction { text, danger: true }
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

/// Adds a field label above a password field with an eye toggle.
fn _password_field(ui: &mut egui::Ui, label: &str, field: &str, buffer: &mut Zeroizing<String>) {
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

/// Renders the fields of a dialog and returns its main action.
pub fn body(ui: &mut egui::Ui, kind: &mut DialogKind) -> MainAction {
    match kind {
        DialogKind::Unlock {
            label, password, ..
        } => {
            _title(ui, &format!("Unlock \"{label}\""));
            _password_field(ui, "Password", FIELD_PASSWORD, password);
            _primary("Unlock")
        }
        DialogKind::CreateCollection {
            label,
            password,
            confirm,
        } => {
            _title(ui, "New keyring");
            _text_field(ui, "Name", label);
            _password_field(ui, "Password", FIELD_PASSWORD, password);
            _password_field(ui, "Confirm password", FIELD_CONFIRM, confirm);
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
            _password_field(ui, "Current password", FIELD_OLD, old);
            _password_field(ui, "New password", FIELD_PASSWORD, new);
            _password_field(ui, "Confirm new password", FIELD_CONFIRM, confirm);
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
            _password_field(ui, "Secret", FIELD_SECRET, secret);
            field_label(ui, "Attributes");
            attribute_rows(ui, "kring-new-item-attrs", rows);
            _primary("Create")
        }
        DialogKind::EditItem { label, secret, .. } => {
            _title(ui, "Edit item");
            _text_field(ui, "Label", label);
            _password_field(ui, "New secret", FIELD_SECRET, secret);
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
                "This keyring file is encrypted. The password is used once and not kept.",
            );
            _password_field(ui, "Keyring password", FIELD_PASSWORD, password);
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
            _muted(
                ui,
                "Identical items are skipped. Items whose attributes exist with another \
                 secret are listed as conflicts and never overwritten.",
            );
            _primary("Import")
        }
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
            _password_field(ui, "Backup passphrase", FIELD_PASSWORD, passphrase);
            _password_field(ui, "Confirm passphrase", FIELD_CONFIRM, confirm);
            _danger("Retire")
        }
        DialogKind::Passphrase {
            passphrase,
            confirm,
            ..
        } => {
            _title(ui, "Backup passphrase");
            ui.label(
                RichText::new("Backup contains plaintext keyrings, choose a passphrase")
                    .color(theme::TERTIARY),
            );
            _password_field(ui, "Passphrase", FIELD_PASSWORD, passphrase);
            _password_field(ui, "Confirm passphrase", FIELD_CONFIRM, confirm);
            _primary("Continue")
        }
    }
}
