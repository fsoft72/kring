//! Field layout of each dialog kind.

use eframe::egui::{self, RichText};
use zeroize::Zeroizing;

use crate::ui::password_field::{
    FIELD_CONFIRM, FIELD_OLD, FIELD_PASSWORD, FIELD_SECRET, password_field,
};
use crate::ui::theme;
use crate::ui::widgets::{field_label, input, semibold};
use crate::views::dialogs::DialogKind;
use crate::views::item_detail::attribute_rows;

/// Width of dialog content.
pub const FIELD_WIDTH: f32 = 380.0;
/// Size of dialog titles.
const TITLE_SIZE: f32 = 18.0;

/// Main action of a dialog: button text and whether it is destructive.
pub struct MainAction {
    pub text: &'static str,
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
