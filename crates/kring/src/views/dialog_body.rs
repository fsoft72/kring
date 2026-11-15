//! Field layout of each dialog kind.

use eframe::egui;
use zeroize::Zeroizing;

use crate::views::dialogs::DialogKind;
use crate::views::item_detail::attribute_rows;
use crate::widgets::password_field::{
    FIELD_CONFIRM, FIELD_OLD, FIELD_PASSWORD, FIELD_SECRET, password_field,
};

/// Width of text fields in dialogs.
pub const FIELD_WIDTH: f32 = 280.0;

/// Adds a labelled single-line text field.
fn _text_row(ui: &mut egui::Ui, label: &str, text: &mut String) {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(text).desired_width(FIELD_WIDTH));
    ui.end_row();
}

/// Adds a labelled password field.
fn _password_row(ui: &mut egui::Ui, label: &str, field: &str, buffer: &mut Zeroizing<String>) {
    ui.label(label);
    password_field(ui, field, buffer, "");
    ui.end_row();
}

/// Renders the fields of a dialog and returns the text of its primary button.
pub fn body(ui: &mut egui::Ui, kind: &mut DialogKind) -> &'static str {
    let grid = egui::Grid::new("kring-dialog-grid").num_columns(2);
    match kind {
        DialogKind::Unlock {
            label, password, ..
        } => {
            ui.heading(format!("Unlock \"{label}\""));
            grid.show(ui, |ui| {
                _password_row(ui, "Password", FIELD_PASSWORD, password)
            });
            "Unlock"
        }
        DialogKind::CreateCollection {
            label,
            password,
            confirm,
        } => {
            ui.heading("New collection");
            grid.show(ui, |ui| {
                _text_row(ui, "Name", label);
                _password_row(ui, "Password", FIELD_PASSWORD, password);
                _password_row(ui, "Confirm", FIELD_CONFIRM, confirm);
            });
            "Create"
        }
        DialogKind::Rename { label, .. } => {
            ui.heading("Rename collection");
            grid.show(ui, |ui| _text_row(ui, "Name", label));
            "Rename"
        }
        DialogKind::ChangePassword {
            label,
            old,
            new,
            confirm,
            ..
        } => {
            ui.heading(format!("Change password of \"{label}\""));
            grid.show(ui, |ui| {
                _password_row(ui, "Current password", FIELD_OLD, old);
                _password_row(ui, "New password", FIELD_PASSWORD, new);
                _password_row(ui, "Confirm", FIELD_CONFIRM, confirm);
            });
            "Change password"
        }
        DialogKind::DeleteCollection {
            label,
            item_count,
            warnings,
            ..
        } => {
            ui.heading("Delete collection");
            ui.label(format!(
                "Delete the collection \"{label}\" and its {item_count} item(s)?"
            ));
            for warning in warnings.iter() {
                ui.colored_label(ui.visuals().warn_fg_color, *warning);
            }
            ui.label("A backup of the keyring files is created first.");
            "Delete"
        }
        DialogKind::NewItem {
            label,
            secret,
            rows,
            ..
        } => {
            ui.heading("New item");
            grid.show(ui, |ui| {
                _text_row(ui, "Label", label);
                _password_row(ui, "Secret", FIELD_SECRET, secret);
            });
            ui.label("Attributes");
            attribute_rows(ui, "kring-new-item-attrs", rows);
            "Create"
        }
        DialogKind::EditItem { label, secret, .. } => {
            ui.heading("Edit item");
            grid.show(ui, |ui| {
                _text_row(ui, "Label", label);
                _password_row(ui, "New secret", FIELD_SECRET, secret);
            });
            ui.weak("Leave the secret empty to keep the current one.");
            "Save"
        }
        DialogKind::SaveAttributes { label, changes, .. } => {
            ui.heading("Save attributes");
            ui.label(format!("Replace the attributes of \"{label}\":"));
            for change in changes.iter() {
                ui.monospace(change);
            }
            "Save"
        }
        DialogKind::DeleteItem { label, .. } => {
            ui.heading("Delete item");
            ui.label(format!("Delete the item \"{label}\"?"));
            ui.label("A backup of the keyring files is created first.");
            "Delete"
        }
        DialogKind::Passphrase {
            passphrase,
            confirm,
            ..
        } => {
            ui.heading("Backup passphrase");
            ui.label("Backup contains plaintext keyrings, choose a passphrase");
            grid.show(ui, |ui| {
                _password_row(ui, "Passphrase", FIELD_PASSWORD, passphrase);
                _password_row(ui, "Confirm", FIELD_CONFIRM, confirm);
            });
            "Continue"
        }
    }
}
