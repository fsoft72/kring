//! Dialogs of the GPG keys area: new key, import, save the public key,
//! export the secret key, change the passphrase and delete.
//!
//! The listing does not tell whether a secret key is protected, so the key
//! passphrase fields start optional; when the worker answers
//! [`kring_core::gpg::MSG_GPG_PASSPHRASE_REQUIRED`] the dialog reopens with
//! the field required (see `dialog_remember::needing_key_passphrase`). A
//! wrong key passphrase ([`kring_core::gpg::MSG_WRONG_GPG_PASSPHRASE`])
//! reopens it with empty fields. The secret export kept in a backup is always
//! age-encrypted, so changing the passphrase or deleting a secret key asks a
//! backup passphrase upfront (the worker's passphrase request clears the key
//! passphrases, so it cannot be answered by a resend). These dialogs take the
//! passphrase remembered for the session for the key and backup fields.

use eframe::egui::{self, RichText};
use kring_core::gpg::{GpgAlgo, GpgKey};
use kring_core::model::SecretValue;
use zeroize::Zeroizing;

use crate::ui::password_field::{
    FIELD_CONFIRM, FIELD_OLD, FIELD_PASSWORD, FIELD_SECOND, FIELD_SECOND_CONFIRM, new_buffer,
};
use crate::ui::theme;
use crate::ui::widgets::{field_label, input};
use crate::views::dialog_body::{FIELD_WIDTH, MainAction};
use crate::views::dialog_ssh::{
    _main, _muted, _password, _set, _text, _text_field, _title, _warning,
};
use crate::views::dialog_submit::{new_passphrase, required_secret, user_path};
use crate::worker::Command;

/// Error of an empty name in the new key dialog.
pub const MSG_NO_NAME: &str = "Enter a name for the key";
/// Error of a name holding angle brackets or line breaks.
pub const MSG_BAD_NAME: &str = "The name must be one line without '<' or '>'";
/// Error of an invalid email address.
pub const MSG_BAD_EMAIL: &str = "Enter an email address like name@example.org (or leave it empty)";
/// Error of an empty key passphrase once the worker said it is required.
pub const MSG_NO_KEY_PASSPHRASE: &str = "Enter the passphrase of the key";
/// Warning of a new key stored without passphrase.
const MSG_UNPROTECTED_WARNING: &str = "The secret key will be stored without a passphrase: anyone who can read your GnuPG home \
     can use it.";
/// Note under an optional key passphrase field.
const MSG_KEY_PASSPHRASE_OPTIONAL: &str = "Leave it empty if the key has no passphrase.";
/// Note above the backup passphrase of the secret key.
const MSG_BACKUP_SECRET: &str = "The secret key is backed up first, age-encrypted: choose a \
     backup passphrase (you need it to recover the key by hand).";
/// Hint of the path fields.
const MSG_PATH_HINT: &str = "Full path, e.g. ~/keys/key.asc";
/// Characters refused in the name of a user id.
const NAME_FORBIDDEN: [char; 2] = ['<', '>'];

/// Expiry offered by the new key dialog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryChoice {
    /// The key never expires.
    Never,
    /// One year.
    OneYear,
    /// Two years (the default).
    TwoYears,
    /// Five years.
    FiveYears,
}

/// Every expiry, in the order of the combo.
pub const EXPIRY_CHOICES: [ExpiryChoice; 4] = [
    ExpiryChoice::OneYear,
    ExpiryChoice::TwoYears,
    ExpiryChoice::FiveYears,
    ExpiryChoice::Never,
];

impl ExpiryChoice {
    /// Label shown in the combo.
    pub fn label(self) -> &'static str {
        match self {
            Self::Never => "Never",
            Self::OneYear => "1 year",
            Self::TwoYears => "2 years",
            Self::FiveYears => "5 years",
        }
    }

    /// Expiry in gpg syntax, `None` for never.
    pub fn value(self) -> Option<&'static str> {
        match self {
            Self::Never => None,
            Self::OneYear => Some("1y"),
            Self::TwoYears => Some("2y"),
            Self::FiveYears => Some("5y"),
        }
    }
}

/// Label of a key algorithm in the combo.
pub fn algo_label(algo: GpgAlgo) -> &'static str {
    match algo {
        GpgAlgo::Ed25519Cv25519 => "Ed25519 / Cv25519 (recommended)",
        GpgAlgo::Rsa3072 => "RSA 3072",
        GpgAlgo::Rsa4096 => "RSA 4096",
    }
}

/// Returns the name shown for a key: its first user id, else its key id.
pub fn key_label(key: &GpgKey) -> String {
    key.uids
        .first()
        .map_or_else(|| key.key_id.clone(), |u| u.uid.clone())
}

/// Builds the user id `Name <email>` (or `Name` without an email).
pub fn user_id(name: &str, email: &str) -> Result<String, String> {
    let name = name.trim();
    let email = email.trim();
    if name.is_empty() {
        return Err(MSG_NO_NAME.into());
    }
    if name.contains(NAME_FORBIDDEN) || name.chars().any(char::is_control) {
        return Err(MSG_BAD_NAME.into());
    }
    if email.is_empty() {
        return Ok(name.to_string());
    }
    if !_valid_email(email) {
        return Err(MSG_BAD_EMAIL.into());
    }
    Ok(format!("{name} <{email}>"))
}

/// True for `local@domain` without spaces, control characters or angle brackets.
fn _valid_email(email: &str) -> bool {
    let bad = |c: char| c.is_whitespace() || c.is_control() || NAME_FORBIDDEN.contains(&c);
    if email.chars().any(bad) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.is_empty() && !domain.contains('@')
}

/// A dialog of the GPG keys area. Passphrase buffers are zeroized on drop.
#[derive(Clone)]
pub enum GpgDialog {
    /// Generate a key pair in the GnuPG home.
    Create {
        name: String,
        email: String,
        algo: GpgAlgo,
        expiry: ExpiryChoice,
        /// "No passphrase" is checked (the secret key is stored unprotected).
        no_passphrase: bool,
        passphrase: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    /// Import the keys of a file.
    Import {
        /// Typed path of the key file.
        source: String,
    },
    /// Write the armored public key to a new file.
    SavePublic {
        fpr: String,
        label: String,
        /// Typed destination path.
        dest: String,
    },
    /// Write the armored secret key to a new file.
    ExportSecret {
        fpr: String,
        label: String,
        /// Typed destination path.
        dest: String,
        /// The worker said the key passphrase is required.
        key_required: bool,
        passphrase: Zeroizing<String>,
    },
    /// Change the passphrase of a secret key, after a backup.
    ChangePassphrase {
        fpr: String,
        label: String,
        /// The worker said the current passphrase is required.
        key_required: bool,
        old: Zeroizing<String>,
        new: Zeroizing<String>,
        confirm: Zeroizing<String>,
        backup: Zeroizing<String>,
        backup_confirm: Zeroizing<String>,
    },
    /// Confirm deleting a key (public and secret parts), after a backup.
    Delete {
        fpr: String,
        label: String,
        /// The key has a secret part: key and backup passphrases are asked.
        secret: bool,
        /// The worker said the key passphrase is required.
        key_required: bool,
        key_passphrase: Zeroizing<String>,
        backup: Zeroizing<String>,
        backup_confirm: Zeroizing<String>,
    },
}

impl GpgDialog {
    /// New key dialog: Ed25519 / Cv25519, expiring in 2 years, protected.
    pub fn create() -> Self {
        Self::Create {
            name: String::new(),
            email: String::new(),
            algo: GpgAlgo::default(),
            expiry: ExpiryChoice::TwoYears,
            no_passphrase: false,
            passphrase: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// Import dialog with an empty path.
    pub fn import() -> Self {
        Self::Import {
            source: String::new(),
        }
    }

    /// Save dialog of the public key of `key`, suggesting `~/<key id>-public.asc`.
    pub fn save_public(key: &GpgKey) -> Self {
        Self::SavePublic {
            fpr: key.fingerprint.clone(),
            label: key_label(key),
            dest: format!("~/{}-public.asc", key.key_id),
        }
    }

    /// Export dialog of the secret key of `key`, suggesting `~/<key id>-secret.asc`.
    pub fn export_secret(key: &GpgKey) -> Self {
        Self::ExportSecret {
            fpr: key.fingerprint.clone(),
            label: key_label(key),
            dest: format!("~/{}-secret.asc", key.key_id),
            key_required: false,
            passphrase: new_buffer(),
        }
    }

    /// Change passphrase dialog of `key`.
    pub fn change_passphrase(key: &GpgKey) -> Self {
        Self::ChangePassphrase {
            fpr: key.fingerprint.clone(),
            label: key_label(key),
            key_required: false,
            old: new_buffer(),
            new: new_buffer(),
            confirm: new_buffer(),
            backup: new_buffer(),
            backup_confirm: new_buffer(),
        }
    }

    /// Delete confirmation of `key`.
    pub fn delete(key: &GpgKey) -> Self {
        Self::Delete {
            fpr: key.fingerprint.clone(),
            label: key_label(key),
            secret: key.secret,
            key_required: false,
            key_passphrase: new_buffer(),
            backup: new_buffer(),
            backup_confirm: new_buffer(),
        }
    }

    /// Returns true when the dialog shows a passphrase field whose value
    /// may be remembered for the session (key or backup passphrase; never
    /// a new key passphrase).
    pub fn asks_passphrase(&self) -> bool {
        match self {
            Self::ExportSecret { .. } | Self::ChangePassphrase { .. } => true,
            Self::Delete { secret, .. } => *secret,
            Self::Create { .. } | Self::Import { .. } | Self::SavePublic { .. } => false,
        }
    }

    /// Returns true for the dialogs sending a key passphrase: they reopen
    /// after a wrong (or missing) key passphrase.
    pub fn reopens_when_wrong(&self) -> bool {
        self.asks_passphrase()
    }

    /// Fills the fields the remembered passphrase answers: the key
    /// passphrase and the backup passphrase (with its confirmation). New
    /// key passphrases are never filled.
    pub fn fill(&mut self, text: &str) {
        match self {
            Self::ExportSecret { passphrase, .. } => _set(passphrase, text),
            Self::ChangePassphrase {
                old,
                backup,
                backup_confirm,
                ..
            }
            | Self::Delete {
                secret: true,
                key_passphrase: old,
                backup,
                backup_confirm,
                ..
            } => {
                for buffer in [old, backup, backup_confirm] {
                    _set(buffer, text);
                }
            }
            Self::Delete { .. }
            | Self::Create { .. }
            | Self::Import { .. }
            | Self::SavePublic { .. } => {}
        }
    }

    /// Empties every passphrase field, new key passphrases included.
    pub fn clear_secrets(&mut self) {
        let buffers: Vec<&mut Zeroizing<String>> = match self {
            Self::Create {
                passphrase,
                confirm,
                ..
            } => vec![passphrase, confirm],
            Self::Import { .. } | Self::SavePublic { .. } => vec![],
            Self::ExportSecret { passphrase, .. } => vec![passphrase],
            Self::ChangePassphrase {
                old,
                new,
                confirm,
                backup,
                backup_confirm,
                ..
            } => vec![old, new, confirm, backup, backup_confirm],
            Self::Delete {
                key_passphrase,
                backup,
                backup_confirm,
                ..
            } => vec![key_passphrase, backup, backup_confirm],
        };
        for buffer in buffers {
            buffer.clear();
        }
    }

    /// Returns the dialog requiring the key passphrase: the worker found the
    /// key protected and none was sent.
    pub fn needing_key_passphrase(mut self) -> Self {
        match &mut self {
            Self::ExportSecret { key_required, .. }
            | Self::ChangePassphrase { key_required, .. }
            | Self::Delete { key_required, .. } => *key_required = true,
            Self::Create { .. } | Self::Import { .. } | Self::SavePublic { .. } => {}
        }
        self
    }

    /// Validates the fields and builds the command to send.
    pub fn command_for(&self) -> Result<Command, String> {
        let cmd = match self {
            Self::Create {
                name,
                email,
                algo,
                expiry,
                no_passphrase,
                passphrase,
                confirm,
            } => Command::CreateGpgKey {
                uid: user_id(name, email)?,
                algo: *algo,
                expire: expiry.value().map(str::to_string),
                passphrase: match no_passphrase {
                    true => None,
                    false => Some(new_passphrase(passphrase, confirm)?),
                },
            },
            Self::Import { source } => Command::ImportGpgKeys {
                path: user_path(source)?,
            },
            Self::SavePublic { fpr, dest, .. } => Command::SaveGpgPublic {
                fpr: fpr.clone(),
                dest: user_path(dest)?,
            },
            Self::ExportSecret {
                fpr,
                dest,
                key_required,
                passphrase,
                ..
            } => Command::ExportGpgSecret {
                fpr: fpr.clone(),
                dest: user_path(dest)?,
                passphrase: _key_passphrase(*key_required, passphrase)?,
            },
            Self::ChangePassphrase {
                fpr,
                key_required,
                old,
                new,
                confirm,
                backup,
                backup_confirm,
                ..
            } => Command::ChangeGpgPassphrase {
                fpr: fpr.clone(),
                old: _key_passphrase(*key_required, old)?,
                new: Some(new_passphrase(new, confirm)?),
                backup_passphrase: Some(new_passphrase(backup, backup_confirm)?),
            },
            Self::Delete {
                fpr,
                secret,
                key_required,
                key_passphrase,
                backup,
                backup_confirm,
                ..
            } => Command::DeleteGpgKey {
                fpr: fpr.clone(),
                key_passphrase: match secret {
                    true => _key_passphrase(*key_required, key_passphrase)?,
                    false => None,
                },
                backup_passphrase: match secret {
                    true => Some(new_passphrase(backup, backup_confirm)?),
                    false => None,
                },
            },
        };
        Ok(cmd)
    }

    /// Renders the fields and returns the main action; `hide` leaves out
    /// the fields the remembered passphrase fills (see [`Self::fill`]).
    pub fn body(&mut self, ui: &mut egui::Ui, hide: bool) -> MainAction {
        match self {
            Self::Create {
                name,
                email,
                algo,
                expiry,
                no_passphrase,
                passphrase,
                confirm,
            } => {
                _title(ui, "New GPG key");
                _text_field(ui, "Name", name, "e.g. Ada Lovelace");
                _text_field(ui, "Email", email, "e.g. ada@example.org (optional)");
                field_label(ui, "Type");
                _algo_combo(ui, algo);
                field_label(ui, "Expires");
                _expiry_combo(ui, expiry);
                if !*no_passphrase {
                    _password(ui, false, "Passphrase", FIELD_PASSWORD, passphrase);
                    _password(ui, false, "Confirm passphrase", FIELD_CONFIRM, confirm);
                }
                ui.checkbox(
                    no_passphrase,
                    RichText::new("No passphrase").color(theme::TEXT),
                );
                if *no_passphrase {
                    _warning(ui, MSG_UNPROTECTED_WARNING);
                }
                _muted(
                    ui,
                    "A signing primary key and an encryption subkey are created.",
                );
                _main("Create key", false)
            }
            Self::Import { source } => {
                _title(ui, "Import GPG keys");
                _text(
                    ui,
                    "Import the public and secret keys of an OpenPGP file (armored or binary).",
                );
                _path_field(ui, "Key file", source);
                _muted(
                    ui,
                    "Known keys are merged by gpg; secret keys may ask their passphrase later.",
                );
                _main("Import", false)
            }
            Self::SavePublic { label, dest, .. } => {
                _title(ui, &format!("Save the public key of \"{label}\""));
                _text(ui, "Write the armored public key to a new file.");
                _path_field(ui, "Destination file", dest);
                _muted(ui, "An existing file is never overwritten.");
                _main("Save", false)
            }
            Self::ExportSecret {
                label,
                dest,
                key_required,
                passphrase,
                ..
            } => {
                _title(ui, &format!("Export the secret key of \"{label}\""));
                _text(
                    ui,
                    "Write the armored secret key (with its subkeys) to a new file, readable \
                     only by you. It keeps the key's protection: a key without passphrase is \
                     exported in clear.",
                );
                _path_field(ui, "Destination file", dest);
                _key_field(ui, hide, *key_required, FIELD_PASSWORD, passphrase);
                _warning(
                    ui,
                    "Keep the file safe: with the passphrase it gives full use of the key.",
                );
                _muted(ui, "An existing file is never overwritten.");
                _main("Export", false)
            }
            Self::ChangePassphrase {
                label,
                key_required,
                old,
                new,
                confirm,
                backup,
                backup_confirm,
                ..
            } => {
                _title(ui, &format!("Change the passphrase of \"{label}\""));
                _key_field(ui, hide, *key_required, FIELD_OLD, old);
                _password(ui, false, "New passphrase", FIELD_PASSWORD, new);
                _password(ui, false, "Confirm new passphrase", FIELD_CONFIRM, confirm);
                _backup_fields(ui, hide, backup, backup_confirm);
                _muted(
                    ui,
                    "The primary key and its subkeys get the new passphrase.",
                );
                _main("Change passphrase", false)
            }
            Self::Delete {
                fpr,
                label,
                secret,
                key_required,
                key_passphrase,
                backup,
                backup_confirm,
            } => {
                _title(ui, &format!("Delete \"{label}\""));
                let parts = match secret {
                    true => "public and secret parts",
                    false => "public key",
                };
                _text(
                    ui,
                    &format!("This key ({parts}) is removed from the GnuPG keyring:"),
                );
                ui.label(
                    RichText::new(crate::views::gpg_detail::grouped_fingerprint(fpr))
                        .monospace()
                        .size(12.5)
                        .color(theme::TEXT),
                );
                if *secret {
                    _key_field(ui, hide, *key_required, FIELD_OLD, key_passphrase);
                    _backup_fields(ui, hide, backup, backup_confirm);
                } else {
                    _muted(ui, "Its public key is backed up first.");
                }
                _main("Delete", true)
            }
        }
    }
}

/// Returns the key passphrase: required (non-empty) when the worker asked
/// for it, otherwise `None` when left empty.
fn _key_passphrase(
    required: bool,
    buffer: &Zeroizing<String>,
) -> Result<Option<SecretValue>, String> {
    if !required && buffer.is_empty() {
        return Ok(None);
    }
    required_secret(buffer, MSG_NO_KEY_PASSPHRASE).map(Some)
}

/// Adds the key passphrase field (optional until `required`); nothing when `hide`.
fn _key_field(
    ui: &mut egui::Ui,
    hide: bool,
    required: bool,
    field: &str,
    buffer: &mut Zeroizing<String>,
) {
    if hide {
        return;
    }
    _password(ui, false, "Key passphrase", field, buffer);
    if !required {
        _muted(ui, MSG_KEY_PASSPHRASE_OPTIONAL);
    }
}

/// Adds the backup passphrase note and fields; nothing when `hide`.
fn _backup_fields(
    ui: &mut egui::Ui,
    hide: bool,
    backup: &mut Zeroizing<String>,
    confirm: &mut Zeroizing<String>,
) {
    if hide {
        return;
    }
    _warning(ui, MSG_BACKUP_SECRET);
    _password(ui, false, "Backup passphrase", FIELD_SECOND, backup);
    _password(
        ui,
        false,
        "Confirm backup passphrase",
        FIELD_SECOND_CONFIRM,
        confirm,
    );
}

/// Adds a field label above a monospace path field.
fn _path_field(ui: &mut egui::Ui, label: &str, text: &mut String) {
    field_label(ui, label);
    ui.add(
        input(text)
            .font(egui::TextStyle::Monospace)
            .hint_text(RichText::new(MSG_PATH_HINT).color(theme::MUTED.gamma_multiply(0.7)))
            .desired_width(f32::INFINITY),
    );
}

/// Combo of the key algorithms.
fn _algo_combo(ui: &mut egui::Ui, algo: &mut GpgAlgo) {
    egui::ComboBox::from_id_salt("kring-gpg-key-type")
        .selected_text(algo_label(*algo))
        .width(FIELD_WIDTH)
        .show_ui(ui, |ui| {
            for a in GpgAlgo::ALL {
                ui.selectable_value(algo, a, algo_label(a));
            }
        });
}

/// Combo of the expiry choices.
fn _expiry_combo(ui: &mut egui::Ui, expiry: &mut ExpiryChoice) {
    egui::ComboBox::from_id_salt("kring-gpg-expiry")
        .selected_text(expiry.label())
        .width(FIELD_WIDTH)
        .show_ui(ui, |ui| {
            for e in EXPIRY_CHOICES {
                ui.selectable_value(expiry, e, e.label());
            }
        });
}

#[cfg(test)]
pub(crate) mod tests;
