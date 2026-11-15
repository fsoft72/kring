//! Dialogs of the SSH keys area: new key, import, add to the agent, export
//! of the private key, change of the passphrase and delete.
//!
//! The key passphrase dialogs (add to the agent, export re-encrypting an
//! encrypted key, change passphrase) take the passphrase remembered for the
//! session and reopen after a wrong key passphrase, like the wallet password
//! dialog (see `dialog_remember`). The backup passphrase of an unencrypted
//! private key (delete, change passphrase) is asked in the same dialog,
//! upfront: the worker's passphrase request clears the key passphrases, so
//! it cannot be answered by a resend.

use eframe::egui::{self, RichText};
use kring_core::ssh::{NewKey, SshAlgorithm, SshKeyInfo, valid_key_name};
use zeroize::Zeroizing;

use crate::ui::password_field::{
    FIELD_CONFIRM, FIELD_OLD, FIELD_PASSWORD, FIELD_SECOND, FIELD_SECOND_CONFIRM, new_buffer,
    password_field,
};
use crate::ui::theme;
use crate::ui::widgets::{field_label, input, semibold};
use crate::views::dialog_body::{FIELD_WIDTH, MainAction};
use crate::views::dialog_submit::{new_passphrase, required_secret, user_path};
use crate::worker::Command;

/// Error of an invalid key name.
pub const MSG_BAD_KEY_NAME: &str =
    "Invalid key name: use letters, digits, '.', '_' and '-' (not a reserved file name)";
/// Error of an empty key passphrase.
pub const MSG_NO_KEY_PASSPHRASE: &str = "Enter the passphrase of the key";
/// Error of a comment spanning more than one line.
pub const MSG_COMMENT_LINE: &str = "The comment must be a single line";
/// Checkbox of the change passphrase dialog removing the encryption.
pub const MSG_STORE_UNENCRYPTED: &str = "Store this key without a passphrase";
/// Warning shown when a private key is (or will be) stored unencrypted.
pub const MSG_UNENCRYPTED_WARNING: &str =
    "The private key will be stored unencrypted: anyone who can read the file can use it.";
/// Note above the backup passphrase of an unencrypted private key.
const MSG_BACKUP_PLAINTEXT: &str = "The private key is not encrypted: its backup is \
     age-encrypted, choose a passphrase.";
/// Hint of the path fields.
const MSG_KEY_PATH_HINT: &str = "Full path, e.g. ~/keys/id_ed25519";
/// Size of dialog titles (same as the other dialogs).
const TITLE_SIZE: f32 = 18.0;
/// Lifetimes offered when adding a key to the agent: seconds (`None` =
/// until removed) and label.
pub const LIFETIMES: [(Option<u32>, &str); 5] = [
    (None, "Until removed"),
    (Some(15 * 60), "15 minutes"),
    (Some(60 * 60), "1 hour"),
    (Some(4 * 60 * 60), "4 hours"),
    (Some(8 * 60 * 60), "8 hours"),
];

/// Key type offered by the new key dialog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyChoice {
    /// Ed25519 (the default).
    Ed25519,
    /// ECDSA over NIST P-256.
    EcdsaP256,
    /// ECDSA over NIST P-384.
    EcdsaP384,
    /// RSA, 3072 bits.
    Rsa3072,
    /// RSA, 4096 bits.
    Rsa4096,
}

/// Every key type, in the order of the combo.
pub const KEY_CHOICES: [KeyChoice; 5] = [
    KeyChoice::Ed25519,
    KeyChoice::EcdsaP256,
    KeyChoice::EcdsaP384,
    KeyChoice::Rsa3072,
    KeyChoice::Rsa4096,
];

impl KeyChoice {
    /// Label shown in the combo.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519 (recommended)",
            Self::EcdsaP256 => "ECDSA P-256",
            Self::EcdsaP384 => "ECDSA P-384",
            Self::Rsa3072 => "RSA 3072",
            Self::Rsa4096 => "RSA 4096",
        }
    }

    /// Algorithm of the key.
    pub fn algorithm(self) -> SshAlgorithm {
        match self {
            Self::Ed25519 => SshAlgorithm::Ed25519,
            Self::EcdsaP256 => SshAlgorithm::EcdsaP256,
            Self::EcdsaP384 => SshAlgorithm::EcdsaP384,
            Self::Rsa3072 | Self::Rsa4096 => SshAlgorithm::Rsa,
        }
    }

    /// RSA modulus size (ignored by the other algorithms).
    pub fn rsa_bits(self) -> u32 {
        match self {
            Self::Rsa4096 => 4096,
            _ => 3072,
        }
    }

    /// Usual OpenSSH file name of this key type.
    pub fn default_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "id_ed25519",
            Self::EcdsaP256 | Self::EcdsaP384 => "id_ecdsa",
            Self::Rsa3072 | Self::Rsa4096 => "id_rsa",
        }
    }
}

/// Returns `base` when no key has that name, else the first free `base_<n>`.
pub fn free_name(base: &str, existing: &[SshKeyInfo]) -> String {
    let taken = |name: &str| existing.iter().any(|k| k.name == name);
    if !taken(base) {
        return base.to_string();
    }
    (2..)
        .map(|n| format!("{base}_{n}"))
        .find(|name| !taken(name))
        .unwrap_or_default()
}

/// Returns the label of a lifetime value.
pub fn lifetime_label(lifetime: Option<u32>) -> String {
    LIFETIMES
        .iter()
        .find(|(secs, _)| *secs == lifetime)
        .map_or_else(
            || format!("{} s", lifetime.unwrap_or_default()),
            |(_, label)| label.to_string(),
        )
}

/// File names of the files of `info`, for the delete confirmation.
fn _file_names(info: &SshKeyInfo) -> Vec<String> {
    [&info.private_path, &info.public_path]
        .into_iter()
        .flatten()
        .map(|p| {
            p.file_name()
                .map_or_else(|| p.display().to_string(), |n| n.to_string_lossy().into())
        })
        .collect()
}

/// A dialog of the SSH keys area. Passphrase buffers are zeroized on drop.
#[derive(Clone)]
pub enum SshDialog {
    /// Generate a key pair in the SSH directory.
    Generate {
        name: String,
        choice: KeyChoice,
        comment: String,
        /// "No passphrase" is checked (the key is stored unencrypted).
        no_passphrase: bool,
        passphrase: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    /// Copy a private key file into the SSH directory.
    Import {
        /// Typed path of the private key.
        source: String,
        /// Name in the SSH directory; empty keeps the file name.
        name: String,
    },
    /// Load a key into the agent.
    AgentAdd {
        name: String,
        /// The private key is encrypted: its passphrase is asked.
        encrypted: bool,
        /// Seconds the agent keeps the key, `None` until removed.
        lifetime: Option<u32>,
        passphrase: Zeroizing<String>,
    },
    /// Write a copy of the private key to a new file.
    Export {
        name: String,
        encrypted: bool,
        /// Typed destination path.
        dest: String,
        /// Encrypt the copy with a new passphrase.
        reencrypt: bool,
        /// Current key passphrase (re-encrypting an encrypted key).
        passphrase: Zeroizing<String>,
        new_passphrase: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    /// Change (or remove) the passphrase of a key, after a backup.
    ChangePassphrase {
        name: String,
        encrypted: bool,
        /// "Store this key without a passphrase" is checked.
        remove: bool,
        old: Zeroizing<String>,
        new: Zeroizing<String>,
        confirm: Zeroizing<String>,
        /// Backup passphrase of an unencrypted key.
        backup: Zeroizing<String>,
        backup_confirm: Zeroizing<String>,
    },
    /// Confirm deleting the files of a key, after a backup.
    Delete {
        name: String,
        /// File names removed, for display.
        files: Vec<String>,
        /// The private key is unencrypted: its backup needs a passphrase.
        needs_backup_passphrase: bool,
        /// The agent holds the key (it stays loaded).
        in_agent: bool,
        passphrase: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
}

impl SshDialog {
    /// New key dialog: Ed25519, encrypted, named `id_ed25519` (or the first
    /// free `id_ed25519_<n>` among `existing`).
    pub fn generate(existing: &[SshKeyInfo]) -> Self {
        let choice = KeyChoice::Ed25519;
        Self::Generate {
            name: free_name(choice.default_name(), existing),
            choice,
            comment: String::new(),
            no_passphrase: false,
            passphrase: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// Import dialog with empty fields.
    pub fn import() -> Self {
        Self::Import {
            source: String::new(),
            name: String::new(),
        }
    }

    /// Add to agent dialog of `info` (no lifetime limit).
    pub fn agent_add(info: &SshKeyInfo) -> Self {
        Self::AgentAdd {
            name: info.name.clone(),
            encrypted: info.encrypted == Some(true),
            lifetime: None,
            passphrase: new_buffer(),
        }
    }

    /// Export dialog of `info`, suggesting `~/<name>-export`; an
    /// unencrypted key is re-encrypted by default.
    pub fn export(info: &SshKeyInfo) -> Self {
        let encrypted = info.encrypted == Some(true);
        Self::Export {
            name: info.name.clone(),
            encrypted,
            dest: format!("~/{}-export", info.name),
            reencrypt: !encrypted,
            passphrase: new_buffer(),
            new_passphrase: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// Change passphrase dialog of `info`.
    pub fn change_passphrase(info: &SshKeyInfo) -> Self {
        Self::ChangePassphrase {
            name: info.name.clone(),
            encrypted: info.encrypted == Some(true),
            remove: false,
            old: new_buffer(),
            new: new_buffer(),
            confirm: new_buffer(),
            backup: new_buffer(),
            backup_confirm: new_buffer(),
        }
    }

    /// Delete confirmation of `info`; `in_agent` when the agent holds it.
    pub fn delete(info: &SshKeyInfo, in_agent: bool) -> Self {
        Self::Delete {
            name: info.name.clone(),
            files: _file_names(info),
            needs_backup_passphrase: info.encrypted == Some(false),
            in_agent,
            passphrase: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// Returns true when the dialog shows a passphrase field whose value
    /// may be remembered for the session (key or backup passphrase; never
    /// a new key passphrase).
    pub fn asks_passphrase(&self) -> bool {
        match self {
            Self::AgentAdd { encrypted, .. } => *encrypted,
            Self::Export {
                encrypted,
                reencrypt,
                ..
            } => *encrypted && *reencrypt,
            Self::ChangePassphrase { .. } => true,
            Self::Delete {
                needs_backup_passphrase,
                ..
            } => *needs_backup_passphrase,
            Self::Generate { .. } | Self::Import { .. } => false,
        }
    }

    /// Returns true for the dialogs sending a key passphrase: they reopen
    /// after a wrong (or missing) key passphrase.
    pub fn reopens_when_wrong(&self) -> bool {
        matches!(
            self,
            Self::AgentAdd { .. } | Self::Export { .. } | Self::ChangePassphrase { .. }
        )
    }

    /// Fills the fields the remembered passphrase answers: the key
    /// passphrase, or the backup passphrase (and its confirmation) of an
    /// unencrypted key. New key passphrases are never filled.
    pub fn fill(&mut self, text: &str) {
        match self {
            Self::AgentAdd { passphrase, .. } | Self::Export { passphrase, .. } => {
                _set(passphrase, text)
            }
            Self::ChangePassphrase {
                encrypted: true,
                old,
                ..
            } => _set(old, text),
            Self::ChangePassphrase {
                encrypted: false,
                backup,
                backup_confirm,
                ..
            } => {
                _set(backup, text);
                _set(backup_confirm, text);
            }
            Self::Delete {
                passphrase,
                confirm,
                ..
            } => {
                _set(passphrase, text);
                _set(confirm, text);
            }
            Self::Generate { .. } | Self::Import { .. } => {}
        }
    }

    /// Empties every passphrase field, new key passphrases included.
    pub fn clear_secrets(&mut self) {
        let buffers: Vec<&mut Zeroizing<String>> = match self {
            Self::Generate {
                passphrase,
                confirm,
                ..
            }
            | Self::Delete {
                passphrase,
                confirm,
                ..
            } => vec![passphrase, confirm],
            Self::Import { .. } => vec![],
            Self::AgentAdd { passphrase, .. } => vec![passphrase],
            Self::Export {
                passphrase,
                new_passphrase,
                confirm,
                ..
            } => vec![passphrase, new_passphrase, confirm],
            Self::ChangePassphrase {
                old,
                new,
                confirm,
                backup,
                backup_confirm,
                ..
            } => vec![old, new, confirm, backup, backup_confirm],
        };
        for buffer in buffers {
            buffer.clear();
        }
    }

    /// Returns the dialog asking the key passphrase: the worker found the
    /// key encrypted although the last scan said otherwise.
    pub fn needing_key_passphrase(mut self) -> Self {
        match &mut self {
            Self::AgentAdd { encrypted, .. } | Self::ChangePassphrase { encrypted, .. } => {
                *encrypted = true
            }
            Self::Export {
                encrypted,
                reencrypt,
                ..
            } => {
                *encrypted = true;
                *reencrypt = true;
            }
            _ => {}
        }
        self
    }

    /// Validates the fields and builds the command to send.
    pub fn command_for(&self) -> Result<Command, String> {
        let cmd = match self {
            Self::Generate {
                name,
                choice,
                comment,
                no_passphrase,
                passphrase,
                confirm,
            } => {
                let name = _key_name(name)?;
                if comment.contains('\n') || comment.contains('\r') {
                    return Err(MSG_COMMENT_LINE.into());
                }
                let passphrase = match no_passphrase {
                    true => None,
                    false => Some(new_passphrase(passphrase, confirm)?),
                };
                Command::GenerateSshKey(NewKey {
                    name,
                    algorithm: choice.algorithm(),
                    rsa_bits: choice.rsa_bits(),
                    comment: comment.trim().to_string(),
                    passphrase,
                })
            }
            Self::Import { source, name } => {
                let name = name.trim();
                let name = match name.is_empty() {
                    true => None,
                    false => Some(_key_name(name)?),
                };
                Command::ImportSshKey {
                    source: user_path(source)?,
                    name,
                }
            }
            Self::AgentAdd {
                name,
                encrypted,
                lifetime,
                passphrase,
            } => Command::AgentAdd {
                name: name.clone(),
                passphrase: _key_passphrase(*encrypted, passphrase)?,
                lifetime_secs: *lifetime,
            },
            Self::Export {
                name,
                encrypted,
                dest,
                reencrypt,
                passphrase,
                new_passphrase: new,
                confirm,
            } => {
                let dest = user_path(dest)?;
                let (passphrase, new_passphrase) = match reencrypt {
                    true => (
                        _key_passphrase(*encrypted, passphrase)?,
                        Some(new_passphrase(new, confirm)?),
                    ),
                    false => (None, None),
                };
                Command::ExportSshPrivate {
                    name: name.clone(),
                    dest,
                    passphrase,
                    new_passphrase,
                }
            }
            Self::ChangePassphrase {
                name,
                encrypted,
                remove,
                old,
                new,
                confirm,
                backup,
                backup_confirm,
            } => {
                let remove = *remove && *encrypted;
                Command::ChangeSshPassphrase {
                    name: name.clone(),
                    old: _key_passphrase(*encrypted, old)?,
                    new: match remove {
                        true => None,
                        false => Some(new_passphrase(new, confirm)?),
                    },
                    allow_unencrypted: remove,
                    backup_passphrase: match encrypted {
                        true => None,
                        false => Some(new_passphrase(backup, backup_confirm)?),
                    },
                }
            }
            Self::Delete {
                name,
                needs_backup_passphrase,
                passphrase,
                confirm,
                ..
            } => Command::DeleteSshKey {
                name: name.clone(),
                backup_passphrase: match needs_backup_passphrase {
                    true => Some(new_passphrase(passphrase, confirm)?),
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
            Self::Generate {
                name,
                choice,
                comment,
                no_passphrase,
                passphrase,
                confirm,
            } => {
                _title(ui, "New SSH key");
                _text_field(ui, "File name", name, "id_ed25519");
                field_label(ui, "Type");
                _choice_combo(ui, choice);
                _text_field(ui, "Comment", comment, "e.g. you@laptop");
                if !*no_passphrase {
                    _password(ui, false, "Passphrase", FIELD_PASSWORD, passphrase);
                    _password(ui, false, "Confirm passphrase", FIELD_CONFIRM, confirm);
                }
                ui.checkbox(
                    no_passphrase,
                    RichText::new("No passphrase").color(theme::TEXT),
                );
                if *no_passphrase {
                    _warning(ui, MSG_UNENCRYPTED_WARNING);
                }
                _muted(ui, "The public key is written next to it as <name>.pub.");
                _main("Create key", false)
            }
            Self::Import { source, name } => {
                _title(ui, "Import an SSH key");
                _text(
                    ui,
                    "Copy an OpenSSH private key into the SSH key folder; its public key is \
                     derived when the .pub is missing.",
                );
                _path_field(ui, "Private key file", source);
                _text_field(ui, "Name (optional)", name, "default: the file name");
                _muted(ui, "Existing files are never overwritten.");
                _main("Import", false)
            }
            Self::AgentAdd {
                name,
                encrypted,
                lifetime,
                passphrase,
            } => {
                _title(ui, &format!("Add \"{name}\" to the agent"));
                _muted(
                    ui,
                    "The agent keeps the key in memory until it is removed, its lifetime \
                     ends or the agent stops.",
                );
                if *encrypted {
                    _password(ui, hide, "Key passphrase", FIELD_PASSWORD, passphrase);
                }
                field_label(ui, "Lifetime");
                _lifetime_combo(ui, lifetime);
                _main("Add to agent", false)
            }
            Self::Export {
                name,
                encrypted,
                dest,
                reencrypt,
                passphrase,
                new_passphrase,
                confirm,
            } => {
                _title(ui, &format!("Export \"{name}\""));
                _text(ui, "Write a copy of the private key to a new file.");
                _path_field(ui, "Destination file", dest);
                ui.checkbox(
                    reencrypt,
                    RichText::new("Encrypt the copy with a new passphrase").color(theme::TEXT),
                );
                if *reencrypt {
                    if *encrypted {
                        _password(ui, hide, "Current passphrase", FIELD_OLD, passphrase);
                    }
                    _password(ui, false, "New passphrase", FIELD_PASSWORD, new_passphrase);
                    _password(ui, false, "Confirm passphrase", FIELD_CONFIRM, confirm);
                } else if *encrypted {
                    _muted(ui, "The copy keeps the current passphrase.");
                } else {
                    _warning(ui, "The copy is not encrypted, like the key itself.");
                }
                _muted(ui, "An existing file is never overwritten.");
                _main("Export", false)
            }
            Self::ChangePassphrase {
                name,
                encrypted,
                remove,
                old,
                new,
                confirm,
                backup,
                backup_confirm,
            } => {
                _title(ui, &format!("Change the passphrase of \"{name}\""));
                if *encrypted {
                    _password(ui, hide, "Current passphrase", FIELD_OLD, old);
                } else {
                    *remove = false;
                }
                if !*remove {
                    _password(ui, false, "New passphrase", FIELD_PASSWORD, new);
                    _password(ui, false, "Confirm new passphrase", FIELD_CONFIRM, confirm);
                }
                if *encrypted {
                    ui.checkbox(
                        remove,
                        RichText::new(MSG_STORE_UNENCRYPTED).color(theme::TEXT),
                    );
                }
                if *remove {
                    _warning(ui, MSG_UNENCRYPTED_WARNING);
                }
                if !*encrypted {
                    _warning(ui, MSG_BACKUP_PLAINTEXT);
                    _password(ui, hide, "Backup passphrase", FIELD_SECOND, backup);
                    _password(
                        ui,
                        hide,
                        "Confirm backup passphrase",
                        FIELD_SECOND_CONFIRM,
                        backup_confirm,
                    );
                }
                _muted(ui, "The current key file is backed up first.");
                match remove {
                    true => _main("Remove passphrase", true),
                    false => _main("Change passphrase", false),
                }
            }
            Self::Delete {
                name,
                files,
                needs_backup_passphrase,
                in_agent,
                passphrase,
                confirm,
            } => {
                _title(ui, &format!("Delete \"{name}\""));
                _text(ui, "These files are moved to a backup and removed:");
                for file in files.iter() {
                    ui.label(
                        RichText::new(file)
                            .monospace()
                            .size(12.5)
                            .color(theme::TEXT),
                    );
                }
                if *in_agent {
                    _muted(
                        ui,
                        "The agent keeps the key loaded until it is removed there.",
                    );
                }
                if *needs_backup_passphrase {
                    _warning(ui, MSG_BACKUP_PLAINTEXT);
                    _password(ui, hide, "Backup passphrase", FIELD_PASSWORD, passphrase);
                    _password(ui, hide, "Confirm passphrase", FIELD_CONFIRM, confirm);
                } else {
                    _muted(ui, "A backup is created first.");
                }
                _main("Delete", true)
            }
        }
    }
}

/// Replaces `buffer` with `text`.
fn _set(buffer: &mut Zeroizing<String>, text: &str) {
    buffer.clear();
    buffer.push_str(text);
}

/// Returns the trimmed key name, refusing an invalid one.
fn _key_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if !valid_key_name(name) {
        return Err(MSG_BAD_KEY_NAME.into());
    }
    Ok(name.to_string())
}

/// Returns the key passphrase of an encrypted key (required), `None` for
/// an unencrypted one.
fn _key_passphrase(
    encrypted: bool,
    buffer: &Zeroizing<String>,
) -> Result<Option<kring_core::model::SecretValue>, String> {
    if !encrypted {
        return Ok(None);
    }
    required_secret(buffer, MSG_NO_KEY_PASSPHRASE).map(Some)
}

/// Main action of a dialog (`danger` for the destructive ones).
fn _main(text: &'static str, danger: bool) -> MainAction {
    MainAction {
        text,
        danger,
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

/// Adds a TERTIARY warning line.
fn _warning(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::TERTIARY).size(12.5));
}

/// Adds a field label above a single-line text field with a hint.
fn _text_field(ui: &mut egui::Ui, label: &str, text: &mut String, hint: &str) {
    field_label(ui, label);
    ui.add(
        input(text)
            .hint_text(RichText::new(hint).color(theme::MUTED.gamma_multiply(0.7)))
            .desired_width(f32::INFINITY),
    );
}

/// Adds a field label above a monospace path field.
fn _path_field(ui: &mut egui::Ui, label: &str, text: &mut String) {
    field_label(ui, label);
    ui.add(
        input(text)
            .font(egui::TextStyle::Monospace)
            .hint_text(RichText::new(MSG_KEY_PATH_HINT).color(theme::MUTED.gamma_multiply(0.7)))
            .desired_width(f32::INFINITY),
    );
}

/// Adds a labelled password field; nothing when `hide` (the remembered
/// passphrase is used instead).
fn _password(
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

/// Combo of the key types.
fn _choice_combo(ui: &mut egui::Ui, choice: &mut KeyChoice) {
    egui::ComboBox::from_id_salt("kring-ssh-key-type")
        .selected_text(choice.label())
        .width(FIELD_WIDTH)
        .show_ui(ui, |ui| {
            for c in KEY_CHOICES {
                ui.selectable_value(choice, c, c.label());
            }
        });
}

/// Combo of the agent lifetimes.
fn _lifetime_combo(ui: &mut egui::Ui, lifetime: &mut Option<u32>) {
    egui::ComboBox::from_id_salt("kring-ssh-lifetime")
        .selected_text(lifetime_label(*lifetime))
        .width(FIELD_WIDTH)
        .show_ui(ui, |ui| {
            for (secs, label) in LIFETIMES {
                ui.selectable_value(lifetime, secs, label);
            }
        });
}

#[cfg(test)]
pub(crate) mod tests;
