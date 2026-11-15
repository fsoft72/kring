//! Modal dialogs: password prompts, forms and confirmations.

use std::path::{Path, PathBuf};

use eframe::egui;
use kring_core::model::{Attributes, CollectionId, CollectionInfo, ItemId, SecretValue};
use kring_core::transfer::apply::TransferMode;
use kring_core::transfer::plan::Choice;
use zeroize::Zeroizing;

use crate::app_state::FileAction;
use crate::session_secret::MSG_WRONG_TRY_AGAIN;
use crate::ui::password_field::{forget_fields, new_buffer};
use crate::ui::theme;
use crate::ui::widgets::{danger_button, primary_button, secondary_button};
use crate::views::collection::{display_name, display_names};
use crate::views::consolidate::PassphraseNeeds;
use crate::views::dialog_body::{FIELD_WIDTH, body};
use crate::views::dialog_gpg::GpgDialog;
use crate::views::dialog_remember::{
    cleared, fill_passphrases, offers_remember, passphrase_of, remember_row, remembered_row,
    remembers_only_when_correct, reopens_when_wrong, uses_remembered,
};
use crate::views::dialog_ssh::SshDialog;
use crate::views::dialog_submit::command_for;
use crate::views::file_detail::default_import_target;
use crate::views::transfer::transfer_targets;
use crate::worker::Command;

/// Id of the (single) open modal.
const MODAL_ID: &str = "kring-dialog";
/// Width of dialog content.
const DIALOG_WIDTH: f32 = FIELD_WIDTH;
/// Inner margin of dialogs.
const DIALOG_MARGIN: i8 = 24;
/// Opacity of the backdrop behind a dialog.
const BACKDROP_ALPHA: u8 = 150;

/// Passphrase asked by the restore confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestorePassphrase {
    /// Nothing encrypted is read or written.
    NotNeeded,
    /// An encrypted copy is restored: the passphrase of the backup.
    Existing,
    /// Only the pre-restore backup of a plaintext file is encrypted: a new
    /// passphrase, typed twice.
    New,
}

/// What the delete dialog of a keyring file shows and allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteSpec {
    /// Body lines.
    pub lines: Vec<String>,
    /// The backup holds plaintext data: it is encrypted with a new passphrase.
    pub needs_passphrase: bool,
    /// Note shown above the passphrase fields.
    pub passphrase_note: &'static str,
    /// The backup may be skipped (the checkbox is shown).
    pub backup_optional: bool,
    /// The keyring held no items in the last listing: no backup is needed,
    /// the checkbox and passphrase are hidden (the worker re-checks and asks
    /// a passphrase when it turns out not empty).
    pub empty: bool,
}

/// A keyring offered as import target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportTarget {
    /// Collection object path.
    pub id: CollectionId,
    /// Display name.
    pub label: String,
    /// Locked keyrings are listed but cannot be chosen.
    pub locked: bool,
}

/// Where the entries of a wallet are imported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletTarget {
    /// An existing keyring.
    Keyring(CollectionId),
    /// A new keyring labelled like the wallet (created first).
    Create,
}

/// The content of a dialog. Password buffers are zeroized when it is dropped.
#[derive(Clone)]
pub enum DialogKind {
    /// Unlock a collection with its password.
    Unlock {
        collection: CollectionId,
        label: String,
        password: Zeroizing<String>,
    },
    /// Unlock several collections with one password.
    UnlockMany {
        collections: Vec<CollectionId>,
        password: Zeroizing<String>,
    },
    /// Create a password protected collection.
    CreateCollection {
        label: String,
        password: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    /// Rename a collection.
    Rename {
        collection: CollectionId,
        label: String,
    },
    /// Change the password of a collection.
    ChangePassword {
        collection: CollectionId,
        label: String,
        old: Zeroizing<String>,
        new: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    /// Confirm the deletion of a collection.
    DeleteCollection {
        collection: CollectionId,
        label: String,
        item_count: usize,
        /// Extra warnings (login or default keyring).
        warnings: Vec<&'static str>,
    },
    /// Create an item.
    NewItem {
        collection: CollectionId,
        label: String,
        secret: Zeroizing<String>,
        rows: Vec<(String, String)>,
    },
    /// Edit the label and (optionally) the secret of an item.
    EditItem {
        item: ItemId,
        label: String,
        secret: Zeroizing<String>,
    },
    /// Confirm replacing the attributes of an item, listing every change.
    SaveAttributes {
        item: ItemId,
        label: String,
        attributes: Attributes,
        changes: Vec<String>,
    },
    /// Confirm the deletion of an item.
    DeleteItem { item: ItemId, label: String },
    /// Password of a binary keyring file, to open or import it.
    FilePassword {
        name: String,
        action: FileAction,
        password: Zeroizing<String>,
    },
    /// Choose the keyring receiving the items of a keyring file.
    ImportFile {
        name: String,
        targets: Vec<ImportTarget>,
        target: Option<CollectionId>,
    },
    /// Confirm retiring a plaintext keyring file, with the backup passphrase.
    RetireFile {
        name: String,
        /// Body lines from `file_detail::retire_dialog_text`.
        lines: Vec<String>,
        passphrase: Zeroizing<String>,
        confirm: Zeroizing<String>,
        /// The file held no items in the last listing: no backup passphrase
        /// is asked (the worker re-checks and asks when it turns out not empty).
        empty: bool,
    },
    /// Confirm deleting a keyring file (a live one through the daemon).
    DeleteFile {
        name: String,
        /// Body, passphrase need and whether the backup may be skipped.
        spec: DeleteSpec,
        /// Back up first (checked by default, forced when not optional).
        backup: bool,
        /// Typed file name, required when `backup` is off.
        typed: String,
        passphrase: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    /// Confirm restoring files of a backup, listing what gets overwritten.
    RestoreBackup {
        dir: PathBuf,
        /// Original paths of the files to restore.
        files: Vec<PathBuf>,
        /// Files that will be overwritten, for display.
        destinations: Vec<String>,
        /// Which passphrase the restore needs.
        mode: RestorePassphrase,
        passphrase: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    /// Export a collection to an age-encrypted archive.
    ExportCollection {
        collection: CollectionId,
        label: String,
        /// Typed archive path.
        path: String,
        passphrase: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    /// Import the items of an archive into a collection.
    ImportArchive {
        target: CollectionId,
        label: String,
        /// Typed archive path.
        path: String,
        passphrase: Zeroizing<String>,
    },
    /// Choose the keyring receiving copied or moved items.
    TransferTarget {
        items: Vec<ItemId>,
        mode: TransferMode,
        /// Every keyring but the current one; locked ones cannot be chosen.
        targets: Vec<ImportTarget>,
        target: Option<CollectionId>,
    },
    /// Passphrase of the backup taken before applying transfer plan `plan_id`;
    /// resends the apply with the choices kept from the preview.
    ApplyPassphrase {
        plan_id: u64,
        choices: Vec<Choice>,
        passphrase: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    /// Passphrases missing to apply consolidation plan `plan_id` (the
    /// backup of plaintext keyrings, the backup of the retired orphan
    /// files); resends the apply with the choices and the passphrases
    /// given before (`kept_*`).
    ConsolidatePassphrases {
        plan_id: u64,
        choices: Vec<Vec<Choice>>,
        ask_backup: bool,
        ask_orphan_files: bool,
        backup: Zeroizing<String>,
        backup_confirm: Zeroizing<String>,
        orphan_files: Zeroizing<String>,
        orphan_files_confirm: Zeroizing<String>,
        kept_backup: Option<SecretValue>,
        kept_orphan_files: Option<SecretValue>,
    },
    /// Password of a KWallet wallet, to open it.
    WalletPassword {
        name: String,
        password: Zeroizing<String>,
    },
    /// Choose the keyring receiving the entries of an open wallet, or
    /// create the keyring labelled like the wallet (with its password).
    ImportWallet {
        name: String,
        /// Password of the open wallet (re-read by the worker for the import).
        password: SecretValue,
        /// Every keyring; locked ones cannot be chosen.
        targets: Vec<ImportTarget>,
        target: Option<WalletTarget>,
        /// No keyring is labelled like the wallet: creating one is offered.
        offer_create: bool,
        /// Why the keyring cannot be created (provider gate), if so.
        create_blocked: Option<&'static str>,
        /// Password of the keyring to create.
        new_password: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
    /// A dialog of the SSH keys area.
    Ssh(SshDialog),
    /// A dialog of the GPG keys area.
    Gpg(GpgDialog),
    /// Choose a passphrase for a backup containing plaintext keyrings.
    Passphrase {
        command: Box<Command>,
        passphrase: Zeroizing<String>,
        confirm: Zeroizing<String>,
    },
}

impl DialogKind {
    /// Unlock dialog for a collection.
    pub fn unlock(collection: CollectionId, label: String) -> Self {
        Self::Unlock {
            collection,
            label,
            password: new_buffer(),
        }
    }

    /// Dialog unlocking `collections` with one password.
    pub fn unlock_many(collections: Vec<CollectionId>) -> Self {
        Self::UnlockMany {
            collections,
            password: new_buffer(),
        }
    }

    /// New collection dialog.
    pub fn create_collection() -> Self {
        Self::CreateCollection {
            label: String::new(),
            password: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// Change password dialog for a collection.
    pub fn change_password(collection: CollectionId, label: String) -> Self {
        Self::ChangePassword {
            collection,
            label,
            old: new_buffer(),
            new: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// New item dialog for a collection.
    pub fn new_item(collection: CollectionId) -> Self {
        Self::NewItem {
            collection,
            label: String::new(),
            secret: new_buffer(),
            rows: Vec::new(),
        }
    }

    /// Edit dialog for an item; an empty secret keeps the current one.
    pub fn edit_item(item: ItemId, label: String) -> Self {
        Self::EditItem {
            item,
            label,
            secret: new_buffer(),
        }
    }

    /// Password dialog of binary file `name`, resending `action` with the password.
    pub fn file_password(name: String, action: FileAction) -> Self {
        Self::FilePassword {
            name,
            action,
            password: new_buffer(),
        }
    }

    /// Import dialog of file `name`: every keyring is listed, locked ones disabled.
    pub fn import_file(name: String, collections: &[CollectionInfo]) -> Self {
        let names = display_names(collections);
        let targets = collections
            .iter()
            .map(|c| ImportTarget {
                id: c.id.clone(),
                label: names.get(&c.id).cloned().unwrap_or_else(|| display_name(c)),
                locked: c.locked,
            })
            .collect();
        Self::ImportFile {
            name,
            targets,
            target: default_import_target(collections),
        }
    }

    /// Password dialog of wallet `name`.
    pub fn wallet_password(name: String) -> Self {
        Self::WalletPassword {
            name,
            password: new_buffer(),
        }
    }

    /// Import dialog of wallet `name` opened with `password`: every keyring
    /// is listed (locked ones disabled). The keyring labelled like the
    /// wallet (`keyring`) is preselected when unlocked, else the default
    /// import target (first unlocked) is. Without such a keyring, creating
    /// it is offered and preselected unless `create_blocked`.
    pub fn import_wallet(
        name: String,
        password: SecretValue,
        collections: &[CollectionInfo],
        keyring: Option<&CollectionInfo>,
        create_blocked: Option<&'static str>,
    ) -> Self {
        let fallback = || default_import_target(collections).map(WalletTarget::Keyring);
        let target = match (keyring, create_blocked) {
            (Some(c), _) if !c.locked => Some(WalletTarget::Keyring(c.id.clone())),
            (Some(_), _) | (None, Some(_)) => fallback(),
            (None, None) => Some(WalletTarget::Create),
        };
        Self::ImportWallet {
            name,
            password,
            targets: transfer_targets(collections, None),
            target,
            offer_create: keyring.is_none(),
            create_blocked,
            new_password: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// Retire confirmation of file `name` with its body lines.
    pub fn retire_file(name: String, lines: Vec<String>) -> Self {
        Self::RetireFile {
            name,
            lines,
            passphrase: new_buffer(),
            confirm: new_buffer(),
            empty: false,
        }
    }

    /// Retire confirmation of the empty file `name`: no backup passphrase.
    pub fn retire_empty_file(name: String, lines: Vec<String>) -> Self {
        Self::RetireFile {
            name,
            lines,
            passphrase: new_buffer(),
            confirm: new_buffer(),
            empty: true,
        }
    }

    /// Delete confirmation of file `name`, with the backup checkbox checked.
    pub fn delete_file(name: String, spec: DeleteSpec) -> Self {
        Self::DeleteFile {
            name,
            spec,
            backup: true,
            typed: String::new(),
            passphrase: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// Restore confirmation of `files` (original paths) of backup `dir`.
    pub fn restore_backup(
        dir: PathBuf,
        files: Vec<PathBuf>,
        destinations: Vec<String>,
        mode: RestorePassphrase,
    ) -> Self {
        Self::RestoreBackup {
            dir,
            files,
            destinations,
            mode,
            passphrase: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// Export dialog of collection `c` shown as `label`, suggesting
    /// `<home>/kring-<label>-<date>.kring.age`.
    pub fn export_collection(c: &CollectionInfo, label: String, home: &Path, date: &str) -> Self {
        Self::ExportCollection {
            collection: c.id.clone(),
            path: default_export_path(home, &label, date),
            label,
            passphrase: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// Archive import dialog into collection `c`, shown as `label`.
    pub fn import_archive(c: &CollectionInfo, label: String) -> Self {
        Self::ImportArchive {
            target: c.id.clone(),
            label,
            path: String::new(),
            passphrase: new_buffer(),
        }
    }

    /// Copy or move target picker for `items` of keyring `current`; the first
    /// unlocked other keyring is preselected.
    pub fn transfer_target(
        items: Vec<ItemId>,
        mode: TransferMode,
        collections: &[CollectionInfo],
        current: &CollectionId,
    ) -> Self {
        let targets = transfer_targets(collections, Some(current));
        let target = targets.iter().find(|t| !t.locked).map(|t| t.id.clone());
        Self::TransferTarget {
            items,
            mode,
            targets,
            target,
        }
    }

    /// Backup passphrase dialog of transfer plan `plan_id`, keeping `choices`.
    pub fn apply_passphrase(plan_id: u64, choices: Vec<Choice>) -> Self {
        Self::ApplyPassphrase {
            plan_id,
            choices,
            passphrase: new_buffer(),
            confirm: new_buffer(),
        }
    }

    /// Dialog asking the passphrases of `missing` for consolidation plan
    /// `plan_id`, keeping `choices` and the passphrases given before.
    pub fn consolidate_passphrases(
        plan_id: u64,
        choices: Vec<Vec<Choice>>,
        missing: PassphraseNeeds,
        kept_backup: Option<SecretValue>,
        kept_orphan_files: Option<SecretValue>,
    ) -> Self {
        Self::ConsolidatePassphrases {
            plan_id,
            choices,
            ask_backup: missing.backup,
            ask_orphan_files: missing.orphan_files,
            backup: new_buffer(),
            backup_confirm: new_buffer(),
            orphan_files: new_buffer(),
            orphan_files_confirm: new_buffer(),
            kept_backup,
            kept_orphan_files,
        }
    }

    /// Passphrase dialog that resends `command` with the chosen passphrase.
    pub fn passphrase(command: Command) -> Self {
        Self::Passphrase {
            command: Box::new(command),
            passphrase: new_buffer(),
            confirm: new_buffer(),
        }
    }
}

/// Returns the suggested archive path `<home>/kring-<name>-<date>.kring.age`;
/// characters of `name` other than ASCII letters, digits, `-` and `_` become `_`,
/// and runs of `_` collapse into one.
pub fn default_export_path(home: &Path, name: &str, date: &str) -> String {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut collapsed = String::with_capacity(safe.len());
    for c in safe.chars() {
        if c == '_' && collapsed.ends_with('_') {
            continue;
        }
        collapsed.push(c);
    }
    home.join(format!("kring-{collapsed}-{date}.kring.age"))
        .display()
        .to_string()
}

/// Builds an Obsidian modal (SURFACE card over a dimmed backdrop) named `id`.
pub fn styled_modal(ctx: &egui::Context, id: &str) -> egui::Modal {
    let frame = egui::Frame::new()
        .fill(theme::SURFACE)
        .stroke(egui::Stroke::new(1.0_f32, theme::FIELD_ROW_BORDER))
        .corner_radius(egui::CornerRadius::same(theme::RADIUS_WINDOW))
        .shadow(ctx.global_style().visuals.window_shadow)
        .inner_margin(egui::Margin::same(DIALOG_MARGIN));
    egui::Modal::new(egui::Id::unique(id))
        .frame(frame)
        .backdrop_color(egui::Color32::from_black_alpha(BACKDROP_ALPHA))
}

/// What happened to a dialog this frame.
pub enum Outcome {
    /// Still open.
    Open,
    /// Closed without action.
    Cancelled,
    /// Closed, the command must be sent.
    Submitted(Command),
}

/// An open dialog with its last validation error.
pub struct Dialog {
    kind: DialogKind,
    error: Option<String>,
    /// "Remember for this session" is checked.
    remember: bool,
    /// Remembered passphrase used instead of the passphrase fields.
    remembered: Option<SecretValue>,
    /// Reopened after a wrong remembered passphrase.
    retry: bool,
    /// The last successful submit used the remembered passphrase.
    used_remembered: bool,
}

impl Dialog {
    /// Opens a dialog.
    pub fn new(kind: DialogKind) -> Self {
        Self {
            kind,
            error: None,
            remember: false,
            remembered: None,
            retry: false,
            used_remembered: false,
        }
    }

    /// Reopens a dialog after the remembered passphrase was wrong: its
    /// fields are shown (the remembered value is not used) under the error
    /// "Wrong passphrase, try again".
    pub fn retry(kind: DialogKind) -> Self {
        Self {
            error: Some(MSG_WRONG_TRY_AGAIN.to_string()),
            retry: true,
            ..Self::new(kind)
        }
    }

    /// Reopens an SSH or GPG dialog whose key turned out to need a
    /// passphrase: it now asks for it, under the error of its area ("Key
    /// passphrase required", "GPG key passphrase required").
    pub fn key_passphrase_required(kind: DialogKind) -> Self {
        let error = match &kind {
            DialogKind::Gpg(_) => kring_core::gpg::MSG_GPG_PASSPHRASE_REQUIRED,
            _ => kring_core::ssh::MSG_KEY_PASSPHRASE_REQUIRED,
        };
        Self {
            error: Some(error.to_string()),
            retry: true,
            ..Self::new(kind)
        }
    }

    /// Returns the dialog to reopen (passphrase fields empty) if the last
    /// submit proves to carry a wrong passphrase: when it used the
    /// remembered one, and always for the file and wallet password dialogs
    /// (see [`reopens_when_wrong`]).
    pub fn retry_kind(&self) -> Option<DialogKind> {
        let watch = self.used_remembered || reopens_when_wrong(&self.kind);
        watch.then(|| cleared(&self.kind))
    }

    /// Opens a dialog that uses `remembered` instead of its passphrase
    /// fields, when it has some (see [`uses_remembered`]).
    pub fn with_remembered(kind: DialogKind, remembered: Option<&SecretValue>) -> Self {
        let remembered = remembered.filter(|_| uses_remembered(&kind)).cloned();
        Self {
            remembered,
            ..Self::new(kind)
        }
    }

    /// Returns true when a wrong password reopens this dialog.
    pub fn reopens_when_wrong(&self) -> bool {
        reopens_when_wrong(&self.kind)
    }

    /// Returns true when the passphrase to remember is kept only once its
    /// command proves it right (see [`remembers_only_when_correct`]).
    pub fn remembers_only_when_correct(&self) -> bool {
        remembers_only_when_correct(&self.kind)
    }

    /// Returns the passphrase to remember from the sent command, when
    /// "Remember for this session" was checked.
    pub fn to_remember(&self, cmd: &Command) -> Option<SecretValue> {
        if !self.remember {
            return None;
        }
        passphrase_of(cmd).cloned()
    }

    /// Returns true while the remembered passphrase replaces the fields.
    fn _uses_remembered(&self) -> bool {
        self.remembered.is_some() && uses_remembered(&self.kind)
    }

    /// Validates the fields and builds the command to send; the remembered
    /// passphrase (when used) fills the passphrase fields for this check
    /// only, they are emptied again afterwards.
    pub fn submit(&mut self) -> Result<Command, String> {
        self.used_remembered = false;
        let Some(secret) = self
            .remembered
            .as_ref()
            .filter(|_| uses_remembered(&self.kind))
        else {
            return command_for(&self.kind);
        };
        fill_passphrases(&mut self.kind, secret);
        let result = command_for(&self.kind);
        fill_passphrases(&mut self.kind, &SecretValue::from_text(""));
        self.used_remembered = result.is_ok();
        result
    }

    /// Renders the dialog and reports whether it closed.
    pub fn show(&mut self, ctx: &egui::Context) -> Outcome {
        let mut submit = false;
        let mut cancel = false;
        let response = styled_modal(ctx, MODAL_ID).show(ctx, |ui| {
            ui.set_width(DIALOG_WIDTH);
            let hide = self._uses_remembered();
            let main = body(ui, &mut self.kind, hide, self.retry);
            if hide {
                if remembered_row(ui) {
                    self.remembered = None;
                }
            } else if offers_remember(&self.kind) {
                remember_row(ui, &mut self.remember);
            }
            if let Some(err) = &self.error {
                ui.label(egui::RichText::new(err).color(theme::ERROR));
            }
            ui.add_space(8.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                submit = if main.danger {
                    danger_button(ui, main.text, main.blocked)
                } else {
                    primary_button(ui, main.text, main.blocked)
                };
                cancel = secondary_button(ui, "Cancel", None);
            });
        });
        if cancel || response.should_close() {
            forget_fields(ctx);
            return Outcome::Cancelled;
        }
        if !submit {
            return Outcome::Open;
        }
        match self.submit() {
            Ok(cmd) => {
                forget_fields(ctx);
                Outcome::Submitted(cmd)
            }
            Err(e) => {
                self.error = Some(e);
                Outcome::Open
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::dialog_submit::with_backup_passphrase;
    use kring_core::model::SecretValue;

    /// Fills a zeroizing buffer with text.
    fn buf(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_string())
    }

    /// Mismatched new passwords are rejected; a valid change carries both passwords.
    #[test]
    fn change_password_validates_confirmation() {
        let id = CollectionId("/c/work".into());
        let mut d = Dialog::new(DialogKind::ChangePassword {
            collection: id.clone(),
            label: "Work".into(),
            old: buf("old"),
            new: buf("a"),
            confirm: buf("b"),
        });
        assert!(d.submit().is_err());
        if let DialogKind::ChangePassword { confirm, .. } = &mut d.kind {
            *confirm = buf("a");
        }
        match d.submit().unwrap() {
            Command::ChangePassword {
                collection,
                old,
                new,
            } => {
                assert_eq!(collection, id);
                assert_eq!(old.as_text(), Some("old"));
                assert_eq!(new.as_text(), Some("a"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// A blank collection name is rejected and names are trimmed.
    #[test]
    fn create_collection_validates_label() {
        let mut d = Dialog::new(DialogKind::CreateCollection {
            label: "  ".into(),
            password: buf("p"),
            confirm: buf("p"),
        });
        assert!(d.submit().is_err());
        if let DialogKind::CreateCollection { label, .. } = &mut d.kind {
            *label = " Work ".into();
        }
        match d.submit().unwrap() {
            Command::CreateCollection { label, password } => {
                assert_eq!(label, "Work");
                assert_eq!(password.as_text(), Some("p"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Duplicate attribute keys are rejected; valid rows become attributes.
    #[test]
    fn new_item_validates_attributes() {
        let coll = CollectionId("/c/a".into());
        let mut d = Dialog::new(DialogKind::NewItem {
            collection: coll.clone(),
            label: "site".into(),
            secret: buf("s3"),
            rows: vec![("k".into(), "1".into()), ("k".into(), "2".into())],
        });
        assert!(d.submit().is_err());
        if let DialogKind::NewItem { rows, .. } = &mut d.kind {
            rows.pop();
        }
        match d.submit().unwrap() {
            Command::CreateItem { collection, item } => {
                assert_eq!(collection, coll);
                assert_eq!(item.label, "site");
                assert_eq!(item.attributes.get("k").map(String::as_str), Some("1"));
                assert_eq!(item.secret.as_text(), Some("s3"));
                assert!(!item.replace);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// An empty secret in the edit dialog keeps the current secret.
    #[test]
    fn edit_item_empty_secret_unchanged() {
        let mut d = Dialog::new(DialogKind::edit_item(ItemId("/c/a/1".into()), "new".into()));
        match d.submit().unwrap() {
            Command::UpdateItem { update, .. } => {
                assert_eq!(update.label.as_deref(), Some("new"));
                assert!(update.secret.is_none());
                assert!(update.attributes.is_none());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// The passphrase dialog resends the original command with the passphrase set.
    #[test]
    fn passphrase_resends_command() {
        let original = Command::DeleteCollection {
            collection: CollectionId("/c/a".into()),
            backup_passphrase: None,
        };
        let mut d = Dialog::new(DialogKind::passphrase(original));
        assert!(d.submit().is_err(), "empty passphrase rejected");
        if let DialogKind::Passphrase {
            passphrase,
            confirm,
            ..
        } = &mut d.kind
        {
            *passphrase = buf("pp");
            *confirm = buf("pp");
        }
        match d.submit().unwrap() {
            Command::DeleteCollection {
                backup_passphrase, ..
            } => assert_eq!(backup_passphrase.unwrap().as_text(), Some("pp")),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// The file password dialog resends Open or Import with the password.
    #[test]
    fn file_password_resends_action() {
        let mut d = Dialog::new(DialogKind::file_password("b".into(), FileAction::Open));
        if let DialogKind::FilePassword { password, .. } = &mut d.kind {
            *password = buf("pw");
        }
        match d.submit().unwrap() {
            Command::OpenFile { name, password } => {
                assert_eq!(name, "b");
                assert_eq!(password.unwrap().as_text(), Some("pw"));
            }
            other => panic!("unexpected {other:?}"),
        }
        let target = CollectionId("/c/t".into());
        let mut d = Dialog::new(DialogKind::file_password(
            "b".into(),
            FileAction::Import {
                target: target.clone(),
            },
        ));
        assert!(d.submit().is_err(), "empty password rejected");
        if let DialogKind::FilePassword { password, .. } = &mut d.kind {
            *password = buf("pw");
        }
        match d.submit().unwrap() {
            Command::ImportFile {
                name,
                password,
                target: t,
            } => {
                assert_eq!(name, "b");
                assert_eq!(password.unwrap().as_text(), Some("pw"));
                assert_eq!(t, target);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// The import dialog lists every keyring, defaults to login and refuses locked targets.
    #[test]
    fn import_file_targets() {
        use kring_core::model::LOGIN_COLLECTION_PATH;
        let col = |path: &str, label: &str, locked: bool| CollectionInfo {
            id: CollectionId(path.into()),
            label: label.into(),
            locked,
            item_count: 0,
            aliases: vec![],
            is_login: path == LOGIN_COLLECTION_PATH,
            created: 0,
            modified: 0,
        };
        let cols = [
            col("/c/work", "Work", true),
            col(LOGIN_COLLECTION_PATH, "Login", false),
        ];
        let mut d = Dialog::new(DialogKind::import_file("t".into(), &cols));
        let DialogKind::ImportFile {
            targets, target, ..
        } = &mut d.kind
        else {
            panic!("expected ImportFile");
        };
        assert_eq!(targets.len(), 2);
        assert!(targets[0].locked && targets[0].label == "Work");
        assert_eq!(
            target.as_ref().map(|t| t.0.as_str()),
            Some(LOGIN_COLLECTION_PATH)
        );
        *target = Some(CollectionId("/c/work".into()));
        assert!(d.submit().is_err(), "locked target rejected");
        if let DialogKind::ImportFile { target, .. } = &mut d.kind {
            *target = None;
        }
        assert!(d.submit().is_err(), "missing target rejected");
        if let DialogKind::ImportFile { target, .. } = &mut d.kind {
            *target = Some(CollectionId(LOGIN_COLLECTION_PATH.into()));
        }
        match d.submit().unwrap() {
            Command::ImportFile {
                name,
                password,
                target,
            } => {
                assert_eq!(name, "t");
                assert!(password.is_none());
                assert_eq!(target.0, LOGIN_COLLECTION_PATH);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// The wallet password dialog opens the wallet; the import dialog
    /// imports into an unlocked keyring with the kept wallet password, or
    /// creates the wallet keyring with a confirmed new password.
    #[test]
    fn wallet_dialogs_submit() {
        let mut d = Dialog::new(DialogKind::wallet_password("kdewallet".into()));
        assert!(d.submit().is_err(), "empty password rejected");
        if let DialogKind::WalletPassword { password, .. } = &mut d.kind {
            *password = buf("pw");
        }
        let Ok(Command::OpenWallet { name, password }) = d.submit() else {
            panic!("expected OpenWallet");
        };
        assert_eq!(
            (name.as_str(), password.as_text()),
            ("kdewallet", Some("pw"))
        );

        let col = |path: &str, label: &str, locked: bool| CollectionInfo {
            id: CollectionId(path.into()),
            label: label.into(),
            locked,
            item_count: 0,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        };
        let cols = [col("/c/a", "A", false), col("/c/w", "Work", true)];
        let kind = DialogKind::import_wallet(
            "kdewallet".into(),
            SecretValue::from_text("wallet-pw"),
            &cols,
            None,
            None,
        );
        let mut d = Dialog::new(kind);
        assert!(d.submit().is_err(), "new password needed");
        if let DialogKind::ImportWallet {
            new_password,
            confirm,
            ..
        } = &mut d.kind
        {
            *new_password = buf("np");
            *confirm = buf("np");
        }
        let Ok(Command::CreateWalletCollection { name, password }) = d.submit() else {
            panic!("expected CreateWalletCollection");
        };
        assert_eq!(
            (name.as_str(), password.as_text()),
            ("kdewallet", Some("np"))
        );
        let set = |d: &mut Dialog, t: Option<WalletTarget>| {
            if let DialogKind::ImportWallet { target, .. } = &mut d.kind {
                *target = t;
            }
        };
        set(
            &mut d,
            Some(WalletTarget::Keyring(CollectionId("/c/w".into()))),
        );
        assert!(d.submit().is_err(), "locked target rejected");
        set(&mut d, None);
        assert!(d.submit().is_err(), "missing target rejected");
        set(
            &mut d,
            Some(WalletTarget::Keyring(CollectionId("/c/a".into()))),
        );
        let Ok(Command::PlanWalletImport {
            name,
            password,
            target,
        }) = d.submit()
        else {
            panic!("expected PlanWalletImport");
        };
        assert_eq!(name, "kdewallet");
        assert_eq!(password.as_text(), Some("wallet-pw"));
        assert_eq!(target.0, "/c/a");

        let blocked = DialogKind::import_wallet(
            "kdewallet".into(),
            SecretValue::from_text("wallet-pw"),
            &cols,
            None,
            Some("Requires gnome-keyring"),
        );
        let mut d = Dialog::new(blocked);
        set(&mut d, Some(WalletTarget::Create));
        assert_eq!(d.submit().unwrap_err(), "Requires gnome-keyring");
    }

    /// Retire needs a confirmed backup passphrase.
    #[test]
    fn retire_file_needs_confirmed_passphrase() {
        let mut d = Dialog::new(DialogKind::retire_file("t".into(), vec!["x".into()]));
        assert!(d.submit().is_err(), "empty passphrase rejected");
        if let DialogKind::RetireFile {
            passphrase,
            confirm,
            ..
        } = &mut d.kind
        {
            *passphrase = buf("pp");
            *confirm = buf("pq");
        }
        assert!(d.submit().is_err(), "mismatch rejected");
        if let DialogKind::RetireFile { confirm, .. } = &mut d.kind {
            *confirm = buf("pp");
        }
        match d.submit().unwrap() {
            Command::RetireFile {
                name,
                backup_passphrase,
            } => {
                assert_eq!(name, "t");
                assert_eq!(backup_passphrase.unwrap().as_text(), Some("pp"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Confirming attribute changes updates only the attributes.
    #[test]
    fn save_attributes_updates_attributes_only() {
        let mut d = Dialog::new(DialogKind::SaveAttributes {
            item: ItemId("/c/a/1".into()),
            label: "x".into(),
            attributes: [("k".to_string(), "v".to_string())].into(),
            changes: vec!["Added: k = v".into()],
        });
        match d.submit().unwrap() {
            Command::UpdateItem { item, update } => {
                assert_eq!(item, ItemId("/c/a/1".into()));
                assert!(update.label.is_none() && update.secret.is_none());
                assert_eq!(update.attributes.unwrap().get("k").unwrap(), "v");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Delete item carries the passphrase too; other commands are unchanged.
    #[test]
    fn with_backup_passphrase_only_for_deletes() {
        let cmd = with_backup_passphrase(
            Command::DeleteItem {
                item: ItemId("/c/a/1".into()),
                backup_passphrase: None,
            },
            SecretValue::from_text("x"),
        );
        assert!(matches!(
            cmd,
            Command::DeleteItem {
                backup_passphrase: Some(_),
                ..
            }
        ));
        let cmd = with_backup_passphrase(Command::Refresh, SecretValue::from_text("x"));
        assert!(matches!(cmd, Command::Refresh));
    }

    /// The target picker plans the transfer; locked or missing targets are refused.
    #[test]
    fn transfer_target_plans_transfer() {
        use kring_core::transfer::apply::TransferMode;
        let col = |path: &str, label: &str, locked: bool| CollectionInfo {
            id: CollectionId(path.into()),
            label: label.into(),
            locked,
            item_count: 0,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        };
        let cols = [
            col("/c/a", "A", false),
            col("/c/w", "Work", true),
            col("/c/b", "B", false),
        ];
        let items = vec![ItemId("/c/a/1".into())];
        let current = CollectionId("/c/a".into());
        let mut d = Dialog::new(DialogKind::transfer_target(
            items.clone(),
            TransferMode::Move,
            &cols,
            &current,
        ));
        let DialogKind::TransferTarget {
            targets, target, ..
        } = &mut d.kind
        else {
            panic!("expected TransferTarget");
        };
        assert_eq!(targets.len(), 2, "the current keyring is not offered");
        assert_eq!(target.as_ref().map(|t| t.0.as_str()), Some("/c/b"));
        *target = Some(CollectionId("/c/w".into()));
        assert!(d.submit().is_err(), "locked target rejected");
        if let DialogKind::TransferTarget { target, .. } = &mut d.kind {
            *target = None;
        }
        assert!(d.submit().is_err(), "missing target rejected");
        if let DialogKind::TransferTarget { target, .. } = &mut d.kind {
            *target = Some(CollectionId("/c/b".into()));
        }
        match d.submit().unwrap() {
            Command::PlanTransfer {
                items: sent,
                target,
                mode,
            } => {
                assert_eq!(sent, items);
                assert_eq!(target.0, "/c/b");
                assert_eq!(mode, TransferMode::Move);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// The apply passphrase dialog resends the plan with the kept choices
    /// and a confirmed passphrase.
    #[test]
    fn apply_passphrase_resends_plan() {
        use kring_core::transfer::plan::Choice;
        let choices = vec![Choice::UseIncoming, Choice::KeepTarget];
        let mut d = Dialog::new(DialogKind::apply_passphrase(4, choices.clone()));
        assert!(d.submit().is_err(), "empty passphrase rejected");
        if let DialogKind::ApplyPassphrase {
            passphrase,
            confirm,
            ..
        } = &mut d.kind
        {
            *passphrase = buf("pp");
            *confirm = buf("pq");
        }
        assert!(d.submit().is_err(), "mismatch rejected");
        if let DialogKind::ApplyPassphrase { confirm, .. } = &mut d.kind {
            *confirm = buf("pp");
        }
        match d.submit().unwrap() {
            Command::ApplyTransfer {
                plan_id,
                choices: sent,
                backup_passphrase,
            } => {
                assert_eq!(plan_id, 4);
                assert_eq!(sent, choices);
                assert_eq!(backup_passphrase.unwrap().as_text(), Some("pp"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// A dialog using the remembered passphrase submits without typed
    /// fields (no confirmation) and remembers nothing unless checked.
    #[test]
    fn remembered_passphrase_fills_dialog() {
        let secret = SecretValue::from_text("kept");
        let kind = DialogKind::retire_file("p".into(), vec![]);
        let mut d = Dialog::with_remembered(kind, Some(&secret));
        let cmd = d.submit().unwrap();
        let Command::RetireFile {
            backup_passphrase, ..
        } = &cmd
        else {
            panic!("expected a retire");
        };
        assert_eq!(backup_passphrase.as_ref().unwrap().as_text(), Some("kept"));
        assert!(d.to_remember(&cmd).is_none());
        d.remember = true;
        assert_eq!(d.to_remember(&cmd).unwrap().as_text(), Some("kept"));
    }

    /// The unlock dialog never uses the remembered value (it opens only
    /// after the remembered one failed).
    #[test]
    fn unlock_dialog_not_filled() {
        let secret = SecretValue::from_text("kept");
        let kind = DialogKind::unlock(CollectionId("/c/a".into()), "a".into());
        let mut d = Dialog::with_remembered(kind, Some(&secret));
        assert!(!d._uses_remembered());
        let Ok(Command::Unlock { password, .. }) = d.submit() else {
            panic!("expected an unlock");
        };
        assert_eq!(password.as_text(), Some(""));
    }

    /// The dialog unlocking many keyrings sends one password for all of
    /// them, offers "Remember" (kept only once one keyring unlocked) and
    /// never uses or reopens with the remembered value.
    #[test]
    fn unlock_many_dialog() {
        let ids = vec![CollectionId("/c/a".into()), CollectionId("/c/b".into())];
        let kind = DialogKind::unlock_many(ids.clone());
        assert!(offers_remember(&kind));
        assert!(!uses_remembered(&kind));
        let secret = SecretValue::from_text("kept");
        let mut d = Dialog::with_remembered(kind, Some(&secret));
        assert!(d.remembers_only_when_correct());
        assert!(d.retry_kind().is_none());
        if let DialogKind::UnlockMany { password, .. } = &mut d.kind {
            *password = buf("typed");
        }
        let Ok(cmd) = d.submit() else {
            panic!("expected a command");
        };
        let Command::UnlockMany {
            collections,
            password,
        } = &cmd
        else {
            panic!("expected UnlockMany");
        };
        assert_eq!(collections, &ids);
        assert_eq!(password.as_text(), Some("typed"));
        d.remember = true;
        assert_eq!(d.to_remember(&cmd).unwrap().as_text(), Some("typed"));
        let one = Dialog::new(DialogKind::unlock(ids[0].clone(), "a".into()));
        assert!(!one.remembers_only_when_correct());
    }

    /// A failed submit with the remembered passphrase empties the fields
    /// again, so "Type another" never shows it.
    #[test]
    fn failed_remembered_submit_clears_fields() {
        let secret = SecretValue::from_text("kept");
        let c = CollectionInfo {
            id: CollectionId("/c/a".into()),
            label: "a".into(),
            locked: false,
            item_count: 0,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        };
        let mut kind = DialogKind::import_archive(&c, "a".into());
        if let DialogKind::ImportArchive { path, .. } = &mut kind {
            path.clear();
        }
        let mut d = Dialog::with_remembered(kind, Some(&secret));
        assert!(d.submit().is_err(), "empty path rejected");
        let DialogKind::ImportArchive { passphrase, .. } = &d.kind else {
            panic!("expected the import dialog");
        };
        assert!(passphrase.is_empty());
    }

    /// A submit with the remembered value offers the dialog to reopen with
    /// empty fields; one with typed fields does not.
    #[test]
    fn retry_kind_after_remembered_submit() {
        let secret = SecretValue::from_text("kept");
        let kind = DialogKind::retire_file("p".into(), vec![]);
        let mut d = Dialog::with_remembered(kind, Some(&secret));
        assert!(d.retry_kind().is_none());
        d.submit().unwrap();
        let Some(DialogKind::RetireFile {
            passphrase,
            confirm,
            ..
        }) = d.retry_kind()
        else {
            panic!("expected the retire dialog");
        };
        assert!(passphrase.is_empty() && confirm.is_empty());
        let mut typed = Dialog::new(DialogKind::retire_file("p".into(), vec![]));
        if let DialogKind::RetireFile {
            passphrase,
            confirm,
            ..
        } = &mut typed.kind
        {
            *passphrase = buf("x");
            *confirm = buf("x");
        }
        typed.submit().unwrap();
        assert!(typed.retry_kind().is_none());
    }

    /// The reopened dialog shows its fields and the wrong passphrase error.
    #[test]
    fn retry_dialog_shows_fields() {
        let d = Dialog::retry(DialogKind::retire_file("p".into(), vec![]));
        assert!(!d._uses_remembered());
        assert_eq!(d.error.as_deref(), Some(MSG_WRONG_TRY_AGAIN));
        assert!(d.retry);
    }
}
