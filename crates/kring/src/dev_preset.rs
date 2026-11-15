//! Screenshot presets for the isolated dev session (debug builds only).
//!
//! The preset can select a keyring, expand an item, reveal its secret and
//! open a dialog without clicks. It is honoured only when the environment
//! passes `kring_core::dev_guard::violation_from` (private runtime dir and a
//! bus that is not the real user bus), so a leftover export in a normal
//! session cannot reveal a secret from the real keyring.

use std::path::Path;

use kring_core::dev_guard::{IT_RUNTIME_VAR, violation_from};
use kring_core::model::{CollectionId, CollectionInfo, ItemId, SecretValue};
use kring_core::transfer::apply::TransferMode;

use crate::app_state::AppState;
use crate::views::backups::{BackupView, path_exists, restore_dialog};
use crate::views::collection::{display_name, export_dialog, shown_name};
use crate::views::consolidate::{default_target, needs_passphrases};
use crate::views::dialogs::DialogKind;
use crate::views::file_detail::{delete_dialog, retire_dialog};
use crate::views::file_items::displayed_file_items;
use crate::views::item_list::displayed_items;
use crate::views::transfer::default_choices;
use crate::views::{Action, Area};
use crate::worker::Command;

/// Keyring (display name) to select first.
const VAR_SELECT: &str = "KRING_DEV_SELECT";
/// Index of the card (in displayed order) to expand.
const VAR_EXPAND: &str = "KRING_DEV_EXPAND";
/// Any non-empty value reveals the expanded item's secret.
const VAR_REVEAL: &str = "KRING_DEV_REVEAL";
/// Dialog to open: `new-keyring`, `unlock`, `export`, `import-archive`,
/// `delete-item-now` (deletes the expanded, or first, item of the selected
/// keyring right away, showing the progress modal) or
/// `transfer-preview` (checks every item of the selected keyring and plans
/// copying them into the other keyring of [`TRANSFER_PAIR`]; with
/// [`VAR_REVEAL`] both sides of the first conflict are revealed); in
/// the files area `import`, `retire`, `delete-file`, `delete-file-no-backup`
/// (backup unchecked) or `open` (password of a binary file);
/// in the backups area `restore` (confirmation) or `restore-now` (restores
/// every file of the selected backup without a passphrase); in the
/// consolidate area `consolidate-preview` (plans a consolidation into the
/// default target with the orphan files; with [`VAR_REVEAL`] both sides of
/// the first conflict are revealed), `consolidate-apply` (then opens the
/// passphrase dialog of the apply) or `consolidate-now` (then applies with
/// the preselected choices and [`DEV_PASSPHRASE`] for every passphrase).
const VAR_DIALOG: &str = "KRING_DEV_DIALOG";
/// Area to show first: `files`, `backups` or `consolidate`.
const VAR_AREA: &str = "KRING_DEV_AREA";
/// Keyring file (name without `.keyring`) to select in the files area.
const VAR_FILE: &str = "KRING_DEV_FILE";
/// Index (newest first) of the backup to select in the backups area.
const VAR_BACKUP: &str = "KRING_DEV_BACKUP";
/// Any non-empty value remembers [`DEV_PASSPHRASE`] for the session at start.
const VAR_REMEMBER: &str = "KRING_DEV_REMEMBER";
/// Value of [`VAR_DIALOG`] deleting an item right away.
const DIALOG_DELETE_ITEM_NOW: &str = "delete-item-now";
/// Value of [`VAR_DIALOG`] opening the transfer preview.
const DIALOG_TRANSFER_PREVIEW: &str = "transfer-preview";
/// Seeded keyrings sharing items (display names, compared case-insensitively).
const TRANSFER_PAIR: [&str; 2] = ["login", "work"];
/// Value of [`VAR_AREA`] selecting the Offline files area.
const AREA_FILES: &str = "files";
/// Value of [`VAR_AREA`] selecting the Backups area.
const AREA_BACKUPS: &str = "backups";
/// Value of [`VAR_AREA`] selecting the Consolidate area.
const AREA_CONSOLIDATE: &str = "consolidate";
/// Value of [`VAR_DIALOG`] opening the consolidation preview.
const DIALOG_CONSOLIDATE_PREVIEW: &str = "consolidate-preview";
/// Value of [`VAR_DIALOG`] opening the passphrase dialog of the consolidation.
const DIALOG_CONSOLIDATE_APPLY: &str = "consolidate-apply";
/// Value of [`VAR_DIALOG`] applying the consolidation right away.
const DIALOG_CONSOLIDATE_NOW: &str = "consolidate-now";
/// Passphrase used by `consolidate-now` (same as the seeded backups).
const DEV_PASSPHRASE: &str = "backup";

/// Initial state requested for screenshots.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DevPreset {
    /// Display name of the keyring to select first.
    pub select: Option<String>,
    /// Index of the card to expand (displayed, sorted order) once items are loaded.
    pub expand: Option<usize>,
    /// Reveal the expanded item's secret.
    pub reveal: bool,
    /// Dialog to open at start: `new-keyring` or `unlock`; `import`, `retire`
    /// or `open` in the files area.
    pub dialog: Option<String>,
    /// Area to show first (`files`).
    pub area: Option<String>,
    /// Keyring file to select in the files area.
    pub file: Option<String>,
    /// Backup (index, newest first) to select in the backups area.
    pub backup: Option<usize>,
    /// Reveal both sides of the first conflict once the transfer preview is open.
    pub transfer_reveal: bool,
    /// Step after the consolidation preview arrived (`consolidate-apply` or
    /// `consolidate-now`).
    pub consolidate_follow: Option<String>,
    /// Remember [`DEV_PASSPHRASE`] for the session at start.
    pub remember: bool,
}

/// Builds the preset from the given environment values; empty unless they
/// describe the isolated session. `get_var` reads the preset variables.
pub fn preset_from(
    it_runtime: Option<&str>,
    runtime_dir: Option<&str>,
    bus_addr: Option<&str>,
    get_var: impl Fn(&str) -> Option<String>,
) -> DevPreset {
    if violation_from(it_runtime, runtime_dir, bus_addr).is_some() {
        return DevPreset::default();
    }
    let var = |name: &str| get_var(name).filter(|v| !v.is_empty());
    DevPreset {
        select: var(VAR_SELECT),
        expand: var(VAR_EXPAND).and_then(|v| v.parse().ok()),
        reveal: var(VAR_REVEAL).is_some(),
        dialog: var(VAR_DIALOG),
        area: var(VAR_AREA),
        file: var(VAR_FILE),
        backup: var(VAR_BACKUP).and_then(|v| v.parse().ok()),
        transfer_reveal: false,
        consolidate_follow: None,
        remember: var(VAR_REMEMBER).is_some(),
    }
}

/// Reads the preset from the process environment.
pub fn from_env() -> DevPreset {
    let get = |name: &str| std::env::var(name).ok();
    let it_runtime = get(IT_RUNTIME_VAR);
    let runtime_dir = get("XDG_RUNTIME_DIR");
    let bus_addr = get("DBUS_SESSION_BUS_ADDRESS");
    preset_from(
        it_runtime.as_deref(),
        runtime_dir.as_deref(),
        bus_addr.as_deref(),
        get,
    )
}

impl DevPreset {
    /// Keyring to select first, when the preset names an existing one.
    pub fn preferred_collection(&self, state: &AppState) -> Option<CollectionId> {
        let wanted = self.select.as_deref()?;
        state
            .collections
            .iter()
            .find(|c| display_name(c) == wanted)
            .map(|c| c.id.clone())
    }

    /// Passphrase to remember for the session at start; returned once.
    pub fn take_remembered(&mut self) -> Option<SecretValue> {
        std::mem::take(&mut self.remember).then(|| SecretValue::from_text(DEV_PASSPHRASE))
    }

    /// Area to switch to at start; returned once.
    pub fn take_area(&mut self) -> Option<Area> {
        let area = self.area.take()?;
        match area.as_str() {
            AREA_FILES => Some(Area::Files),
            AREA_BACKUPS => Some(Area::Backups),
            AREA_CONSOLIDATE => Some(Area::Consolidate),
            _ => None,
        }
    }

    /// Backups area actions due now: selects the preset backup in `view`
    /// once listed, then opens or sends the restore; each fires once.
    pub fn take_backup_actions(
        &mut self,
        state: &AppState,
        view: &mut BackupView,
        keyrings_dir: &Path,
    ) -> Vec<Action> {
        if let Some(index) = self.backup {
            let Some(info) = state.backups.get(index) else {
                return Vec::new();
            };
            view.select(Some(info.dir.clone()));
            self.backup = None;
        }
        let Some(info) = view
            .selected
            .as_ref()
            .and_then(|d| state.backups.iter().find(|b| &b.dir == d))
        else {
            return Vec::new();
        };
        let action = match self.dialog.as_deref() {
            Some("restore") => {
                let checked = view.checked(info);
                Action::Open(restore_dialog(
                    info,
                    &checked,
                    &state.files,
                    keyrings_dir,
                    path_exists,
                ))
            }
            Some("restore-now") => Action::Send(Command::RestoreBackup {
                dir: info.dir.clone(),
                files: info.files.iter().map(|f| f.original.clone()).collect(),
                passphrase: None,
            }),
            _ => return Vec::new(),
        };
        self.dialog = None;
        vec![action]
    }

    /// Files area actions due now (select file, dialog); each fires once when its data exists.
    pub fn take_file_actions(&mut self, state: &AppState) -> Vec<Action> {
        let mut out = Vec::new();
        if let Some(name) = self.file.as_deref() {
            if !state.files.iter().any(|f| f.name == name) {
                return out;
            }
            out.push(Action::SelectFile(name.to_string()));
            self.file = None;
            return out;
        }
        let Some(info) = state
            .selected_file
            .as_ref()
            .and_then(|n| state.files.iter().find(|f| &f.name == n))
        else {
            return out;
        };
        let action = match self.dialog.as_deref() {
            Some("import") => Some(Action::Open(DialogKind::import_file(
                info.name.clone(),
                &state.collections,
            ))),
            Some("retire") => Some(Action::Open(retire_dialog(state, info))),
            Some("delete-file") => Some(Action::Open(delete_dialog(state, info))),
            // Unchecks the backup only where it is optional (never for a
            // loaded keyring holding items).
            Some("delete-file-no-backup") => {
                let mut kind = delete_dialog(state, info);
                if let DialogKind::DeleteFile { spec, backup, .. } = &mut kind {
                    *backup = !spec.backup_optional;
                }
                Some(Action::Open(kind))
            }
            Some("open") => Some(Action::Send(Command::OpenFile {
                name: info.name.clone(),
                password: None,
            })),
            _ => None,
        };
        if let Some(action) = action {
            self.dialog = None;
            out.push(action);
        }
        out
    }

    /// Files area card to expand, as `(index into file_items, reveal)`; returned
    /// once, after the items of the selected file arrived.
    pub fn take_file_card(&mut self, state: &AppState) -> Option<(usize, bool)> {
        let wanted = self.expand?;
        let index = *displayed_file_items(&state.file_items, "").get(wanted)?;
        self.expand = None;
        Some((index, self.reveal))
    }

    /// Transfer preview actions due now: once the selected keyring of
    /// [`TRANSFER_PAIR`] listed its items, checks them all and plans copying
    /// them into the other keyring of the pair; fires once.
    fn _take_transfer_preview(&mut self, state: &AppState, filter: &str) -> Vec<Action> {
        let in_pair = |c: &&CollectionInfo| {
            let name = display_name(c).to_lowercase();
            TRANSFER_PAIR.contains(&name.as_str())
        };
        let Some(current) = state.selected.as_ref() else {
            return Vec::new();
        };
        let pair: Vec<&CollectionInfo> = state.collections.iter().filter(in_pair).collect();
        let source = pair.iter().find(|c| &c.id == current);
        let target = pair.iter().find(|c| &c.id != current && !c.locked);
        let items: Vec<ItemId> = displayed_items(state, filter)
            .iter()
            .map(|i| i.id.clone())
            .collect();
        let (Some(_), Some(target)) = (source, target) else {
            return Vec::new();
        };
        if items.is_empty() {
            return Vec::new();
        }
        self.dialog = None;
        self.transfer_reveal = self.reveal;
        let mut out: Vec<Action> = items
            .iter()
            .filter(|id| !state.selection.contains(id))
            .map(|id| Action::ToggleSelect(id.clone()))
            .collect();
        out.push(Action::Send(Command::PlanTransfer {
            items,
            target: target.id.clone(),
            mode: TransferMode::Copy,
        }));
        out
    }

    /// Consolidate area actions due now: once the collections are listed,
    /// plans a consolidation into the default target with the orphan files;
    /// fires once.
    ///
    /// With `consolidate-apply` / `consolidate-now` the apply follows once
    /// the preview arrived.
    pub fn take_consolidate_actions(&mut self, state: &AppState) -> Vec<Action> {
        if self.consolidate_follow.is_some() {
            return self._take_consolidate_follow(state);
        }
        let wanted = [
            DIALOG_CONSOLIDATE_PREVIEW,
            DIALOG_CONSOLIDATE_APPLY,
            DIALOG_CONSOLIDATE_NOW,
        ];
        if !self.dialog.as_deref().is_some_and(|d| wanted.contains(&d)) {
            return Vec::new();
        }
        let Some(target) = default_target(&state.collections) else {
            return Vec::new();
        };
        let dialog = self.dialog.take();
        self.consolidate_follow = dialog.filter(|d| d != DIALOG_CONSOLIDATE_PREVIEW);
        self.transfer_reveal = self.reveal;
        vec![Action::Send(Command::PlanConsolidation {
            target,
            include_orphan_files: true,
        })]
    }

    /// Opens the passphrase dialog or sends the apply of the consolidation
    /// preview with its preselected choices; fires once.
    fn _take_consolidate_follow(&mut self, state: &AppState) -> Vec<Action> {
        let Some((plan_id, summary)) = &state.consolidation_preview else {
            return Vec::new();
        };
        let Some(follow) = self.consolidate_follow.take() else {
            return Vec::new();
        };
        let choices: Vec<_> = summary
            .steps
            .iter()
            .map(|s| default_choices(&s.conflicts))
            .collect();
        let needs = needs_passphrases(summary);
        if follow == DIALOG_CONSOLIDATE_APPLY {
            let kind = DialogKind::consolidate_passphrases(*plan_id, choices, needs, None, None);
            return vec![Action::Open(kind)];
        }
        let pass = |needed: bool| needed.then(|| SecretValue::from_text(DEV_PASSPHRASE));
        vec![Action::Send(Command::ApplyConsolidation {
            plan_id: *plan_id,
            choices,
            backup_passphrase: pass(needs.backup),
            orphan_files_passphrase: pass(needs.orphan_files),
        })]
    }

    /// Reveals both sides of the first conflict of the open transfer or
    /// consolidation preview (never a planned target item); fires once.
    pub fn take_transfer_reveal(&mut self, state: &AppState) -> Vec<Action> {
        if !self.transfer_reveal {
            return Vec::new();
        }
        let transfer = state
            .transfer_preview
            .as_ref()
            .and_then(|p| p.conflicts.first());
        let consolidation = state
            .consolidation_preview
            .as_ref()
            .and_then(|(_, s)| s.steps.iter().find_map(|step| step.conflicts.first()));
        let Some(first) = transfer.or(consolidation) else {
            return Vec::new();
        };
        self.transfer_reveal = false;
        let existing = first
            .existing_item
            .as_ref()
            .filter(|_| !first.existing_planned);
        [existing, first.incoming_item.as_ref()]
            .into_iter()
            .flatten()
            .map(|id| Action::RevealPreviewSecret(id.clone()))
            .collect()
    }

    /// Deletes the item at the expand index (or the first one) of the
    /// selected keyring once its items are listed; fires once.
    fn _take_delete_item(&mut self, state: &AppState, filter: &str) -> Vec<Action> {
        let items = displayed_items(state, filter);
        let Some(item) = items.get(self.expand.unwrap_or(0)) else {
            return Vec::new();
        };
        self.dialog = None;
        self.expand = None;
        vec![Action::Send(Command::DeleteItem {
            item: item.id.clone(),
            backup_passphrase: None,
        })]
    }

    /// Actions due now (expand, reveal, dialog); each fires once when its data exists.
    pub fn take_actions(&mut self, state: &AppState, filter: &str) -> Vec<Action> {
        if self.dialog.as_deref() == Some(DIALOG_TRANSFER_PREVIEW) {
            return self._take_transfer_preview(state, filter);
        }
        if self.dialog.as_deref() == Some(DIALOG_DELETE_ITEM_NOW) {
            return self._take_delete_item(state, filter);
        }
        let mut out = Vec::new();
        let card = self.expand.and_then(|i| {
            displayed_items(state, filter)
                .get(i)
                .map(|item| item.id.clone())
        });
        if let Some(id) = card {
            self.expand = None;
            out.push(Action::SelectItem(id.clone()));
            if self.reveal {
                out.push(Action::Send(Command::RevealSecret(id)));
            }
        }
        let locked = state.collections.iter().find(|c| c.locked);
        let selected = state
            .selected
            .as_ref()
            .and_then(|id| state.collections.iter().find(|c| &c.id == id));
        let kind = match (self.dialog.as_deref(), locked, selected) {
            (Some("new-keyring"), _, _) => Some(DialogKind::create_collection()),
            (Some("unlock"), Some(c), _) => {
                let name = shown_name(&state.collections, c);
                Some(DialogKind::unlock(c.id.clone(), name))
            }
            (Some("export"), _, Some(c)) => {
                Some(export_dialog(c, shown_name(&state.collections, c)))
            }
            (Some("import-archive"), _, Some(c)) => {
                let label = shown_name(&state.collections, c);
                Some(DialogKind::import_archive(c, label))
            }
            _ => None,
        };
        if let Some(kind) = kind {
            self.dialog = None;
            out.push(Action::Open(kind));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::Event;
    use kring_core::model::ItemInfo;

    /// Private runtime dir of the isolated session.
    const RUN: &str = "/tmp/kring-dev.abc/run";
    /// Private bus address.
    const PRIVATE_BUS: &str = "unix:path=/tmp/dbus-XyZ,guid=0123";
    /// The user's real session bus.
    const REAL_BUS: &str = "unix:path=/run/user/1000/bus";

    /// Preset variables as a fake environment.
    fn vars(name: &str) -> Option<String> {
        match name {
            VAR_SELECT => Some("login".into()),
            VAR_EXPAND => Some("1".into()),
            VAR_REVEAL => Some("1".into()),
            VAR_DIALOG => Some("unlock".into()),
            VAR_AREA => Some("files".into()),
            VAR_FILE => Some("textual_two_items".into()),
            VAR_BACKUP => Some("1".into()),
            VAR_REMEMBER => Some("1".into()),
            _ => None,
        }
    }

    /// Inside the isolated session the variables are parsed.
    #[test]
    fn parsed_in_isolated_session() {
        let p = preset_from(Some(RUN), Some(RUN), Some(PRIVATE_BUS), vars);
        assert_eq!(
            p,
            DevPreset {
                select: Some("login".into()),
                expand: Some(1),
                reveal: true,
                dialog: Some("unlock".into()),
                area: Some("files".into()),
                file: Some("textual_two_items".into()),
                backup: Some(1),
                transfer_reveal: false,
                consolidate_follow: None,
                remember: true,
            }
        );
    }

    /// Mismatched or empty runtime dirs and the real bus give the empty preset.
    #[test]
    fn empty_outside_isolated_session() {
        let empty = DevPreset::default();
        let other = Some("/run/user/1000");
        assert_eq!(
            preset_from(Some(RUN), other, Some(PRIVATE_BUS), vars),
            empty
        );
        assert_eq!(
            preset_from(Some(""), Some(""), Some(PRIVATE_BUS), vars),
            empty
        );
        assert_eq!(preset_from(None, Some(RUN), Some(PRIVATE_BUS), vars), empty);
        assert_eq!(
            preset_from(Some(RUN), Some(RUN), Some(REAL_BUS), vars),
            empty
        );
        assert_eq!(preset_from(Some(RUN), Some(RUN), None, vars), empty);
    }

    /// Builds a textual file info.
    fn file(name: &str) -> kring_core::keyring_file::KeyringFileInfo {
        kring_core::keyring_file::KeyringFileInfo {
            path: format!("/k/{name}.keyring").into(),
            name: name.into(),
            format: kring_core::keyring_file::KeyringFormat::Textual,
            size: 1,
            modified: 0,
            display_name: None,
            item_count: Some(2),
            daemon_readable: Some(true),
            plaintext: true,
            error: None,
        }
    }

    /// The files area is entered once; the file is selected once it is listed,
    /// then the dialog opens; the card follows the displayed order.
    #[test]
    fn files_area_preset() {
        use kring_core::keyring_file::textual::OfflineItem;
        use kring_core::model::SecretValue;
        let mut p = DevPreset {
            area: Some("files".into()),
            file: Some("t".into()),
            dialog: Some("retire".into()),
            expand: Some(0),
            reveal: true,
            ..DevPreset::default()
        };
        assert_eq!(p.take_area(), Some(Area::Files));
        assert_eq!(p.take_area(), None);
        let mut s = AppState::default();
        assert!(p.take_file_actions(&s).is_empty());
        s.apply(Event::Files(vec![file("t")]));
        let actions = p.take_file_actions(&s);
        assert!(matches!(&actions[..], [Action::SelectFile(n)] if n == "t"));
        s.select_file("t".into());
        let actions = p.take_file_actions(&s);
        assert!(matches!(
            &actions[..],
            [Action::Open(DialogKind::RetireFile { .. })]
        ));
        assert!(p.take_file_actions(&s).is_empty());
        assert!(p.take_file_card(&s).is_none());
        let item = |label: &str| OfflineItem {
            label: label.into(),
            attributes: Default::default(),
            secret: SecretValue::from_text("s"),
            created: 0,
            modified: 0,
            secret_missing: false,
        };
        s.apply(Event::FileItems {
            name: "t".into(),
            items: vec![item("zeta"), item("alpha")],
            warnings: vec![],
        });
        assert_eq!(p.take_file_card(&s), Some((1, true)));
        assert!(p.take_file_card(&s).is_none());
        assert_eq!(DevPreset::default().take_area(), None);
    }

    /// The delete presets open the delete dialog, with the backup checked or
    /// not; a loaded keyring holding items always keeps its backup.
    #[test]
    fn delete_file_presets() {
        let live = CollectionInfo {
            id: CollectionId("/org/freedesktop/secrets/collection/t".into()),
            label: "T".into(),
            locked: false,
            item_count: 1,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        };
        let cases = [
            ("delete-file", false, true),
            ("delete-file-no-backup", false, false),
            ("delete-file", true, true),
            ("delete-file-no-backup", true, true),
        ];
        for (dialog, is_live, expected) in cases {
            let mut p = DevPreset {
                dialog: Some(dialog.into()),
                ..DevPreset::default()
            };
            let mut s = AppState::default();
            if is_live {
                s.apply(Event::Collections(vec![live.clone()]));
            }
            s.apply(Event::Files(vec![file("t")]));
            s.select_file("t".into());
            let actions = p.take_file_actions(&s);
            assert!(
                matches!(
                    &actions[..],
                    [Action::Open(DialogKind::DeleteFile { backup, spec, .. })]
                        if *backup == expected && spec.backup_optional == !is_live
                ),
                "{dialog} live={is_live}"
            );
        }
    }

    /// The backups area is entered; the backup is selected once listed, then
    /// the restore confirmation opens with every file.
    #[test]
    fn backups_area_preset() {
        use kring_core::backup::{BackupFile, BackupInfo};
        let mut p = DevPreset {
            area: Some("backups".into()),
            backup: Some(1),
            dialog: Some("restore".into()),
            ..DevPreset::default()
        };
        assert_eq!(p.take_area(), Some(Area::Backups));
        let mut view = BackupView::default();
        let mut s = AppState::default();
        let k = Path::new("/k");
        assert!(p.take_backup_actions(&s, &mut view, k).is_empty());
        let info = |dir: &str| BackupInfo {
            dir: dir.into(),
            reason: "delete-item".into(),
            created: String::new(),
            files: vec![BackupFile {
                original: "/x/a.keyring".into(),
                stored: "/s/a.keyring".into(),
                sha256: String::new(),
                encrypted: false,
            }],
            seq: 0,
            prune_warning: None,
            pruned: Vec::new(),
        };
        s.apply(Event::Backups(vec![info("/b/2"), info("/b/1")]));
        let actions = p.take_backup_actions(&s, &mut view, k);
        assert_eq!(view.selected.as_deref(), Some(Path::new("/b/1")));
        assert!(matches!(
            &actions[..],
            [Action::Open(DialogKind::RestoreBackup { destinations, .. })]
                if destinations == &["/k/a.keyring (new)"]
        ));
        assert!(p.take_backup_actions(&s, &mut view, k).is_empty());
    }

    /// The consolidate preset waits for an unlocked target, plans once with
    /// the orphan files, then reveals the first conflict of the preview.
    #[test]
    fn consolidate_preview_preset() {
        use crate::worker::{ConflictView, ConsolidationSummary, StepSummary};
        use kring_core::model::LOGIN_COLLECTION_PATH;
        use kring_core::transfer::plan::{Choice, TransferCounts};
        let mut p = DevPreset {
            area: Some(AREA_CONSOLIDATE.into()),
            dialog: Some(DIALOG_CONSOLIDATE_PREVIEW.into()),
            reveal: true,
            ..DevPreset::default()
        };
        assert_eq!(p.take_area(), Some(Area::Consolidate));
        let mut s = AppState::default();
        assert!(p.take_consolidate_actions(&s).is_empty(), "no keyrings yet");
        s.apply(Event::Collections(vec![CollectionInfo {
            id: CollectionId(LOGIN_COLLECTION_PATH.into()),
            label: "Login".into(),
            locked: false,
            item_count: 1,
            aliases: vec![],
            is_login: true,
            created: 0,
            modified: 0,
        }]));
        let actions = p.take_consolidate_actions(&s);
        assert!(matches!(
            &actions[..],
            [Action::Send(Command::PlanConsolidation { target, include_orphan_files: true })]
                if target.0 == LOGIN_COLLECTION_PATH
        ));
        assert!(p.take_consolidate_actions(&s).is_empty());
        let conflict = ConflictView {
            label_incoming: "a".into(),
            label_existing: "a".into(),
            modified_incoming: 0,
            modified_existing: 0,
            default_choice: Choice::KeepTarget,
            incoming_item: Some(ItemId("/c/w/1".into())),
            incoming_revealable: true,
            existing_item: Some(ItemId("planned:0".into())),
            existing_planned: true,
            offline_index: None,
        };
        s.apply(Event::ConsolidationPreview {
            plan_id: 1,
            summary: ConsolidationSummary {
                target: CollectionId(LOGIN_COLLECTION_PATH.into()),
                steps: vec![StepSummary {
                    source: CollectionId("/c/w".into()),
                    label: "w".into(),
                    counts: TransferCounts::default(),
                    conflicts: vec![conflict],
                }],
                delete_empty: vec![],
                skipped: vec![],
                locked_count: 0,
                set_default: false,
                conflict_count: 1,
                orphan_files: vec![],
                backup_needs_passphrase: false,
            },
        });
        let reveal = p.take_transfer_reveal(&s);
        assert!(matches!(
            &reveal[..],
            [Action::RevealPreviewSecret(id)] if id.0 == "/c/w/1"
        ));
    }

    /// `consolidate-now` applies the preview once it arrived (plain
    /// keyrings only: no passphrase); `consolidate-apply` opens the dialog.
    #[test]
    fn consolidate_apply_follows_preview() {
        use crate::worker::ConsolidationSummary;
        use kring_core::model::LOGIN_COLLECTION_PATH;
        let login = CollectionId(LOGIN_COLLECTION_PATH.into());
        let collections = vec![CollectionInfo {
            id: login.clone(),
            label: "Login".into(),
            locked: false,
            item_count: 1,
            aliases: vec![],
            is_login: true,
            created: 0,
            modified: 0,
        }];
        let summary = ConsolidationSummary {
            target: login,
            steps: vec![],
            delete_empty: vec![],
            skipped: vec![],
            locked_count: 0,
            set_default: false,
            conflict_count: 0,
            orphan_files: vec!["o".into()],
            backup_needs_passphrase: false,
        };
        for (dialog, opens) in [
            (DIALOG_CONSOLIDATE_NOW, false),
            (DIALOG_CONSOLIDATE_APPLY, true),
        ] {
            let mut p = DevPreset {
                dialog: Some(dialog.into()),
                ..DevPreset::default()
            };
            let mut s = AppState::default();
            s.apply(Event::Collections(collections.clone()));
            let plan = p.take_consolidate_actions(&s);
            assert!(matches!(
                &plan[..],
                [Action::Send(Command::PlanConsolidation { .. })]
            ));
            assert!(
                p.take_consolidate_actions(&s).is_empty(),
                "waits for the preview"
            );
            s.apply(Event::ConsolidationPreview {
                plan_id: 7,
                summary: summary.clone(),
            });
            let next = p.take_consolidate_actions(&s);
            if opens {
                assert!(matches!(
                    &next[..],
                    [Action::Open(DialogKind::ConsolidatePassphrases {
                        plan_id: 7,
                        ask_orphan_files: true,
                        ..
                    })]
                ));
            } else {
                assert!(matches!(
                    &next[..],
                    [Action::Send(Command::ApplyConsolidation {
                        plan_id: 7,
                        backup_passphrase: None,
                        orphan_files_passphrase: Some(_),
                        ..
                    })]
                ));
            }
            assert!(p.take_consolidate_actions(&s).is_empty());
        }
    }

    /// The expand index follows the displayed (label-sorted) order, once.
    #[test]
    fn expand_uses_displayed_order() {
        let coll = CollectionId("/c/a".into());
        let mut s = AppState::default();
        s.apply(Event::Collections(vec![CollectionInfo {
            id: coll.clone(),
            label: "a".into(),
            locked: false,
            item_count: 2,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        }]));
        s.select_collection(coll.clone());
        let item = |id: &str, label: &str| ItemInfo {
            id: ItemId(id.into()),
            collection: coll.clone(),
            label: label.into(),
            attributes: Default::default(),
            locked: false,
            created: 0,
            modified: 0,
        };
        s.apply(Event::Items(
            coll.clone(),
            vec![item("/i/z", "Zeta"), item("/i/a", "alpha")],
        ));
        let mut p = DevPreset {
            expand: Some(1),
            ..DevPreset::default()
        };
        let actions = p.take_actions(&s, "");
        assert!(matches!(&actions[..], [Action::SelectItem(id)] if id.0 == "/i/z"));
        assert!(p.take_actions(&s, "").is_empty());

        // `delete-item-now` deletes the displayed item at the expand index, once.
        let mut p = DevPreset {
            expand: Some(1),
            dialog: Some(DIALOG_DELETE_ITEM_NOW.into()),
            ..DevPreset::default()
        };
        let actions = p.take_actions(&s, "");
        assert!(matches!(
            &actions[..],
            [Action::Send(Command::DeleteItem { item, backup_passphrase: None })] if item.0 == "/i/z"
        ));
        assert!(p.take_actions(&s, "").is_empty());
    }

    /// The remembered dev passphrase is handed out once.
    #[test]
    fn remember_taken_once() {
        let mut p = DevPreset {
            remember: true,
            ..DevPreset::default()
        };
        assert_eq!(p.take_remembered().unwrap().as_text(), Some(DEV_PASSPHRASE));
        assert!(p.take_remembered().is_none());
    }

    /// The transfer preset waits for the items of a pair keyring, checks them
    /// and plans a copy into the other unlocked one; the reveal follows the preview.
    #[test]
    fn transfer_preview_preset() {
        use crate::worker::ConflictView;
        use kring_core::transfer::plan::{Choice, TransferCounts};
        let col = |path: &str, label: &str, locked: bool| CollectionInfo {
            id: CollectionId(path.into()),
            label: label.into(),
            locked,
            item_count: 1,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        };
        let login = CollectionId("/c/login".into());
        let mut s = AppState::default();
        s.apply(Event::Collections(vec![
            col("/c/login", "Login", false),
            col("/c/work", "Work", false),
            col("/c/d1", "Default_1", false),
        ]));
        s.select_collection(login.clone());
        let mut p = DevPreset {
            dialog: Some(DIALOG_TRANSFER_PREVIEW.into()),
            reveal: true,
            ..DevPreset::default()
        };
        assert!(p.take_actions(&s, "").is_empty(), "items not loaded yet");
        let item = ItemInfo {
            id: ItemId("/c/login/1".into()),
            collection: login.clone(),
            label: "a".into(),
            attributes: Default::default(),
            locked: false,
            created: 0,
            modified: 0,
        };
        s.apply(Event::Items(login, vec![item]));
        let actions = p.take_actions(&s, "");
        assert!(matches!(
            &actions[..],
            [
                Action::ToggleSelect(id),
                Action::Send(Command::PlanTransfer { target, mode: TransferMode::Copy, .. }),
            ] if id.0 == "/c/login/1" && target.0 == "/c/work"
        ));
        assert!(p.take_actions(&s, "").is_empty());
        assert!(p.take_transfer_reveal(&s).is_empty(), "no preview yet");
        s.apply(Event::TransferPreview {
            plan_id: 1,
            target: CollectionId("/c/work".into()),
            mode: TransferMode::Copy,
            counts: TransferCounts::default(),
            conflicts: vec![ConflictView {
                label_incoming: "a".into(),
                label_existing: "a".into(),
                modified_incoming: 0,
                modified_existing: 0,
                default_choice: Choice::KeepTarget,
                incoming_item: Some(ItemId("/c/login/1".into())),
                incoming_revealable: true,
                existing_item: Some(ItemId("/c/work/1".into())),
                existing_planned: false,
                offline_index: None,
            }],
        });
        let reveal = p.take_transfer_reveal(&s);
        assert_eq!(reveal.len(), 2);
        assert!(p.take_transfer_reveal(&s).is_empty());
    }
}
