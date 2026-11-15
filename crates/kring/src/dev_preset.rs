//! Screenshot presets for the isolated dev session (debug builds only).
//!
//! The preset can select a keyring, expand an item, reveal its secret and
//! open a dialog without clicks. It is honoured only when the environment
//! passes `kring_core::dev_guard::violation_from` (private runtime dir and a
//! bus that is not the real user bus), so a leftover export in a normal
//! session cannot reveal a secret from the real keyring.

use std::path::Path;

use kring_core::dev_guard::{IT_RUNTIME_VAR, violation_from};
use kring_core::model::CollectionId;

use crate::app_state::AppState;
use crate::views::backups::{BackupView, path_exists, restore_dialog};
use crate::views::collection::{display_name, export_dialog};
use crate::views::dialogs::DialogKind;
use crate::views::file_detail::retire_dialog;
use crate::views::file_items::displayed_file_items;
use crate::views::item_list::displayed_items;
use crate::views::{Action, Area};
use crate::worker::Command;

/// Keyring (display name) to select first.
const VAR_SELECT: &str = "KRING_DEV_SELECT";
/// Index of the card (in displayed order) to expand.
const VAR_EXPAND: &str = "KRING_DEV_EXPAND";
/// Any non-empty value reveals the expanded item's secret.
const VAR_REVEAL: &str = "KRING_DEV_REVEAL";
/// Dialog to open: `new-keyring`, `unlock`, `export` or `import-archive`; in
/// the files area `import`, `retire` or `open` (password of a binary file);
/// in the backups area `restore` (confirmation) or `restore-now` (restores
/// every file of the selected backup without a passphrase).
const VAR_DIALOG: &str = "KRING_DEV_DIALOG";
/// Area to show first: `files` or `backups`.
const VAR_AREA: &str = "KRING_DEV_AREA";
/// Keyring file (name without `.keyring`) to select in the files area.
const VAR_FILE: &str = "KRING_DEV_FILE";
/// Index (newest first) of the backup to select in the backups area.
const VAR_BACKUP: &str = "KRING_DEV_BACKUP";
/// Value of [`VAR_AREA`] selecting the Offline files area.
const AREA_FILES: &str = "files";
/// Value of [`VAR_AREA`] selecting the Backups area.
const AREA_BACKUPS: &str = "backups";

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

    /// Area to switch to at start; returned once.
    pub fn take_area(&mut self) -> Option<Area> {
        let area = self.area.take()?;
        match area.as_str() {
            AREA_FILES => Some(Area::Files),
            AREA_BACKUPS => Some(Area::Backups),
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

    /// Actions due now (expand, reveal, dialog); each fires once when its data exists.
    pub fn take_actions(&mut self, state: &AppState, filter: &str) -> Vec<Action> {
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
            (Some("unlock"), Some(c), _) => Some(DialogKind::unlock(c.id.clone(), display_name(c))),
            (Some("export"), _, Some(c)) => Some(export_dialog(c)),
            (Some("import-archive"), _, Some(c)) => Some(DialogKind::import_archive(c)),
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
    use kring_core::model::{CollectionInfo, ItemId, ItemInfo};

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
    }
}
