//! Backups area: list of the backups (newest first), the files of the
//! selected one with checkboxes, `Restore selected` and the restart hint.
//!
//! Restores go through a confirmation dialog listing every file that will be
//! overwritten. Sizes are read from disk only when the list changes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use eframe::egui::{self, Align, Layout, RichText, Sense, Ui, UiBuilder};
use kring_core::backup::{BackupFile, BackupInfo, RESTART_HINT};
use kring_core::keyring_file::KeyringFileInfo;

use crate::app_state::AppState;
use crate::local_time;
use crate::ui::glyphs::Ico;
use crate::ui::theme;
use crate::ui::widgets::{
    accent_card, card, chip, danger_button, glyph_tile, heading, ico_button, muted, muted_text,
    semibold,
};
use crate::views::Action;
use crate::views::dialogs::{DialogKind, RestorePassphrase};
use crate::views::files_list::format_size;
use crate::views::sidebar::row_background;
use crate::worker::Command;

/// Height of a backup row.
const ROW_HEIGHT: f32 = 52.0;
/// Horizontal padding inside a row.
const ROW_PADDING: f32 = 12.0;
/// Chip of age-encrypted backup files.
const CHIP_ENCRYPTED: &str = "encrypted";
/// Suffix of restore destinations that do not exist yet.
const NEW_SUFFIX: &str = " (new)";
/// Tooltip of `Restore selected` with nothing selected.
const MSG_NOTHING_SELECTED: &str = "Select at least one file";
/// Explanation under the backup header.
const MSG_RESTORE_NOTE: &str = "Restoring overwrites the keyring files with these copies. The \
     current versions are backed up first. gnome-keyring loads them after a restart.";

/// Returns a readable reason, e.g. `delete-item` -> `Before deleting an item`.
pub fn humanize_reason(reason: &str) -> String {
    let known = match reason {
        "delete-item" => Some("Before deleting an item"),
        "delete-collection" => Some("Before deleting a keyring"),
        "retire-plaintext" => Some("Before retiring a plaintext file"),
        "pre-restore" => Some("Before a restore"),
        _ => None,
    };
    if let Some(text) = known {
        return text.to_string();
    }
    let spaced = reason.replace('-', " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "Backup".to_string(),
    }
}

/// Returns the file name of a backed-up file (`<name>.keyring` or `default`).
pub fn file_name(file: &BackupFile) -> String {
    file.original
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.original.display().to_string())
}

/// Returns the total size on disk of the stored copies (missing files count 0).
pub fn backup_size(info: &BackupInfo) -> u64 {
    info.files
        .iter()
        .filter_map(|f| std::fs::metadata(&f.stored).ok())
        .map(|m| m.len())
        .sum()
}

/// Returns the muted summary of a backup, e.g. `2 files - 1.2 KB`.
pub fn backup_summary(info: &BackupInfo, size: u64) -> String {
    let n = info.files.len();
    let noun = if n == 1 { "file" } else { "files" };
    format!("{n} {noun} - {}", format_size(size))
}

/// Returns where a restore writes `file`: `<keyrings_dir>/<file name>`.
pub fn restore_destination(file: &BackupFile, keyrings_dir: &Path) -> PathBuf {
    keyrings_dir.join(file_name(file))
}

/// Decides the passphrase of a restore of `selected`: encrypted copies need
/// theirs; a plaintext destination (per the last file scan) needs a new one
/// for its pre-restore backup.
pub fn restore_passphrase(
    selected: &[&BackupFile],
    files: &[KeyringFileInfo],
    keyrings_dir: &Path,
) -> RestorePassphrase {
    if selected.iter().any(|f| f.encrypted) {
        return RestorePassphrase::Existing;
    }
    let plaintext_dest = selected.iter().any(|f| {
        let dest = restore_destination(f, keyrings_dir);
        files.iter().any(|k| k.path == dest && k.plaintext)
    });
    if plaintext_dest {
        return RestorePassphrase::New;
    }
    RestorePassphrase::NotNeeded
}

/// Returns true when `path` exists on disk (symlinks are not followed).
pub fn path_exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Builds the restore confirmation of the `selected` files of `info`;
/// destinations for which `exists` is false are marked `(new)`.
pub fn restore_dialog(
    info: &BackupInfo,
    selected: &[&BackupFile],
    files: &[KeyringFileInfo],
    keyrings_dir: &Path,
    exists: impl Fn(&Path) -> bool,
) -> DialogKind {
    let destinations = selected
        .iter()
        .map(|f| {
            let dest = restore_destination(f, keyrings_dir);
            let shown = dest.display().to_string();
            if exists(&dest) {
                return shown;
            }
            format!("{shown}{NEW_SUFFIX}")
        })
        .collect();
    DialogKind::restore_backup(
        info.dir.clone(),
        selected.iter().map(|f| f.original.clone()).collect(),
        destinations,
        restore_passphrase(selected, files, keyrings_dir),
    )
}

/// Selection of the Backups area: selected backup, unchecked files and the
/// cached sizes of the listed backups.
#[derive(Debug, Default)]
pub struct BackupView {
    /// Directory of the selected backup.
    pub selected: Option<PathBuf>,
    /// Original paths of the files of the selected backup left out of a restore.
    unchecked: BTreeSet<PathBuf>,
    /// Backup directories the sizes were computed for.
    listed: Vec<PathBuf>,
    /// Size of each listed backup, same order as `listed`.
    sizes: Vec<u64>,
}

impl BackupView {
    /// Recomputes the sizes when the list changed and drops a vanished selection.
    pub fn sync(&mut self, state: &AppState) {
        let dirs: Vec<PathBuf> = state.backups.iter().map(|b| b.dir.clone()).collect();
        if dirs == self.listed {
            return;
        }
        self.sizes = state.backups.iter().map(backup_size).collect();
        self.listed = dirs;
        let gone = self
            .selected
            .as_ref()
            .is_some_and(|s| !self.listed.contains(s));
        if gone {
            self.select(None);
        }
    }

    /// Selects a backup (or none) with every file checked.
    pub fn select(&mut self, dir: Option<PathBuf>) {
        self.selected = dir;
        self.unchecked.clear();
    }

    /// Checks or unchecks the file whose original path is `original`.
    pub fn toggle(&mut self, original: &Path) {
        if !self.unchecked.remove(original) {
            self.unchecked.insert(original.to_path_buf());
        }
    }

    /// Returns true when the file is part of the restore.
    pub fn is_checked(&self, original: &Path) -> bool {
        !self.unchecked.contains(original)
    }

    /// Returns the checked files of `info`, in manifest order.
    pub fn checked<'a>(&self, info: &'a BackupInfo) -> Vec<&'a BackupFile> {
        info.files
            .iter()
            .filter(|f| self.is_checked(&f.original))
            .collect()
    }

    /// Returns the cached size of the backup in `dir`.
    pub fn size_of(&self, dir: &Path) -> u64 {
        self.listed
            .iter()
            .position(|d| d == dir)
            .and_then(|i| self.sizes.get(i).copied())
            .unwrap_or_default()
    }
}

/// Renders one backup row; returns true when clicked.
fn _row(ui: &mut Ui, info: &BackupInfo, size: u64, selected: bool) -> bool {
    let rect_size = egui::vec2(ui.available_width(), ROW_HEIGHT);
    let (rect, resp) = ui.allocate_exact_size(rect_size, Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    row_background(ui, rect, selected, resp.hovered());
    let inner = rect.shrink2(egui::vec2(ROW_PADDING, 6.0));
    let builder = UiBuilder::new()
        .max_rect(inner)
        .layout(Layout::top_down(Align::Min));
    ui.scope_builder(builder, |ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        let reason = RichText::new(humanize_reason(&info.reason))
            .family(theme::medium())
            .size(14.0)
            .color(theme::TEXT);
        ui.add(egui::Label::new(reason).truncate().selectable(false));
        let when = local_time::format_rfc3339(&info.created, local_time::offset());
        let sub = format!("{when} - {}", backup_summary(info, size));
        ui.add(
            egui::Label::new(muted_text(sub))
                .truncate()
                .selectable(false),
        );
    });
    resp.clicked()
}

/// Renders the backups list panel and returns the requested action.
pub fn list(ui: &mut Ui, state: &AppState, view: &mut BackupView) -> Option<Action> {
    view.sync(state);
    let mut action = None;
    ui.horizontal(|ui| {
        ui.label(semibold("Backups", 18.0));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ico_button(ui, Ico::Refresh, "Reload the backups", None, false) {
                action = Some(Action::Send(Command::ListBackups));
            }
        });
    });
    ui.add_space(2.0);
    let n = state.backups.len();
    let noun = if n == 1 { "backup" } else { "backups" };
    muted(
        ui,
        &format!("{n} {noun}, newest first - the last 20 are kept"),
    );
    ui.add_space(2.0);
    egui::ScrollArea::vertical()
        .id_salt("kring-backups")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for info in &state.backups {
                let selected = view.selected.as_ref() == Some(&info.dir);
                if _row(ui, info, view.size_of(&info.dir), selected) && !selected {
                    view.select(Some(info.dir.clone()));
                }
            }
        });
    action
}

/// Renders the restart hint after a restore, with a copy button.
fn _restore_done(ui: &mut Ui, state: &AppState) {
    let Some(report) = &state.last_restore else {
        return;
    };
    accent_card(ui, theme::OK, |ui| {
        let n = report.restored.len();
        let noun = if n == 1 { "file" } else { "files" };
        let text = format!("Restored {n} {noun}. Restart gnome-keyring to load them:");
        ui.label(RichText::new(text).color(theme::OK).size(12.5));
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(RESTART_HINT)
                    .monospace()
                    .size(12.5)
                    .color(theme::TEXT),
            );
            if ico_button(ui, Ico::Copy, "Copy the command", None, false) {
                ui.ctx().copy_text(RESTART_HINT.to_string());
            }
        });
        if let Some(pre) = &report.pre_restore_backup {
            let text = format!("Previous versions saved in {}", pre.dir.display());
            ui.label(muted_text(text));
        }
    });
    ui.add_space(8.0);
}

/// Renders one file of the selected backup with its checkbox.
fn _file_row(ui: &mut Ui, file: &BackupFile, view: &mut BackupView) {
    ui.horizontal(|ui| {
        let mut checked = view.is_checked(&file.original);
        if ui.checkbox(&mut checked, "").changed() {
            view.toggle(&file.original);
        }
        let name = RichText::new(file_name(file))
            .family(theme::medium())
            .size(14.0)
            .color(theme::TEXT);
        ui.add(egui::Label::new(name).selectable(false));
        if file.encrypted {
            chip(ui, CHIP_ENCRYPTED, theme::SECONDARY);
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let path = RichText::new(file.original.display().to_string())
                .monospace()
                .size(12.0)
                .color(theme::MUTED);
            ui.add(egui::Label::new(path).truncate());
        });
    });
}

/// Renders the empty state shown when no backup is selected.
fn _empty_state(ui: &mut Ui, state: &AppState) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        glyph_tile(ui, Ico::Archive, 64.0);
        ui.add_space(8.0);
        let title = if state.backups.is_empty() {
            "No backups yet"
        } else {
            "Select a backup"
        };
        heading(ui, title);
        muted(
            ui,
            "kring backs up the keyring files before every delete, retire and restore.",
        );
        ui.add_space(12.0);
        ui.label(
            RichText::new(kring_core::paths::backups_dir().display().to_string())
                .monospace()
                .size(12.0)
                .color(theme::MUTED),
        );
    });
}

/// Renders the selected backup and returns the requested action.
pub fn detail(
    ui: &mut Ui,
    state: &AppState,
    view: &mut BackupView,
    keyrings_dir: &Path,
) -> Option<Action> {
    view.sync(state);
    _restore_done(ui, state);
    let Some(info) = view
        .selected
        .as_ref()
        .and_then(|dir| state.backups.iter().find(|b| &b.dir == dir))
    else {
        _empty_state(ui, state);
        return None;
    };
    let mut action = None;
    let checked = view.checked(info);
    ui.horizontal(|ui| {
        ui.add(egui::Label::new(semibold(humanize_reason(&info.reason), 22.0)).truncate());
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let blocked = checked.is_empty().then_some(MSG_NOTHING_SELECTED);
            if danger_button(ui, "Restore selected", blocked) {
                let kind = restore_dialog(info, &checked, &state.files, keyrings_dir, path_exists);
                action = Some(Action::Open(kind));
            }
        });
    });
    ui.label(
        RichText::new(info.dir.display().to_string())
            .monospace()
            .size(12.0)
            .color(theme::MUTED),
    );
    let when = local_time::format_rfc3339(&info.created, local_time::offset());
    let size = view.size_of(&info.dir);
    muted(
        ui,
        &format!("Created {when} - {}", backup_summary(info, size)),
    );
    ui.add_space(4.0);
    accent_card(ui, theme::SECONDARY, |ui| {
        ui.label(
            RichText::new(MSG_RESTORE_NOTE)
                .color(theme::MUTED)
                .size(12.5),
        );
    });
    ui.add_space(10.0);
    card(ui, |ui| {
        ui.spacing_mut().item_spacing.y = 6.0;
        for file in &info.files {
            _file_row(ui, file, view);
        }
    });
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::Event;
    use kring_core::keyring_file::KeyringFormat;

    /// Builds a backup file entry.
    fn bfile(original: &str, stored: &Path, encrypted: bool) -> BackupFile {
        BackupFile {
            original: original.into(),
            stored: stored.to_path_buf(),
            sha256: String::new(),
            encrypted,
        }
    }

    /// Builds a backup of `files` in `dir`.
    fn backup(dir: &str, files: Vec<BackupFile>) -> BackupInfo {
        BackupInfo {
            dir: dir.into(),
            reason: "delete-item".into(),
            created: "2026-11-15T10:00:00Z".into(),
            files,
            seq: 1,
            prune_warning: None,
        }
    }

    /// Builds a scanned keyring file at `path`.
    fn scanned(path: &str, plaintext: bool) -> KeyringFileInfo {
        KeyringFileInfo {
            path: path.into(),
            name: "x".into(),
            format: if plaintext {
                KeyringFormat::Textual
            } else {
                KeyringFormat::BinaryV0
            },
            size: 0,
            modified: 0,
            display_name: None,
            item_count: None,
            daemon_readable: None,
            plaintext,
            error: None,
        }
    }

    /// Known reasons are phrased; unknown ones are spaced and capitalised.
    #[test]
    fn reasons_humanized() {
        assert_eq!(humanize_reason("delete-item"), "Before deleting an item");
        assert_eq!(
            humanize_reason("delete-collection"),
            "Before deleting a keyring"
        );
        assert_eq!(
            humanize_reason("retire-plaintext"),
            "Before retiring a plaintext file"
        );
        assert_eq!(humanize_reason("pre-restore"), "Before a restore");
        assert_eq!(humanize_reason("manual-copy"), "Manual copy");
        assert_eq!(humanize_reason(""), "Backup");
    }

    /// Sizes add up the stored copies; the summary counts the files.
    #[test]
    fn size_and_summary() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a.keyring");
        let b = tmp.path().join("b.keyring.age");
        std::fs::write(&a, vec![0u8; 1000]).unwrap();
        std::fs::write(&b, vec![0u8; 1048]).unwrap();
        let info = backup(
            "/b/1",
            vec![
                bfile("/k/a.keyring", &a, false),
                bfile("/k/b.keyring", &b, true),
                bfile("/k/c.keyring", &tmp.path().join("missing"), false),
            ],
        );
        assert_eq!(backup_size(&info), 2048);
        assert_eq!(backup_summary(&info, 2048), "3 files - 2.0 KB");
        let one = backup("/b/2", vec![bfile("/k/a.keyring", &a, false)]);
        assert_eq!(backup_summary(&one, 10), "1 file - 10 B");
    }

    /// Destinations are the file names inside the keyrings dir.
    #[test]
    fn destinations_in_keyrings_dir() {
        let f = bfile("/old/home/keyrings/login.keyring", Path::new("/s"), false);
        assert_eq!(file_name(&f), "login.keyring");
        assert_eq!(
            restore_destination(&f, Path::new("/k")),
            PathBuf::from("/k/login.keyring")
        );
    }

    /// Encrypted copies need their passphrase; plaintext destinations a new one.
    #[test]
    fn passphrase_rules() {
        let s = Path::new("/s");
        let k = Path::new("/k");
        let bin = bfile("/x/a.keyring", s, false);
        let enc = bfile("/x/p.keyring", s, true);
        let scan = [
            scanned("/k/a.keyring", false),
            scanned("/k/t.keyring", true),
        ];
        assert_eq!(
            restore_passphrase(&[&bin], &scan, k),
            RestorePassphrase::NotNeeded
        );
        assert_eq!(
            restore_passphrase(&[&bin, &enc], &scan, k),
            RestorePassphrase::Existing
        );
        let over_plain = bfile("/x/t.keyring", s, false);
        assert_eq!(
            restore_passphrase(&[&over_plain], &scan, k),
            RestorePassphrase::New
        );
    }

    /// The dialog lists the checked files and their destinations.
    #[test]
    fn restore_dialog_lists_destinations() {
        let s = Path::new("/s");
        let info = backup(
            "/b/1",
            vec![
                bfile("/x/a.keyring", s, false),
                bfile("/x/p.keyring", s, true),
            ],
        );
        let mut view = BackupView::default();
        view.select(Some("/b/1".into()));
        view.toggle(Path::new("/x/a.keyring"));
        let checked = view.checked(&info);
        assert_eq!(checked.len(), 1);
        match restore_dialog(&info, &checked, &[], Path::new("/k"), |_| true) {
            DialogKind::RestoreBackup {
                dir,
                files,
                destinations,
                mode,
                ..
            } => {
                assert_eq!(dir, PathBuf::from("/b/1"));
                assert_eq!(files, [PathBuf::from("/x/p.keyring")]);
                assert_eq!(destinations, ["/k/p.keyring"]);
                assert_eq!(mode, RestorePassphrase::Existing);
            }
            _ => panic!("expected RestoreBackup"),
        }
    }

    /// Destinations that do not exist yet are marked new.
    #[test]
    fn restore_dialog_marks_new_destinations() {
        let s = Path::new("/s");
        let info = backup(
            "/b/1",
            vec![
                bfile("/x/a.keyring", s, false),
                bfile("/x/b.keyring", s, false),
            ],
        );
        let checked: Vec<&BackupFile> = info.files.iter().collect();
        let exists = |p: &Path| p == Path::new("/k/a.keyring");
        match restore_dialog(&info, &checked, &[], Path::new("/k"), exists) {
            DialogKind::RestoreBackup { destinations, .. } => {
                assert_eq!(destinations, ["/k/a.keyring", "/k/b.keyring (new)"]);
            }
            _ => panic!("expected RestoreBackup"),
        }
    }

    /// Every file starts checked; a new selection or a vanished backup resets it.
    #[test]
    fn view_selection_and_sync() {
        let s = Path::new("/s");
        let mut state = AppState::default();
        state.apply(Event::Backups(vec![
            backup("/b/2", vec![bfile("/x/a.keyring", s, false)]),
            backup("/b/1", vec![bfile("/x/a.keyring", s, false)]),
        ]));
        let mut view = BackupView::default();
        view.sync(&state);
        view.select(Some("/b/2".into()));
        assert!(view.is_checked(Path::new("/x/a.keyring")));
        view.toggle(Path::new("/x/a.keyring"));
        assert!(!view.is_checked(Path::new("/x/a.keyring")));
        view.select(Some("/b/1".into()));
        assert!(view.is_checked(Path::new("/x/a.keyring")));
        state.apply(Event::Backups(vec![backup("/b/2", vec![])]));
        view.sync(&state);
        assert!(view.selected.is_none());
        assert_eq!(view.size_of(Path::new("/b/2")), 0);
    }
}
