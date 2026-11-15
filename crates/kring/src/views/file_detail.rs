//! The selected keyring file: header, notes, actions and its items.

use eframe::egui::{self, RichText};
use kring_core::keyring_file::textual::{ParseWarning, WarningKind};
use kring_core::keyring_file::{KeyringFileInfo, KeyringFormat, RetireMode, retire_mode};
use kring_core::model::{CollectionId, CollectionInfo};

use crate::app_state::AppState;
use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;
use crate::ui::widgets::{
    accent_card, danger_button, glyph_tile, heading, muted, note, primary_button, semibold,
};
use crate::views::collection::{collection_key, format_date};
use crate::views::dialogs::{DeleteSpec, DialogKind};
use crate::views::file_items::{self, FileView};
use crate::views::files_list::{chips, format_size};
use crate::views::{Action, Gates, MSG_NO_PROVIDER};
use crate::worker::Command;

/// Plaintext warning of textual files.
pub const MSG_PLAINTEXT: &str = "Secrets in this file are stored unencrypted on disk";
/// Tooltip of Import when no keyring is unlocked.
const MSG_NO_TARGET: &str = "Unlock a keyring first";
/// Tooltip of Import on a file that is not a keyring.
const MSG_NOT_KEYRING: &str = "Not a keyring file";
/// Tooltip of Import on a file without items.
const MSG_NOTHING_TO_IMPORT: &str = "No items to import";
/// Passphrase note of the backup of a plaintext file before deleting it.
const MSG_DELETE_PLAINTEXT: &str =
    "This file is not encrypted on disk: its backup is encrypted, choose a passphrase";
/// Passphrase note of the backup of all keyrings before deleting a loaded one.
const MSG_DELETE_LIVE_PLAINTEXT: &str =
    "The backup contains plaintext keyrings: it is encrypted, choose a passphrase";
/// Body of the card of a binary file not opened yet.
const MSG_ENCRYPTED: &str = "Encrypted keyring file. Enter its password to see the items.";

/// Returns the live collection (served by the daemon) of a file, if any.
pub fn live_collection<'a>(
    info: &KeyringFileInfo,
    collections: &'a [CollectionInfo],
) -> Option<&'a CollectionInfo> {
    match retire_mode(info, collections) {
        RetireMode::DeleteLiveCollection(id) => collections.iter().find(|c| c.id == id),
        RetireMode::DeleteFile => None,
    }
}

/// Returns true for a textual file without items that the daemon does not serve.
pub fn is_empty_orphan(info: &KeyringFileInfo, live: bool) -> bool {
    !live && info.format == KeyringFormat::Textual && info.item_count == Some(0)
}

/// Returns the muted subline, e.g. `585 B - modified 2026-11-15 - 2 items`.
pub fn file_subline(info: &KeyringFileInfo) -> String {
    let mut text = format!(
        "{} - modified {}",
        format_size(info.size),
        format_date(info.modified)
    );
    if let Some(n) = info.item_count {
        let noun = if n == 1 { "item" } else { "items" };
        text.push_str(&format!(" - {n} {noun}"));
    }
    text
}

/// Returns how many lines were joined to recover multi-line values.
pub fn joined_lines(warnings: &[ParseWarning]) -> usize {
    warnings
        .iter()
        .filter(|w| w.kind == WarningKind::ContinuationLine)
        .count()
}

/// Returns the error note of a file gnome-keyring cannot read.
pub fn unreadable_note(info: &KeyringFileInfo) -> Option<String> {
    if info.daemon_readable != Some(false) {
        return None;
    }
    let (what, them) = match info.item_count.unwrap_or_default() {
        1 => ("this secret".to_string(), "it"),
        n => (format!("these {n} secrets"), "them"),
    };
    Some(format!(
        "gnome-keyring cannot read this file, so apps cannot see {what}. \
         Import {them} into a keyring to recover {them}."
    ))
}

/// Returns the default import target: `login` when unlocked, else the first unlocked keyring.
pub fn default_import_target(collections: &[CollectionInfo]) -> Option<CollectionId> {
    let unlocked = || collections.iter().filter(|c| !c.locked);
    unlocked()
        .find(|c| c.is_login)
        .or_else(|| unlocked().next())
        .map(|c| c.id.clone())
}

/// Returns why Import is disabled for `info`, or `None` when allowed.
pub fn import_blocked(state: &AppState, info: &KeyringFileInfo) -> Option<&'static str> {
    if state.provider.is_none() {
        return Some(MSG_NO_PROVIDER);
    }
    if info.format == KeyringFormat::Unknown {
        return Some(MSG_NOT_KEYRING);
    }
    if info.item_count == Some(0) {
        return Some(MSG_NOTHING_TO_IMPORT);
    }
    if default_import_target(&state.collections).is_none() {
        return Some(MSG_NO_TARGET);
    }
    None
}

/// Returns the body lines of the retire confirmation for `mode`.
pub fn retire_dialog_text(mode: &RetireMode, info: &KeyringFileInfo) -> Vec<String> {
    let mut lines = match mode {
        RetireMode::DeleteFile => vec![format!(
            "\"{}.keyring\" is backed up, encrypted with the passphrase below, then \
             deleted from disk.",
            info.name
        )],
        RetireMode::DeleteLiveCollection(_) => {
            let label = info.display_name.as_deref().unwrap_or(&info.name);
            vec![
                format!(
                    "gnome-keyring has this file loaded: this will delete the live keyring \
                     '{label}' with backup."
                ),
                "The backup is encrypted with the passphrase below.".to_string(),
            ]
        }
    };
    if let Some(n) = info.item_count.filter(|n| *n > 0) {
        let noun = if n == 1 { "item" } else { "items" };
        lines.push(format!(
            "It holds {n} {noun} in plaintext. Import them into a keyring first if you \
             still need them."
        ));
    }
    lines
}

/// Returns the command to send when file `name` is selected: textual files are read right away.
pub fn select_command(state: &AppState, name: &str) -> Option<Command> {
    let info = state.files.iter().find(|f| f.name == name)?;
    (info.format == KeyringFormat::Textual).then(|| Command::OpenFile {
        name: name.to_string(),
        password: None,
    })
}

/// Returns the retire dialog of `info`, computing the mode from the live collections.
pub fn retire_dialog(state: &AppState, info: &KeyringFileInfo) -> DialogKind {
    let mode = retire_mode(info, &state.collections);
    DialogKind::retire_file(info.name.clone(), retire_dialog_text(&mode, info))
}

/// Returns why Delete is disabled: a live file is deleted through the
/// daemon, so the provider must allow writes (Plan 1 gate).
pub fn delete_blocked(live: bool, gates: Gates) -> Option<&'static str> {
    if gates.busy.is_some() || !live {
        return gates.busy;
    }
    gates.write
}

/// Returns ` (label "<label>")`, or nothing for a blank label.
fn _label_part(c: &CollectionInfo) -> String {
    if c.label.trim().is_empty() {
        return String::new();
    }
    format!(" (label \"{}\")", c.label)
}

/// Returns the live note of a file, e.g.
/// `gnome-keyring has this file loaded as the keyring Default_10 (label "Default")`.
pub fn live_note(c: &CollectionInfo) -> String {
    format!(
        "gnome-keyring has this file loaded as the keyring {}{}",
        collection_key(&c.id),
        _label_part(c)
    )
}

/// Returns what the delete dialog of `info` shows and allows.
///
/// A file the daemon does not serve is deleted from disk, the backup
/// optional. A live one is deleted through the daemon after a backup of all
/// keyrings (needing a passphrase when any listed file is plaintext); the
/// backup may be skipped only when the keyring holds no items.
pub fn delete_spec(state: &AppState, info: &KeyringFileInfo) -> DeleteSpec {
    let Some(c) = live_collection(info, &state.collections) else {
        return DeleteSpec {
            lines: vec![format!(
                "\"{}.keyring\" is not loaded by gnome-keyring and is deleted from disk.",
                info.name
            )],
            needs_passphrase: info.plaintext,
            passphrase_note: MSG_DELETE_PLAINTEXT,
            backup_optional: true,
        };
    };
    let key = collection_key(&c.id);
    let label = _label_part(c);
    // Fail closed: a locked keyring never counts as empty.
    let empty = !c.locked && c.item_count == 0;
    let line = if empty {
        format!(
            "\"{key}\" is loaded by gnome-keyring{label} and holds no items: it will be \
             deleted through gnome-keyring."
        )
    } else {
        format!(
            "\"{key}\" is loaded by gnome-keyring{label}: it will be deleted through \
             gnome-keyring after a backup."
        )
    };
    DeleteSpec {
        lines: vec![line],
        needs_passphrase: state.files.iter().any(|f| f.plaintext),
        passphrase_note: MSG_DELETE_LIVE_PLAINTEXT,
        backup_optional: empty,
    }
}

/// Returns the delete dialog of `info` (backup checked by default).
pub fn delete_dialog(state: &AppState, info: &KeyringFileInfo) -> DialogKind {
    DialogKind::delete_file(info.name.clone(), delete_spec(state, info))
}

/// Returns why Retire is disabled: a live keyring needs a provider allowing writes.
fn _retire_blocked(live: bool, gates: Gates) -> Option<&'static str> {
    if gates.busy.is_some() || !live {
        return gates.busy;
    }
    gates.write
}

/// Renders the right-aligned header actions (Import, Retire, Delete).
fn _actions(
    ui: &mut egui::Ui,
    state: &AppState,
    info: &KeyringFileInfo,
    live: bool,
    gates: Gates,
) -> Option<Action> {
    let mut action = None;
    if danger_button(ui, "Delete file", delete_blocked(live, gates)) {
        action = Some(Action::Open(delete_dialog(state, info)));
    }
    if info.plaintext && danger_button(ui, "Retire file", _retire_blocked(live, gates)) {
        action = Some(Action::Open(retire_dialog(state, info)));
    }
    if is_empty_orphan(info, live) {
        return action;
    }
    if primary_button(ui, "Import into...", import_blocked(state, info)) {
        let kind = DialogKind::import_file(info.name.clone(), &state.collections);
        action = Some(Action::Open(kind));
    }
    action
}

/// Renders name, chips, actions, path and subline.
fn _header(
    ui: &mut egui::Ui,
    state: &AppState,
    info: &KeyringFileInfo,
    live: bool,
    gates: Gates,
) -> Option<Action> {
    let mut action = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.add(egui::Label::new(semibold(&info.name, 22.0)).truncate());
        chips(ui, info);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            action = _actions(ui, state, info, live, gates);
        });
    });
    let path = info.path.display().to_string();
    ui.label(
        RichText::new(path)
            .monospace()
            .size(12.0)
            .color(theme::MUTED),
    );
    muted(ui, &file_subline(info));
    action
}

/// Renders the notes: plaintext, unreadable, parse error and live state.
fn _notes(
    ui: &mut egui::Ui,
    state: &AppState,
    info: &KeyringFileInfo,
    live: Option<&CollectionInfo>,
) {
    ui.add_space(4.0);
    if info.format == KeyringFormat::Textual {
        note(ui, theme::TERTIARY, MSG_PLAINTEXT, theme::TERTIARY);
    }
    if let Some(text) = unreadable_note(info) {
        accent_card(ui, theme::ERROR, |ui| {
            ui.label(RichText::new(text).color(theme::ERROR).size(12.5));
            let joined = joined_lines(&state.file_warnings);
            if joined > 0 {
                let noun = if joined == 1 {
                    "line was"
                } else {
                    "lines were"
                };
                let text = format!("{joined} {noun} joined to recover multi-line values");
                ui.label(RichText::new(text).color(theme::MUTED).size(12.0));
            }
        });
    }
    if let Some(err) = &info.error {
        note(ui, theme::ERROR, err, theme::ERROR);
    }
    let text = match live {
        Some(c) => live_note(c),
        None => "Not loaded by gnome-keyring: apps cannot see the items of this file".into(),
    };
    note(ui, theme::SECONDARY, &text, theme::MUTED);
}

/// Renders the card of a binary file whose items are not read yet.
fn _encrypted_card(ui: &mut egui::Ui, info: &KeyringFileInfo) -> Option<Action> {
    let mut action = None;
    accent_card(ui, theme::SECONDARY, |ui| {
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
            glyphs::paint(ui.painter(), r, Ico::Lock, theme::LABEL);
            ui.label(RichText::new(MSG_ENCRYPTED).color(theme::MUTED));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if primary_button(ui, "Open", None) {
                    action = Some(Action::Send(Command::OpenFile {
                        name: info.name.clone(),
                        password: None,
                    }));
                }
            });
        });
    });
    action
}

/// Renders the conflicts and failures of the last import, if any.
pub fn import_report(ui: &mut egui::Ui, state: &AppState) {
    let Some(report) = &state.last_import else {
        return;
    };
    if report.conflicts.is_empty() && report.failed.is_empty() {
        return;
    }
    ui.add_space(4.0);
    accent_card(ui, theme::TERTIARY, |ui| {
        if !report.conflicts.is_empty() {
            let text = "Not imported, the target has the same attributes with another secret:";
            ui.label(RichText::new(text).color(theme::TERTIARY).size(12.5));
            for label in &report.conflicts {
                ui.label(
                    RichText::new(label)
                        .monospace()
                        .size(12.0)
                        .color(theme::TEXT),
                );
            }
        }
        for (label, err) in &report.failed {
            let text = format!("Failed: {label}: {err}");
            ui.label(RichText::new(text).color(theme::ERROR).size(12.5));
        }
    });
}

/// Renders the empty state shown when no file is selected.
pub fn empty_state(ui: &mut egui::Ui, state: &AppState) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        glyph_tile(ui, Ico::Folder, 64.0);
        ui.add_space(8.0);
        heading(ui, "Select a keyring file");
        muted(
            ui,
            "Keyring files are read from disk, without gnome-keyring.",
        );
        let dir = state.files.first().and_then(|f| f.path.parent());
        if let Some(dir) = dir {
            ui.add_space(12.0);
            ui.label(
                RichText::new(dir.display().to_string())
                    .monospace()
                    .size(12.0)
                    .color(theme::MUTED),
            );
        }
    });
}

/// Renders the selected keyring file with its items.
pub fn show(
    ui: &mut egui::Ui,
    state: &AppState,
    view: &mut FileView,
    gates: Gates,
) -> Option<Action> {
    view.sync(state);
    let Some(info) = state
        .selected_file
        .as_ref()
        .and_then(|name| state.files.iter().find(|f| &f.name == name))
    else {
        empty_state(ui, state);
        return None;
    };
    let live = live_collection(info, &state.collections);
    let mut action = _header(ui, state, info, live.is_some(), gates);
    _notes(ui, state, info, live);
    import_report(ui, state);
    ui.add_space(10.0);
    if info.format == KeyringFormat::BinaryV0 && !state.file_opened {
        return _encrypted_card(ui, info).or(action);
    }
    if info.format == KeyringFormat::Unknown {
        return action;
    }
    action = file_items::show(ui, state, view).or(action);
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::Event;
    use kring_core::model::LOGIN_COLLECTION_PATH;
    use kring_core::provider::{ProviderInfo, ProviderKind};

    /// Builds a textual file info.
    fn textual(name: &str, items: usize, readable: bool) -> KeyringFileInfo {
        KeyringFileInfo {
            path: format!("/k/{name}.keyring").into(),
            name: name.into(),
            format: KeyringFormat::Textual,
            size: 585,
            modified: 1_759_363_200,
            display_name: Some("Label".into()),
            item_count: Some(items),
            daemon_readable: Some(readable),
            plaintext: true,
            error: None,
        }
    }

    /// Builds a collection.
    fn col(path: &str, label: &str, locked: bool) -> CollectionInfo {
        CollectionInfo {
            id: CollectionId(path.into()),
            label: label.into(),
            locked,
            item_count: 0,
            aliases: vec![],
            is_login: path == LOGIN_COLLECTION_PATH,
            created: 0,
            modified: 0,
        }
    }

    /// Selecting a textual file reads it; binary and unknown files wait.
    #[test]
    fn select_reads_textual_only() {
        let mut s = AppState::default();
        let mut bin = textual("b", 2, true);
        bin.format = KeyringFormat::BinaryV0;
        let mut unknown = textual("g", 0, true);
        unknown.format = KeyringFormat::Unknown;
        s.apply(Event::Files(vec![textual("t", 2, true), bin, unknown]));
        assert!(matches!(
            select_command(&s, "t"),
            Some(Command::OpenFile { name, password: None }) if name == "t"
        ));
        assert!(select_command(&s, "b").is_none());
        assert!(select_command(&s, "g").is_none());
        assert!(select_command(&s, "missing").is_none());
    }

    /// Only textual, empty, not live files are empty orphans.
    #[test]
    fn empty_orphan_rules() {
        assert!(is_empty_orphan(&textual("e", 0, true), false));
        assert!(!is_empty_orphan(&textual("e", 0, true), true));
        assert!(!is_empty_orphan(&textual("t", 1, true), false));
        let mut bin = textual("b", 0, true);
        bin.format = KeyringFormat::BinaryV0;
        assert!(!is_empty_orphan(&bin, false));
    }

    /// The subline shows size, date and the item count when known.
    #[test]
    fn subline_parts() {
        let mut f = textual("t", 2, true);
        assert_eq!(file_subline(&f), "585 B - modified 2025-10-02 - 2 items");
        f.item_count = Some(1);
        assert_eq!(file_subline(&f), "585 B - modified 2025-10-02 - 1 item");
        f.item_count = None;
        assert_eq!(file_subline(&f), "585 B - modified 2025-10-02");
    }

    /// Unreadable files explain why apps miss their secrets; readable ones have no note.
    #[test]
    fn unreadable_note_counts_secrets() {
        assert_eq!(
            unreadable_note(&textual("m", 3, false)).as_deref(),
            Some(
                "gnome-keyring cannot read this file, so apps cannot see these 3 secrets. \
                 Import them into a keyring to recover them."
            )
        );
        assert_eq!(
            unreadable_note(&textual("m", 1, false)).as_deref(),
            Some(
                "gnome-keyring cannot read this file, so apps cannot see this secret. \
                 Import it into a keyring to recover it."
            )
        );
        assert!(unreadable_note(&textual("t", 3, true)).is_none());
    }

    /// Only continuation lines count as joined lines.
    #[test]
    fn joined_lines_counts_continuations_only() {
        let w = |line, kind| ParseWarning { line, kind };
        let warnings = [
            w(3, WarningKind::ContinuationLine),
            w(4, WarningKind::MissingSecret),
            w(5, WarningKind::ContinuationLine),
            w(6, WarningKind::BadNumber),
        ];
        assert_eq!(joined_lines(&warnings), 2);
        assert_eq!(joined_lines(&[]), 0);
    }

    /// login wins when unlocked, otherwise the first unlocked keyring; none when all locked.
    #[test]
    fn default_target_prefers_unlocked_login() {
        let login = col(LOGIN_COLLECTION_PATH, "Login", false);
        let work = col("/c/work", "Work", false);
        let locked_login = col(LOGIN_COLLECTION_PATH, "Login", true);
        assert_eq!(
            default_import_target(&[work.clone(), login.clone()]),
            Some(login.id.clone())
        );
        assert_eq!(
            default_import_target(&[locked_login.clone(), work.clone()]),
            Some(work.id.clone())
        );
        assert_eq!(default_import_target(&[locked_login]), None);
    }

    /// Import needs a provider, an unlocked keyring, a keyring file and items.
    #[test]
    fn import_gates() {
        let mut s = AppState::default();
        let f = textual("t", 2, true);
        assert_eq!(import_blocked(&s, &f), Some(MSG_NO_PROVIDER));
        s.apply(Event::Provider(ProviderInfo {
            kind: ProviderKind::GnomeKeyring,
            pid: None,
            process_name: None,
            competitors: vec![],
            has_master_password_iface: true,
        }));
        s.apply(Event::Collections(vec![col("/c/w", "Work", true)]));
        assert_eq!(import_blocked(&s, &f), Some(MSG_NO_TARGET));
        s.apply(Event::Collections(vec![col("/c/w", "Work", false)]));
        assert_eq!(import_blocked(&s, &f), None);
        assert_eq!(
            import_blocked(&s, &textual("e", 0, true)),
            Some(MSG_NOTHING_TO_IMPORT)
        );
        let mut unknown = textual("g", 0, true);
        unknown.format = KeyringFormat::Unknown;
        unknown.item_count = None;
        assert_eq!(import_blocked(&s, &unknown), Some(MSG_NOT_KEYRING));
    }

    /// The retire text states backup and deletion, or the live keyring deletion.
    #[test]
    fn retire_text_by_mode() {
        let f = textual("Default_keyring", 3, false);
        assert_eq!(
            retire_dialog_text(&RetireMode::DeleteFile, &f),
            [
                "\"Default_keyring.keyring\" is backed up, encrypted with the passphrase \
                 below, then deleted from disk.",
                "It holds 3 items in plaintext. Import them into a keyring first if you \
                 still need them.",
            ]
        );
        let live = RetireMode::DeleteLiveCollection(CollectionId("/c/x".into()));
        let empty = textual("Default_1", 0, true);
        assert_eq!(
            retire_dialog_text(&live, &empty),
            [
                "gnome-keyring has this file loaded: this will delete the live keyring \
                 'Label' with backup.",
                "The backup is encrypted with the passphrase below.",
            ]
        );
    }

    /// Delete of a live file follows the write gate; the spec depends on the file.
    #[test]
    fn delete_gate_and_spec() {
        let gated = Gates {
            write: Some("no writes"),
            master: None,
            busy: None,
        };
        assert_eq!(delete_blocked(true, gated), Some("no writes"));
        assert_eq!(delete_blocked(false, gated), None);
        let open = Gates {
            write: None,
            master: None,
            busy: None,
        };
        assert_eq!(delete_blocked(true, open), None);
        // An open operation blocks every delete, live or not.
        let busy = open.with_operation(true);
        assert_eq!(delete_blocked(false, busy), busy.busy);
        assert_eq!(_retire_blocked(true, busy), busy.busy);

        let mut s = AppState::default();
        let f = textual("Default_keyring_3", 1, true);
        let mut b = textual("Default_10", 0, true);
        b.format = KeyringFormat::BinaryV0;
        b.plaintext = false;
        s.apply(Event::Files(vec![f.clone(), b.clone()]));
        let spec = delete_spec(&s, &f);
        assert!(spec.needs_passphrase && spec.backup_optional);
        assert_eq!(
            spec.lines,
            [
                "\"Default_keyring_3.keyring\" is not loaded by gnome-keyring and is deleted \
              from disk."
            ]
        );
        assert!(matches!(
            delete_dialog(&s, &f),
            DialogKind::DeleteFile { backup: true, .. }
        ));
        let spec = delete_spec(&s, &b);
        assert!(!spec.needs_passphrase && spec.backup_optional);

        let mut live = col(
            "/org/freedesktop/secrets/collection/Default_5f10",
            "Default",
            false,
        );
        live.item_count = 2;
        s.apply(Event::Collections(vec![live.clone()]));
        let spec = delete_spec(&s, &b);
        assert_eq!(
            spec.lines,
            [
                "\"Default_10\" is loaded by gnome-keyring (label \"Default\"): it will be \
              deleted through gnome-keyring after a backup."
            ]
        );
        assert!(!spec.backup_optional);
        assert!(spec.needs_passphrase, "another listed file is plaintext");
        assert_eq!(spec.passphrase_note, MSG_DELETE_LIVE_PLAINTEXT);

        live.item_count = 0;
        s.apply(Event::Collections(vec![live.clone()]));
        let spec = delete_spec(&s, &b);
        assert!(
            spec.backup_optional,
            "an empty loaded keyring may skip the backup"
        );
        assert!(spec.lines[0].contains("holds no items"));

        live.locked = true;
        s.apply(Event::Collections(vec![live]));
        let spec = delete_spec(&s, &b);
        assert!(
            !spec.backup_optional,
            "a locked keyring never counts as empty"
        );
        assert!(spec.lines[0].ends_with("after a backup."));
    }

    /// The live note names the keyring id and its label.
    #[test]
    fn live_note_shows_id_and_label() {
        let c = col(
            "/org/freedesktop/secrets/collection/Default_5f10",
            "Default",
            false,
        );
        assert_eq!(
            live_note(&c),
            "gnome-keyring has this file loaded as the keyring Default_10 (label \"Default\")"
        );
        let blank = col("/org/freedesktop/secrets/collection/x", " ", false);
        assert_eq!(
            live_note(&blank),
            "gnome-keyring has this file loaded as the keyring x"
        );
    }
}
