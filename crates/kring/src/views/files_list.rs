//! List panel "Keyring files": rescan button, search box, summary and rows.

use eframe::egui::{self, Align, Color32, Layout, RichText, Sense, Ui, UiBuilder};
use kring_core::keyring_file::{KeyringFileInfo, KeyringFormat};

use crate::app_state::AppState;
use crate::ui::glyphs::Ico;
use crate::ui::theme;
use crate::ui::widgets::{chip, ico_button, muted, muted_text, search_box, semibold};
use crate::views::Action;
use crate::views::file_detail::{is_empty_orphan, live_collection, retire_dialog};
use crate::views::sidebar::row_background;
use crate::worker::Command;

/// Height of a file row.
const ROW_HEIGHT: f32 = 44.0;
/// Horizontal padding inside a row.
const ROW_PADDING: f32 = 12.0;
/// Tooltip of the quick Retire button of empty orphan files.
const MSG_QUICK_RETIRE: &str = "Retire this empty file (not used by gnome-keyring)";
/// Bytes in a kilobyte (sizes are shown in binary units).
const KB: u64 = 1024;
/// Bytes in a megabyte.
const MB: u64 = KB * KB;

/// A status chip of a keyring file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileChip {
    /// Encrypted binary file.
    Binary,
    /// Textual file: secrets are readable on disk.
    Plaintext,
    /// gnome-keyring rejects the file, so apps cannot see its secrets.
    Unreadable,
    /// Textual file without items.
    Empty,
    /// Not a recognized keyring file.
    Unknown,
}

impl FileChip {
    /// Chip text (painted uppercase).
    pub fn label(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Plaintext => "plaintext",
            Self::Unreadable => "unreadable",
            Self::Empty => "empty",
            Self::Unknown => "unknown",
        }
    }

    /// Tint of the chip text and border.
    pub fn color(self) -> Color32 {
        match self {
            Self::Binary => theme::SECONDARY,
            Self::Plaintext => theme::TERTIARY,
            Self::Unreadable | Self::Unknown => theme::ERROR,
            Self::Empty => theme::LABEL,
        }
    }
}

/// Returns the chips of a keyring file, in display order.
pub fn file_chips(info: &KeyringFileInfo) -> Vec<FileChip> {
    match info.format {
        KeyringFormat::BinaryV0 => vec![FileChip::Binary],
        KeyringFormat::Unknown => vec![FileChip::Unknown],
        KeyringFormat::Textual => {
            let mut out = vec![FileChip::Plaintext];
            if info.daemon_readable == Some(false) {
                out.push(FileChip::Unreadable);
            }
            if info.item_count == Some(0) {
                out.push(FileChip::Empty);
            }
            out
        }
    }
}

/// Returns the muted summary line, e.g. `6 files - 4 plaintext - 1 unreadable by gnome-keyring`.
pub fn files_summary(files: &[KeyringFileInfo]) -> String {
    let total = files.len();
    let noun = if total == 1 { "file" } else { "files" };
    let plaintext = files
        .iter()
        .filter(|f| f.format == KeyringFormat::Textual)
        .count();
    let unreadable = files
        .iter()
        .filter(|f| f.daemon_readable == Some(false))
        .count();
    format!("{total} {noun} - {plaintext} plaintext - {unreadable} unreadable by gnome-keyring")
}

/// Returns true when the file name or keyring label contains `filter` (case-insensitive).
pub fn file_matches(info: &KeyringFileInfo, filter: &str) -> bool {
    let needle = filter.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    let label = info.display_name.as_deref().unwrap_or_default();
    info.name.to_lowercase().contains(&needle) || label.to_lowercase().contains(&needle)
}

/// Formats a byte count: `585 B`, `22.4 KB`, `1.5 MB`.
pub fn format_size(bytes: u64) -> String {
    if bytes < KB {
        return format!("{bytes} B");
    }
    if bytes < MB {
        return format!("{:.1} KB", bytes as f64 / KB as f64);
    }
    format!("{:.1} MB", bytes as f64 / MB as f64)
}

/// Renders the chips of a file.
pub fn chips(ui: &mut Ui, info: &KeyringFileInfo) {
    for c in file_chips(info) {
        chip(ui, c.label(), c.color());
    }
}

/// What a click on a file row asked for.
enum RowClick {
    /// Nothing clicked.
    None,
    /// The row itself: select the file.
    Select,
    /// The quick Retire button of an empty orphan file.
    Retire,
}

/// Renders one file row; `orphan` adds the quick Retire button.
fn _row(ui: &mut Ui, info: &KeyringFileInfo, selected: bool, orphan: bool) -> RowClick {
    let mut retire = false;
    let size = egui::vec2(ui.available_width(), ROW_HEIGHT);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    row_background(ui, rect, selected, resp.hovered());
    let inner = rect.shrink2(egui::vec2(ROW_PADDING, 0.0));
    // Right to left: quick action, size and chips keep their room; the name
    // truncates into what is left.
    let builder = UiBuilder::new()
        .max_rect(inner)
        .layout(Layout::right_to_left(Align::Center));
    ui.scope_builder(builder, |ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        if orphan {
            retire = ico_button(ui, Ico::Trash, MSG_QUICK_RETIRE, None, true);
        }
        ui.label(muted_text(format_size(info.size)));
        ui.add_space(4.0);
        for c in file_chips(info).into_iter().rev() {
            chip(ui, c.label(), c.color());
        }
        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            let name = RichText::new(&info.name)
                .family(theme::medium())
                .size(14.0)
                .color(theme::TEXT);
            ui.add(egui::Label::new(name).truncate().selectable(false));
        });
    });
    if retire {
        return RowClick::Retire;
    }
    if resp.clicked() {
        return RowClick::Select;
    }
    RowClick::None
}

/// Renders the keyring files list panel and returns the requested action.
pub fn show(ui: &mut Ui, state: &AppState, filter: &mut String) -> Option<Action> {
    let mut action = None;
    ui.horizontal(|ui| {
        ui.label(semibold("Keyring files", 18.0));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ico_button(ui, Ico::Refresh, "Rescan the keyrings folder", None, false) {
                action = Some(Action::Send(Command::ScanFiles));
            }
        });
    });
    ui.add_space(2.0);
    search_box(ui, filter, "Search files");
    muted(ui, &files_summary(&state.files));
    ui.add_space(2.0);
    egui::ScrollArea::vertical()
        .id_salt("kring-files")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for info in state.files.iter().filter(|f| file_matches(f, filter)) {
                let selected = state.selected_file.as_ref() == Some(&info.name);
                let live = live_collection(info, &state.collections).is_some();
                match _row(ui, info, selected, is_empty_orphan(info, live)) {
                    RowClick::Select if !selected => {
                        action = Some(Action::SelectFile(info.name.clone()));
                    }
                    RowClick::Retire => {
                        action = Some(Action::Open(retire_dialog(state, info)));
                    }
                    _ => {}
                }
            }
        });
    action
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a file info of the given format.
    fn info(name: &str, format: KeyringFormat) -> KeyringFileInfo {
        KeyringFileInfo {
            path: format!("/k/{name}.keyring").into(),
            name: name.into(),
            format,
            size: 10,
            modified: 0,
            display_name: None,
            item_count: None,
            daemon_readable: None,
            plaintext: format != KeyringFormat::BinaryV0,
            error: None,
        }
    }

    /// Builds a textual file with `items` items and the daemon readability.
    fn textual(name: &str, items: usize, readable: bool) -> KeyringFileInfo {
        KeyringFileInfo {
            item_count: Some(items),
            daemon_readable: Some(readable),
            ..info(name, KeyringFormat::Textual)
        }
    }

    /// Binary, plaintext, unreadable, empty and unknown files get their chips.
    #[test]
    fn chips_by_format_and_state() {
        use FileChip::*;
        assert_eq!(file_chips(&info("b", KeyringFormat::BinaryV0)), [Binary]);
        assert_eq!(file_chips(&textual("t", 2, true)), [Plaintext]);
        assert_eq!(file_chips(&textual("m", 1, false)), [Plaintext, Unreadable]);
        assert_eq!(file_chips(&textual("e", 0, true)), [Plaintext, Empty]);
        assert_eq!(file_chips(&info("g", KeyringFormat::Unknown)), [Unknown]);
        assert_eq!(Plaintext.color(), theme::TERTIARY);
        assert_eq!(Unreadable.color(), theme::ERROR);
    }

    /// The summary counts files, textual (plaintext) files and unreadable ones.
    #[test]
    fn summary_counts() {
        let files = [
            info("b", KeyringFormat::BinaryV0),
            textual("t", 2, true),
            textual("m", 1, false),
            info("g", KeyringFormat::Unknown),
        ];
        assert_eq!(
            files_summary(&files),
            "4 files - 2 plaintext - 1 unreadable by gnome-keyring"
        );
        assert_eq!(
            files_summary(&files[..1]),
            "1 file - 0 plaintext - 0 unreadable by gnome-keyring"
        );
    }

    /// The filter matches the file name or the keyring label; blank matches all.
    #[test]
    fn filter_by_name_or_label() {
        let mut f = textual("Default_keyring", 1, false);
        f.display_name = Some("Old Stuff".into());
        assert!(file_matches(&f, " "));
        assert!(file_matches(&f, "default_k"));
        assert!(file_matches(&f, "STUFF"));
        assert!(!file_matches(&f, "login"));
    }

    /// Sizes use binary units with one decimal above a kilobyte.
    #[test]
    fn sizes_formatted() {
        assert_eq!(format_size(585), "585 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(22 * 1024 + 410), "22.4 KB");
        assert_eq!(format_size(3 * 1024 * 1024 / 2), "1.5 MB");
    }
}
