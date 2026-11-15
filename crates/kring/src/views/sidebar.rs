//! Left panel: collection list and the sections not implemented yet.

use eframe::egui;

use crate::app_state::AppState;
use crate::views::collection::display_name;
use crate::views::dialogs::DialogKind;
use crate::views::{Action, Gates, gated_button};

/// Sections shown disabled until they are implemented.
const COMING_SOON: [&str; 4] = ["OFFLINE FILES", "KWALLET", "SSH KEYS", "GPG KEYS"];
/// Entries of the disabled TOOLS section.
const TOOLS: [&str; 2] = ["Consolidate", "Backups"];
/// Share of the sidebar height used by the collection list.
const LIST_HEIGHT_FRACTION: f32 = 0.6;
/// Tooltip of disabled sections.
const MSG_COMING_SOON: &str = "coming soon";

/// Adds a disabled section title with the "coming soon" tooltip.
fn _disabled(ui: &mut egui::Ui, text: &str) {
    ui.add_enabled(false, egui::Label::new(text))
        .on_disabled_hover_text(MSG_COMING_SOON);
}

/// Renders the sidebar and returns the requested action.
pub fn show(ui: &mut egui::Ui, state: &AppState, gates: Gates) -> Option<Action> {
    let mut action = None;
    ui.strong("SECRETS");
    egui::ScrollArea::vertical()
        .id_salt("kring-collections")
        .max_height(ui.available_height() * LIST_HEIGHT_FRACTION)
        .show(ui, |ui| {
            for c in &state.collections {
                let selected = state.selected.as_ref() == Some(&c.id);
                let name = display_name(c);
                let text = if c.locked {
                    format!("{name} (locked)")
                } else {
                    name
                };
                if ui.selectable_label(selected, text).clicked() {
                    action = Some(Action::SelectCollection(c.id.clone()));
                }
            }
        });
    if gated_button(ui, "New collection", gates.write_and_master()) {
        action = Some(Action::Open(DialogKind::create_collection()));
    }
    ui.separator();
    for section in COMING_SOON {
        _disabled(ui, section);
    }
    _disabled(ui, "TOOLS");
    ui.indent("kring-tools", |ui| {
        for tool in TOOLS {
            _disabled(ui, tool);
        }
    });
    ui.weak(MSG_COMING_SOON);
    action
}
