//! Full-width banners at the top of the detail pane: worker stopped, no
//! provider and competing Secret Service owners.

use eframe::egui::{self, RichText};

use crate::app_state::AppState;
use crate::ui::theme;
use crate::ui::widgets::accent_card;

/// Banner shown when the worker thread is gone.
pub const MSG_WORKER_STOPPED: &str = "Background worker stopped, restart kring";
/// Banner shown when no provider owns the Secret Service name.
pub const MSG_NO_PROVIDER: &str = "No Secret Service provider running";

/// Returns the banners to show, each with its accent colour.
pub fn banners(state: &AppState, worker_stopped: bool) -> Vec<(String, egui::Color32)> {
    let mut out = Vec::new();
    if worker_stopped {
        out.push((MSG_WORKER_STOPPED.to_string(), theme::ERROR));
    }
    if state.provider_unavailable {
        out.push((MSG_NO_PROVIDER.to_string(), theme::ERROR));
    }
    let competitors = state.provider.as_ref().map(|p| &p.competitors);
    if let Some(list) = competitors.filter(|l| !l.is_empty()) {
        let names = list.join(", ");
        let text = format!("Other services may claim org.freedesktop.secrets: {names}");
        out.push((text, theme::TERTIARY));
    }
    out
}

/// Renders the banners as accent cards with coloured text.
pub fn show(ui: &mut egui::Ui, state: &AppState, worker_stopped: bool) {
    let list = banners(state, worker_stopped);
    if list.is_empty() {
        return;
    }
    for (text, color) in list {
        accent_card(ui, color, |ui| {
            ui.label(RichText::new(text).color(color));
        });
    }
    ui.add_space(8.0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::Event;

    /// Worker and provider failures are errors; nothing to show by default.
    #[test]
    fn banner_conditions() {
        let mut s = AppState::default();
        assert!(banners(&s, false).is_empty());
        s.apply(Event::ProviderUnavailable);
        let b = banners(&s, true);
        assert_eq!(b.len(), 2);
        assert_eq!(b[0], (MSG_WORKER_STOPPED.to_string(), theme::ERROR));
        assert_eq!(b[1], (MSG_NO_PROVIDER.to_string(), theme::ERROR));
    }
}
