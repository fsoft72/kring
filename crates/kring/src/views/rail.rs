//! Nav rail (64 px, NAVY_DARK): brand tile, area tiles and the worker dot.

use eframe::egui::{self, Align2, CornerRadius, FontId, Sense, Ui};

use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;
use crate::views::Area;

/// Side of a rail tile.
const TILE_SIZE: f32 = 44.0;
/// Side of the brand tile.
const BRAND_SIZE: f32 = 36.0;
/// Corner radius of the brand tile.
const BRAND_RADIUS: u8 = 8;
/// Opacity of the glyphs of areas not implemented yet.
const SOON_ALPHA: f32 = 0.4;
/// Areas that are implemented, with their glyph and tooltip.
const AREAS: [(Area, Ico, &str); 2] = [
    (Area::Secrets, Ico::Key, "Secrets"),
    (Area::Files, Ico::Folder, "Offline files"),
];
/// Areas that are not implemented yet, with their glyph.
const FUTURE_AREAS: [(Ico, &str); 4] = [
    (Ico::Wallet, "KWallet"),
    (Ico::Terminal, "SSH keys"),
    (Ico::Shield, "GPG keys"),
    (Ico::Sliders, "Tools"),
];

/// State of the background worker shown by the rail dot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerActivity {
    /// Waiting for commands (OK dot).
    Idle,
    /// A command is in flight (pulsing SECONDARY dot).
    Busy,
    /// The worker thread is gone (ERROR dot).
    Stopped,
}

impl WorkerActivity {
    /// Derives the activity from the app flags (stopped wins over busy).
    pub fn from_flags(stopped: bool, busy: bool) -> Self {
        if stopped {
            return Self::Stopped;
        }
        if busy {
            return Self::Busy;
        }
        Self::Idle
    }

    /// Tooltip of the worker dot.
    pub fn tooltip(self) -> &'static str {
        match self {
            Self::Idle => "Worker idle",
            Self::Busy => "Worker busy",
            Self::Stopped => "Worker stopped, restart kring",
        }
    }
}

/// App mark: a 36 px PRIMARY tile with a semi-bold "K".
fn _brand(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(BRAND_SIZE, BRAND_SIZE), Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(BRAND_RADIUS), theme::PRIMARY);
    p.text(
        rect.center(),
        Align2::CENTER_CENTER,
        "K",
        FontId::new(20.0, theme::semibold()),
        theme::ON_ACCENT,
    );
}

/// Rail tile: glyph with an accent bar on the left edge when active. Future
/// areas are dimmed and only show a tooltip. Returns true when clicked.
fn _tile(ui: &mut Ui, ico: Ico, tip: &str, active: bool, enabled: bool) -> bool {
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(TILE_SIZE, TILE_SIZE), sense);
    let resp = resp.on_hover_text(tip);
    let r = CornerRadius::same(theme::RADIUS_CARD);
    if active {
        ui.painter().rect_filled(rect, r, theme::INPUT_FILL_BLUE);
        let bar = egui::Rect::from_min_size(
            egui::pos2(rect.left() - 8.0, rect.top() + 8.0),
            egui::vec2(3.0, rect.height() - 16.0),
        );
        ui.painter()
            .rect_filled(bar, CornerRadius::same(1), theme::PRIMARY);
    } else if enabled && resp.hovered() {
        ui.painter().rect_filled(rect, r, theme::FIELD_ROW_BG);
    }
    let color = match (active, enabled) {
        (true, _) => theme::SECONDARY,
        (false, false) => theme::LABEL.gamma_multiply(SOON_ALPHA),
        (false, true) => theme::LABEL,
    };
    glyphs::paint(ui.painter(), rect.shrink(2.0), ico, color);
    if enabled {
        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
    } else {
        false
    }
}

/// Small dot with the worker state as tooltip; pulses while busy.
fn _worker_dot(ui: &mut Ui, activity: WorkerActivity) {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(TILE_SIZE, 24.0), Sense::hover());
    let color = match activity {
        WorkerActivity::Idle => theme::OK,
        WorkerActivity::Stopped => theme::ERROR,
        WorkerActivity::Busy => {
            let t = ui.input(|i| i.time) as f32;
            ui.ctx().request_repaint();
            theme::SECONDARY.gamma_multiply(0.55 + 0.45 * (t * 5.0).sin().abs())
        }
    };
    ui.painter().circle_filled(rect.center(), 4.0, color);
    resp.on_hover_text(activity.tooltip());
}

/// Renders the rail content (the panel frame is set by the caller); returns
/// the area whose tile was clicked.
pub fn show(ui: &mut Ui, activity: WorkerActivity, current: Area) -> Option<Area> {
    let mut clicked = None;
    ui.spacing_mut().item_spacing.y = 6.0;
    ui.vertical_centered(|ui| {
        _brand(ui);
        ui.add_space(14.0);
        for (area, ico, tip) in AREAS {
            if _tile(ui, ico, tip, area == current, true) {
                clicked = Some(area);
            }
        }
        for (ico, area) in FUTURE_AREAS {
            _tile(ui, ico, &format!("{area} - coming soon"), false, false);
        }
    });
    ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
        _worker_dot(ui, activity);
    });
    clicked
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stopped wins over busy, which wins over idle.
    #[test]
    fn activity_from_flags() {
        assert_eq!(
            WorkerActivity::from_flags(true, true),
            WorkerActivity::Stopped
        );
        assert_eq!(
            WorkerActivity::from_flags(false, true),
            WorkerActivity::Busy
        );
        assert_eq!(
            WorkerActivity::from_flags(false, false),
            WorkerActivity::Idle
        );
    }
}
