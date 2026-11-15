//! Nav rail (64 px, NAVY_DARK): brand tile, area tiles, the remembered
//! passphrase indicator and the worker dot.

use eframe::egui::{self, Align2, CornerRadius, FontId, Sense, Ui};

use crate::session_secret::MSG_REMEMBERED_TIP;
use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;
use crate::views::{Action, Area};

/// Side of a rail tile.
const TILE_SIZE: f32 = 44.0;
/// Side of the brand tile.
const BRAND_SIZE: f32 = 36.0;
/// Corner radius of the brand tile.
const BRAND_RADIUS: u8 = 8;
/// Opacity of the glyphs of areas not implemented yet.
const SOON_ALPHA: f32 = 0.4;
/// Rail tiles in order: the area (`None` when not implemented yet), glyph
/// and tooltip.
const TILES: [(Option<Area>, Ico, &str); 7] = [
    (Some(Area::Secrets), Ico::Key, "Secrets"),
    (Some(Area::Files), Ico::Folder, "Offline files"),
    (Some(Area::KWallet), Ico::Wallet, "KWallet"),
    (Some(Area::Ssh), Ico::Terminal, "SSH keys"),
    (Some(Area::Gpg), Ico::Shield, "GPG keys"),
    (Some(Area::Backups), Ico::Archive, "Backups"),
    (Some(Area::Consolidate), Ico::Merge, "Consolidate"),
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

/// Key tile tinted TERTIARY shown while a passphrase is remembered; returns
/// true when clicked (ask to forget it).
fn _remembered_tile(ui: &mut Ui) -> bool {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(TILE_SIZE, TILE_SIZE), Sense::click());
    let resp = resp.on_hover_text(MSG_REMEMBERED_TIP);
    let r = CornerRadius::same(theme::RADIUS_CARD);
    let fill = if resp.hovered() {
        theme::TERTIARY.gamma_multiply(theme::ACCENT_ACTIVE_ALPHA)
    } else {
        theme::TERTIARY.gamma_multiply(theme::DANGER_HOVER_ALPHA)
    };
    ui.painter().rect_filled(rect, r, fill);
    glyphs::paint(ui.painter(), rect.shrink(6.0), Ico::Key, theme::TERTIARY);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

/// Renders the rail content (the panel frame is set by the caller); returns
/// the area switch, or the forget request of the remembered passphrase
/// (its tile is shown only when `remembered`).
pub fn show(
    ui: &mut Ui,
    activity: WorkerActivity,
    current: Area,
    remembered: bool,
) -> Option<Action> {
    let mut clicked = None;
    ui.spacing_mut().item_spacing.y = 6.0;
    ui.vertical_centered(|ui| {
        _brand(ui);
        ui.add_space(14.0);
        for (area, ico, tip) in TILES {
            let Some(area) = area else {
                _tile(ui, ico, &format!("{tip} - coming soon"), false, false);
                continue;
            };
            if _tile(ui, ico, tip, area == current, true) {
                clicked = Some(Action::SwitchArea(area));
            }
        }
    });
    ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
        _worker_dot(ui, activity);
        if remembered && _remembered_tile(ui) {
            clicked = Some(Action::AskForgetPassphrase);
        }
    });
    clicked
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every area has exactly one enabled tile; Backups replaced Tools and
    /// Consolidate comes last.
    #[test]
    fn tiles_cover_areas() {
        let areas = [
            Area::Secrets,
            Area::Files,
            Area::KWallet,
            Area::Ssh,
            Area::Backups,
            Area::Consolidate,
        ];
        for area in areas {
            assert_eq!(TILES.iter().filter(|t| t.0 == Some(area)).count(), 1);
        }
        assert!(TILES.iter().all(|t| t.2 != "Tools"));
        assert_eq!(TILES[3], (Some(Area::Ssh), Ico::Terminal, "SSH keys"));
        assert_eq!(TILES[5], (Some(Area::Backups), Ico::Archive, "Backups"));
        assert_eq!(
            TILES[6],
            (Some(Area::Consolidate), Ico::Merge, "Consolidate")
        );
    }

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
