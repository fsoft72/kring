//! Obsidian buttons ported from Paranoid's `ui/widgets.rs`: primary,
//! danger, secondary, small "add" and square icon buttons, all gated (disabled
//! with the blocking reason as tooltip).

use eframe::egui::{self, Color32, CornerRadius, RichText, Sense, Stroke, Ui};

use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;

/// Side of square icon buttons.
const ICO_BUTTON_SIZE: f32 = 28.0;
/// Opacity of disabled icons.
const DISABLED_ALPHA: f32 = 0.35;

/// Adds `button` enabled unless `blocked`; returns true when clicked.
fn _gated(ui: &mut Ui, button: egui::Button<'_>, blocked: Option<&str>) -> bool {
    let resp = ui.add_enabled(blocked.is_none(), button);
    match blocked {
        Some(reason) => resp.on_disabled_hover_text(reason).clicked(),
        None => resp
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked(),
    }
}

/// Solid accent button, the one main action of a view. Disabled with `blocked`
/// as tooltip. Hover keeps the fill (white text stays above 4.5:1) and adds a
/// SECONDARY border.
pub fn primary_button(ui: &mut Ui, text: &str, blocked: Option<&str>) -> bool {
    ui.scope(|ui| {
        let w = &mut ui.visuals_mut().widgets;
        for (s, fill, border) in [
            (&mut w.inactive, theme::PRIMARY, Stroke::NONE),
            (
                &mut w.hovered,
                theme::PRIMARY,
                Stroke::new(1.0_f32, theme::SECONDARY),
            ),
            (&mut w.active, theme::PRIMARY_ACTIVE, Stroke::NONE),
        ] {
            s.weak_bg_fill = fill;
            s.bg_fill = fill;
            s.bg_stroke = border;
            s.fg_stroke = Stroke::new(1.0_f32, theme::ON_ACCENT);
        }
        let label = RichText::new(text)
            .family(theme::semibold())
            .color(theme::ON_ACCENT);
        _gated(ui, egui::Button::new(label), blocked)
    })
    .inner
}

/// Outlined destructive button (red hairline, tinted on hover).
pub fn danger_button(ui: &mut Ui, text: &str, blocked: Option<&str>) -> bool {
    ui.scope(|ui| {
        let w = &mut ui.visuals_mut().widgets;
        for (s, a) in [
            (&mut w.inactive, 0.0),
            (&mut w.hovered, theme::DANGER_HOVER_ALPHA),
            (&mut w.active, theme::DANGER_ACTIVE_ALPHA),
        ] {
            let fill = theme::ERROR.gamma_multiply(a);
            s.weak_bg_fill = fill;
            s.bg_fill = fill;
            s.bg_stroke = Stroke::new(1.0_f32, theme::ERROR.gamma_multiply(0.6 + a));
            s.fg_stroke = Stroke::new(1.0_f32, theme::ERROR);
        }
        let label = RichText::new(text).color(theme::ERROR);
        _gated(ui, egui::Button::new(label), blocked)
    })
    .inner
}

/// Flat hairline button for secondary actions (Cancel, Edit...).
pub fn secondary_button(ui: &mut Ui, text: &str, blocked: Option<&str>) -> bool {
    _gated(ui, egui::Button::new(text), blocked)
}

/// Compact hairline button for actions inside list rows and card headers.
pub fn compact_button(ui: &mut Ui, text: &str, blocked: Option<&str>) -> bool {
    let label = RichText::new(text).size(12.5);
    ui.scope(|ui| {
        ui.spacing_mut().button_padding = egui::vec2(10.0, 2.0);
        ui.spacing_mut().interact_size.y = 24.0;
        _gated(ui, egui::Button::new(label), blocked)
    })
    .inner
}

/// Small text button with a leading `+` for "add" actions inside cards.
pub fn add_button(ui: &mut Ui, text: &str, blocked: Option<&str>) -> bool {
    let label = RichText::new(format!("+  {text}"))
        .size(12.5)
        .color(theme::SECONDARY);
    ui.scope(|ui| {
        ui.spacing_mut().button_padding = egui::vec2(10.0, 3.0);
        ui.spacing_mut().interact_size.y = 26.0;
        _gated(ui, egui::Button::new(label), blocked)
    })
    .inner
}

/// Square icon button with a vector icon, hover background and tooltip.
/// Disabled (dimmed, `blocked` as tooltip) when `blocked` is set. `danger`
/// turns the hover state red.
pub fn ico_button(ui: &mut Ui, ico: Ico, tip: &str, blocked: Option<&str>, danger: bool) -> bool {
    let size = egui::vec2(ICO_BUTTON_SIZE, ICO_BUTTON_SIZE);
    let sense = if blocked.is_some() {
        Sense::hover()
    } else {
        Sense::click()
    };
    let (rect, resp) = ui.allocate_exact_size(size, sense);
    let resp = match blocked {
        Some(reason) => resp.on_hover_text(format!("{tip}: {reason}")),
        None => resp
            .on_hover_text(tip)
            .on_hover_cursor(egui::CursorIcon::PointingHand),
    };
    let hot = blocked.is_none() && resp.hovered();
    if hot {
        let fill = if danger {
            theme::ERROR.gamma_multiply(theme::DANGER_HOVER_ALPHA)
        } else {
            theme::INPUT_FILL_BLUE
        };
        ui.painter()
            .rect_filled(rect, CornerRadius::same(theme::RADIUS_CTRL), fill);
    }
    let color = match (blocked.is_some(), hot, danger) {
        (true, _, _) => theme::LABEL.gamma_multiply(DISABLED_ALPHA),
        (false, true, true) => theme::ERROR,
        (false, true, false) => Color32::WHITE,
        _ => theme::LABEL,
    };
    glyphs::paint(ui.painter(), rect, ico, color);
    resp.clicked()
}
