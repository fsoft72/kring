//! Obsidian widgets ported from Paranoid's `ui/widgets.rs`: text styles,
//! buttons, icon buttons, cards, chips, notes and inputs.

use eframe::egui::{self, Color32, CornerRadius, Response, RichText, Sense, Stroke, Ui};

use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;

/// Vertical inner margin of every text input.
pub const INPUT_V_MARGIN: i8 = 9;
/// Side of square icon buttons.
const ICO_BUTTON_SIZE: f32 = 28.0;
/// Opacity of disabled icons.
const DISABLED_ALPHA: f32 = 0.35;
/// Font size of chips.
const CHIP_FONT_SIZE: f32 = 10.5;
/// Inner padding of chips.
const CHIP_PADDING: egui::Vec2 = egui::vec2(6.0, 2.0);
/// Width of the accent bar of notes and banners.
pub const ACCENT_BAR_WIDTH: f32 = 3.0;

/// Page heading: semi-bold 22.
pub fn heading(ui: &mut Ui, text: &str) {
    ui.label(semibold(text, 22.0));
}

/// Semi-bold text of `size` points.
pub fn semibold(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text.into())
        .size(size)
        .family(theme::semibold())
        .color(theme::TEXT)
}

/// Muted secondary text (12 pt).
pub fn muted_text(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).color(theme::MUTED).size(12.0)
}

/// Adds a muted secondary label.
pub fn muted(ui: &mut Ui, text: &str) {
    ui.label(muted_text(text));
}

/// Small uppercase field label (LABEL colour, semi-bold 11).
pub fn field_label(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text.to_uppercase())
            .color(theme::LABEL)
            .size(11.0)
            .family(theme::semibold()),
    );
}

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
            (&mut w.hovered, 0.18),
            (&mut w.active, 0.30),
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
            theme::ERROR.gamma_multiply(0.18)
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

/// Small uppercase chip: `color` text on INPUT_FILL_BLUE.
pub fn chip(ui: &mut Ui, text: &str, color: Color32) {
    let font = egui::FontId::new(CHIP_FONT_SIZE, theme::semibold());
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_uppercase(), font, color);
    let size = galley.size() + 2.0 * CHIP_PADDING;
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let r = CornerRadius::same(theme::RADIUS_CTRL);
    let p = ui.painter();
    p.rect_filled(rect, r, theme::INPUT_FILL_BLUE);
    p.rect_stroke(
        rect,
        r,
        Stroke::new(1.0_f32, color.gamma_multiply(0.30)),
        egui::StrokeKind::Inside,
    );
    p.galley(rect.min + CHIP_PADDING, galley, color);
}

/// Frame of a raised card (FIELD_ROW_BG, hairline border, RADIUS_CARD).
pub fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(theme::FIELD_ROW_BG)
        .stroke(Stroke::new(1.0_f32, theme::FIELD_ROW_BORDER))
        .corner_radius(CornerRadius::same(theme::RADIUS_CARD))
        .inner_margin(egui::Margin::symmetric(16, 12))
}

/// Raised card filling the available width.
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> egui::InnerResponse<R> {
    card_frame().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        add(ui)
    })
}

/// Card with a coloured accent bar on its left edge, for notes and banners.
pub fn accent_card<R>(
    ui: &mut Ui,
    accent: Color32,
    add: impl FnOnce(&mut Ui) -> R,
) -> egui::InnerResponse<R> {
    let resp = card_frame()
        .inner_margin(egui::Margin {
            left: 18,
            right: 16,
            top: 10,
            bottom: 10,
        })
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            add(ui)
        });
    let r = resp.response.rect;
    let bar = egui::Rect::from_min_size(r.min, egui::vec2(ACCENT_BAR_WIDTH, r.height()));
    let radius = CornerRadius {
        nw: theme::RADIUS_CARD,
        sw: theme::RADIUS_CARD,
        ne: 0,
        se: 0,
    };
    ui.painter().rect_filled(bar, radius, accent);
    resp
}

/// Note card: accent bar plus muted (or coloured) wrapped text.
pub fn note(ui: &mut Ui, accent: Color32, text: &str, text_color: Color32) {
    accent_card(ui, accent, |ui| {
        ui.label(RichText::new(text).color(text_color).size(12.5));
    });
}

/// Single-line `TextEdit` with the app-wide taller input size.
pub fn input(text: &mut String) -> egui::TextEdit<'_> {
    egui::TextEdit::singleline(text).margin(egui::Margin::symmetric(8, INPUT_V_MARGIN))
}

/// Search field with a vector magnifier and an inline clear button.
pub fn search_box(ui: &mut Ui, text: &mut String, hint: &str) -> Response {
    let w = ui.available_width();
    let left = ui.available_rect_before_wrap().left();
    let resp = ui.add(
        input(text)
            .hint_text(hint)
            .margin(egui::Margin {
                left: 34,
                right: 30,
                top: INPUT_V_MARGIN,
                bottom: INPUT_V_MARGIN,
            })
            .desired_width(w),
    );
    let c = egui::pos2(left + 17.0, resp.rect.center().y);
    let icon = if resp.has_focus() {
        theme::SECONDARY
    } else {
        theme::LABEL
    };
    let icon_rect = egui::Rect::from_center_size(c, egui::vec2(24.0, 24.0));
    glyphs::paint(ui.painter(), icon_rect, Ico::Search, icon);
    if text.is_empty() {
        return resp;
    }
    let r = egui::Rect::from_center_size(
        resp.rect.right_center() - egui::vec2(16.0, 0.0),
        egui::vec2(24.0, 24.0),
    );
    let clear = ui.interact(r, resp.id.with("clear"), Sense::click());
    let color = if clear.hovered() {
        theme::TEXT
    } else {
        theme::LABEL
    };
    glyphs::paint(ui.painter(), r, Ico::Close, color);
    if clear
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
    {
        text.clear();
    }
    resp
}

/// Rounded tile with a glyph, as used by empty states (64 px) and the brand.
pub fn glyph_tile(ui: &mut Ui, ico: Ico, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), Sense::hover());
    let r = CornerRadius::same(theme::RADIUS_CARD);
    ui.painter().rect_filled(rect, r, theme::INPUT_FILL_BLUE);
    ui.painter().rect_stroke(
        rect,
        r,
        Stroke::new(1.0_f32, theme::PRIMARY.gamma_multiply(0.5)),
        egui::StrokeKind::Inside,
    );
    glyphs::paint(ui.painter(), rect, ico, theme::SECONDARY);
}
