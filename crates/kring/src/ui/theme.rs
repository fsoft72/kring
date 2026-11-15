//! "Obsidian" design system shared with Paranoid Password Manager: near-black
//! neutral surfaces, one electric-blue accent, sharp corners (3-6 px) and IBM
//! Plex typography. Tokens are copied verbatim from Paranoid's `theme.rs`.

use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Stroke, TextStyle,
};

/// App background (detail pane, list).
pub const DEEP_DARK: Color32 = Color32::from_rgb(0x0E, 0x11, 0x17);
/// Chrome background (nav rail, headers): darker than the content.
pub const NAVY_DARK: Color32 = Color32::from_rgb(0x09, 0x0B, 0x0F);
/// Sunken input background.
pub const INPUT_FILL: Color32 = Color32::from_rgb(0x0A, 0x0D, 0x12);
/// Hover / selected tint (accent at low strength).
pub const INPUT_FILL_BLUE: Color32 = Color32::from_rgb(0x17, 0x20, 0x38);
/// Raised card background.
pub const FIELD_ROW_BG: Color32 = Color32::from_rgb(0x14, 0x18, 0x21);
/// Card / divider border.
pub const FIELD_ROW_BORDER: Color32 = Color32::from_rgb(0x25, 0x2B, 0x3A);
/// Accent (solid fills and strokes; white text on it is 4.8:1).
pub const PRIMARY: Color32 = Color32::from_rgb(0x3F, 0x6B, 0xDB);
/// Accent used for text and icons on dark surfaces.
pub const SECONDARY: Color32 = Color32::from_rgb(0x8F, 0xB1, 0xF7);
/// Warnings.
pub const TERTIARY: Color32 = Color32::from_rgb(0xF2, 0xB8, 0x4B);
/// Floating surfaces (windows, menus, toasts).
pub const SURFACE: Color32 = Color32::from_rgb(0x13, 0x17, 0x20);
/// Errors and destructive actions.
pub const ERROR: Color32 = Color32::from_rgb(0xF0, 0x70, 0x7F);
/// Success.
pub const OK: Color32 = Color32::from_rgb(0x3D, 0xD6, 0x8C);
/// Small uppercase field labels.
pub const LABEL: Color32 = Color32::from_rgb(0x8A, 0x94, 0xA9);
/// Secondary text.
pub const MUTED: Color32 = Color32::from_rgb(0x80, 0x89, 0x9E);
/// Primary text.
pub const TEXT: Color32 = Color32::from_rgb(0xE6, 0xEA, 0xF2);
/// Text on a solid accent button.
pub const ON_ACCENT: Color32 = Color32::WHITE;
/// Hovered accent button in Paranoid. White text on it is only 3.9:1, so kring
/// keeps the PRIMARY fill on hover and marks it with a SECONDARY border instead.
pub const PRIMARY_HOVER: Color32 = Color32::from_rgb(0x4F, 0x7B, 0xE8);
/// Pressed accent button.
pub const PRIMARY_ACTIVE: Color32 = Color32::from_rgb(0x34, 0x59, 0xC0);
/// Hairline border of inactive buttons.
pub const BUTTON_BORDER: Color32 = Color32::from_rgb(0x32, 0x3A, 0x4D);

/// Corner radius of buttons, inputs and chips.
pub const RADIUS_CTRL: u8 = 3;
/// Corner radius of cards and list rows.
pub const RADIUS_CARD: u8 = 4;
/// Corner radius of windows and popups.
pub const RADIUS_WINDOW: u8 = 6;

/// Name of the semi-bold font family.
const FAMILY_SEMIBOLD: &str = "semibold";
/// Name of the medium font family.
const FAMILY_MEDIUM: &str = "medium";

/// Font family of semi-bold text (headings, brand, buttons).
pub fn semibold() -> FontFamily {
    FontFamily::Name(FAMILY_SEMIBOLD.into())
}

/// Font family of medium-weight text (list rows, button labels).
pub fn medium() -> FontFamily {
    FontFamily::Name(FAMILY_MEDIUM.into())
}

/// Returns `first` followed by the `rest` fallback fonts.
fn _with_fallback(first: &str, rest: &[String]) -> Vec<String> {
    let mut v = vec![first.to_owned()];
    v.extend(rest.iter().cloned());
    v
}

/// Registers IBM Plex Sans (regular, medium, semi-bold) and Plex Mono. The
/// egui default fonts stay as fallback, so symbols still render.
fn _install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let faces: [(&str, &'static [u8]); 4] = [
        (
            "plex-sans",
            include_bytes!("../../assets/fonts/IBMPlexSans-Regular.ttf"),
        ),
        (
            "plex-sans-medium",
            include_bytes!("../../assets/fonts/IBMPlexSans-Medium.ttf"),
        ),
        (
            "plex-sans-semibold",
            include_bytes!("../../assets/fonts/IBMPlexSans-SemiBold.ttf"),
        ),
        (
            "plex-mono",
            include_bytes!("../../assets/fonts/IBMPlexMono-Regular.ttf"),
        ),
    ];
    for (name, data) in faces {
        fonts
            .font_data
            .insert(name.to_owned(), Arc::new(FontData::from_static(data)));
    }
    let fallback = fonts.families[&FontFamily::Proportional].clone();
    let mono_fallback = fonts.families[&FontFamily::Monospace].clone();
    let families = [
        (
            FontFamily::Proportional,
            _with_fallback("plex-sans", &fallback),
        ),
        (
            FontFamily::Monospace,
            _with_fallback("plex-mono", &mono_fallback),
        ),
        (semibold(), _with_fallback("plex-sans-semibold", &fallback)),
        (medium(), _with_fallback("plex-sans-medium", &fallback)),
    ];
    for (family, list) in families {
        fonts.families.insert(family, list);
    }
    ctx.set_fonts(fonts);
}

/// Builds the dark Obsidian visuals.
fn _visuals() -> egui::Visuals {
    let mut v = egui::Visuals::dark();
    v.panel_fill = DEEP_DARK;
    v.window_fill = SURFACE;
    v.extreme_bg_color = INPUT_FILL;
    v.text_edit_bg_color = Some(INPUT_FILL);
    v.faint_bg_color = FIELD_ROW_BG;
    v.code_bg_color = INPUT_FILL;
    v.hyperlink_color = SECONDARY;
    v.warn_fg_color = TERTIARY;
    v.error_fg_color = ERROR;
    v.override_text_color = Some(TEXT);
    v.selection.bg_fill = PRIMARY.gamma_multiply(0.35);
    v.selection.stroke = Stroke::new(1.0_f32, SECONDARY);
    v.window_corner_radius = CornerRadius::same(RADIUS_WINDOW);
    v.menu_corner_radius = CornerRadius::same(RADIUS_WINDOW);
    v.window_stroke = Stroke::new(1.0_f32, FIELD_ROW_BORDER);
    v.window_shadow = egui::Shadow {
        offset: [0, 12],
        blur: 32,
        spread: 0,
        color: Color32::from_black_alpha(160),
    };
    v.popup_shadow = v.window_shadow;
    v.striped = false;
    _widget_visuals(&mut v.widgets);
    v
}

/// Flat buttons with a hairline border and an accent border on hover.
fn _widget_visuals(w: &mut egui::style::Widgets) {
    let r = CornerRadius::same(RADIUS_CTRL);
    for s in [
        &mut w.noninteractive,
        &mut w.inactive,
        &mut w.hovered,
        &mut w.active,
        &mut w.open,
    ] {
        s.corner_radius = r;
        s.expansion = 0.0;
    }
    w.noninteractive.bg_fill = FIELD_ROW_BG;
    w.noninteractive.bg_stroke = Stroke::new(1.0_f32, FIELD_ROW_BORDER);
    w.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    w.inactive.bg_fill = FIELD_ROW_BG;
    w.inactive.weak_bg_fill = FIELD_ROW_BG;
    w.inactive.bg_stroke = Stroke::new(1.0_f32, BUTTON_BORDER);
    w.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    w.hovered.bg_fill = INPUT_FILL_BLUE;
    w.hovered.weak_bg_fill = INPUT_FILL_BLUE;
    w.hovered.bg_stroke = Stroke::new(1.0_f32, PRIMARY);
    w.hovered.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    w.active.bg_fill = PRIMARY.gamma_multiply(0.30);
    w.active.weak_bg_fill = PRIMARY.gamma_multiply(0.30);
    w.active.bg_stroke = Stroke::new(1.0_f32, SECONDARY);
    w.active.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    w.open.bg_fill = INPUT_FILL_BLUE;
    w.open.weak_bg_fill = INPUT_FILL_BLUE;
    w.open.bg_stroke = Stroke::new(1.0_f32, PRIMARY);
}

/// Spacing and text styles of the Obsidian design.
fn _style(s: &mut egui::Style) {
    s.spacing.item_spacing = egui::vec2(8.0, 8.0);
    s.spacing.button_padding = egui::vec2(14.0, 6.0);
    s.spacing.interact_size.y = 32.0;
    s.spacing.menu_margin = egui::Margin::same(6);
    s.spacing.scroll = egui::style::ScrollStyle::floating();
    s.interaction.selectable_labels = false;
    s.text_styles = [
        (TextStyle::Heading, FontId::new(22.0, semibold())),
        (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(13.5, medium())),
        (
            TextStyle::Small,
            FontId::new(12.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Monospace,
            FontId::new(14.0, FontFamily::Monospace),
        ),
    ]
    .into();
}

/// Installs fonts, colours, radii and spacing on `ctx` (dark only).
pub fn apply(ctx: &egui::Context) {
    _install_fonts(ctx);
    ctx.set_theme(egui::Theme::Dark);
    ctx.set_visuals_of(egui::Theme::Dark, _visuals());
    ctx.style_mut_of(egui::Theme::Dark, _style);
}

/// WCAG 2.1 relative luminance of an sRGB colour.
pub fn relative_luminance(c: Color32) -> f64 {
    let channel = |v: u8| {
        let s = f64::from(v) / 255.0;
        if s <= 0.040_45 {
            return s / 12.92;
        }
        ((s + 0.055) / 1.055).powf(2.4)
    };
    0.2126 * channel(c.r()) + 0.7152 * channel(c.g()) + 0.0722 * channel(c.b())
}

/// WCAG 2.1 contrast ratio between two opaque colours (1.0 to 21.0).
pub fn contrast_ratio(a: Color32, b: Color32) -> f64 {
    let (la, lb) = (relative_luminance(a), relative_luminance(b));
    let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimum contrast of body text (WCAG AA).
    const MIN_TEXT: f64 = 4.5;
    /// Minimum contrast of icons and meaningful graphics (WCAG AA, non-text).
    const MIN_GRAPHIC: f64 = 3.0;
    /// Backgrounds that carry text.
    const BACKGROUNDS: [(&str, Color32); 6] = [
        ("DEEP_DARK", DEEP_DARK),
        ("NAVY_DARK", NAVY_DARK),
        ("FIELD_ROW_BG", FIELD_ROW_BG),
        ("SURFACE", SURFACE),
        ("INPUT_FILL", INPUT_FILL),
        ("INPUT_FILL_BLUE", INPUT_FILL_BLUE),
    ];
    /// Text colours used on those backgrounds.
    const TEXTS: [(&str, Color32); 7] = [
        ("TEXT", TEXT),
        ("MUTED", MUTED),
        ("LABEL", LABEL),
        ("SECONDARY", SECONDARY),
        ("TERTIARY", TERTIARY),
        ("ERROR", ERROR),
        ("OK", OK),
    ];

    /// Known reference values: black on white is 21:1, equal colours 1:1.
    #[test]
    fn contrast_reference_values() {
        let r = contrast_ratio(Color32::BLACK, Color32::WHITE);
        assert!((r - 21.0).abs() < 1e-9, "{r}");
        assert!((contrast_ratio(PRIMARY, PRIMARY) - 1.0).abs() < 1e-9);
    }

    /// Every text/background pair in use meets WCAG AA (4.5:1), icons 3:1.
    #[test]
    fn wcag_contrast() {
        let mut failures = Vec::new();
        for (bn, bg) in BACKGROUNDS {
            for (tn, fg) in TEXTS {
                let r = contrast_ratio(fg, bg);
                if r < MIN_TEXT {
                    failures.push(format!("{tn} on {bn}: {r:.2}"));
                }
            }
            let r = contrast_ratio(LABEL, bg);
            if r < MIN_GRAPHIC {
                failures.push(format!("LABEL glyph on {bn}: {r:.2}"));
            }
        }
        for (n, bg) in [("PRIMARY", PRIMARY), ("PRIMARY_ACTIVE", PRIMARY_ACTIVE)] {
            let r = contrast_ratio(ON_ACCENT, bg);
            if r < MIN_TEXT {
                failures.push(format!("ON_ACCENT on {n}: {r:.2}"));
            }
        }
        assert!(failures.is_empty(), "contrast failures: {failures:#?}");
    }
}
