//! Paranoid-style toasts: bottom-right cards with a coloured bar that replace
//! the old status bar. Fed from `AppState` status and error messages.

use std::time::{Duration, Instant};

use eframe::egui::{self, Align2, CornerRadius, RichText, Sense, Stroke};

use crate::ui::theme;

/// Lifetime of info and success toasts.
const TOAST_TTL: Duration = Duration::from_secs(4);
/// Lifetime of error toasts.
const ERROR_TTL: Duration = Duration::from_secs(8);
/// Most toasts shown at once (oldest dropped first).
const MAX_TOASTS: usize = 5;
/// Maximum width of a toast.
const TOAST_WIDTH: f32 = 360.0;
/// Distance of the stack from the window corner.
const TOAST_OFFSET: f32 = 16.0;
/// Status prefixes reported as information rather than success.
const INFO_PREFIXES: [&str; 2] = ["Copied", "Backup"];
/// `KringError` category prefixes hidden from the user (the inner message stays).
const ERROR_PREFIXES: [&str; 2] = ["invalid input: ", "unsupported: "];

/// Severity of a toast; selects the colour of its bar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToastKind {
    /// Neutral information (SECONDARY bar).
    Info,
    /// Success (OK bar).
    Ok,
    /// Failure (ERROR bar, shown longer).
    Error,
}

/// One message with its expiry time.
#[derive(Debug)]
pub struct Toast {
    /// Message shown.
    pub text: String,
    /// Severity (bar colour and lifetime).
    pub kind: ToastKind,
    /// When the toast disappears.
    pub until: Instant,
}

/// Queue of visible toasts.
#[derive(Debug, Default)]
pub struct Toasts(pub Vec<Toast>);

/// Classifies a status message: copies and backups are info, the rest success.
pub fn kind_for_status(status: &str) -> ToastKind {
    if INFO_PREFIXES.iter().any(|p| status.starts_with(p)) {
        return ToastKind::Info;
    }
    ToastKind::Ok
}

/// Returns the user-facing part of an error message: the inner message
/// without a `KringError` category prefix such as `invalid input: `.
pub fn user_message(raw: &str) -> &str {
    ERROR_PREFIXES
        .iter()
        .find_map(|p| raw.strip_prefix(p))
        .unwrap_or(raw)
}

impl Toasts {
    /// Adds a toast shown from `now`; errors stay longer.
    pub fn push(&mut self, kind: ToastKind, text: impl Into<String>, now: Instant) {
        let ttl = if kind == ToastKind::Error {
            ERROR_TTL
        } else {
            TOAST_TTL
        };
        self.0.push(Toast {
            text: text.into(),
            kind,
            until: now + ttl,
        });
        let excess = self.0.len().saturating_sub(MAX_TOASTS);
        self.0.drain(..excess);
    }

    /// Drops expired toasts.
    pub fn expire(&mut self, now: Instant) {
        self.0.retain(|t| t.until > now);
    }

    /// Draws the live toasts in the bottom-right corner.
    pub fn draw(&mut self, ctx: &egui::Context) {
        self.expire(Instant::now());
        if self.0.is_empty() {
            return;
        }
        egui::Area::new(egui::Id::unique("kring-toasts"))
            .anchor(Align2::RIGHT_BOTTOM, [-TOAST_OFFSET, -TOAST_OFFSET])
            .order(egui::Order::Foreground)
            .interactable(false)
            .show(ctx, |ui| {
                for t in &self.0 {
                    _toast(ui, t);
                }
            });
        ctx.request_repaint_after(Duration::from_millis(250));
    }
}

/// Draws one toast card.
fn _toast(ui: &mut egui::Ui, t: &Toast) {
    let color = match t.kind {
        ToastKind::Ok => theme::OK,
        ToastKind::Error => theme::ERROR,
        ToastKind::Info => theme::SECONDARY,
    };
    egui::Frame::new()
        .fill(theme::SURFACE)
        .stroke(Stroke::new(1.0_f32, theme::FIELD_ROW_BORDER))
        .corner_radius(CornerRadius::same(theme::RADIUS_WINDOW))
        .shadow(egui::Shadow {
            offset: [0, 6],
            blur: 18,
            spread: 0,
            color: egui::Color32::from_black_alpha(140),
        })
        .inner_margin(egui::Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_max_width(TOAST_WIDTH);
            ui.horizontal(|ui| {
                let (bar, _) = ui.allocate_exact_size(egui::vec2(3.0, 18.0), Sense::hover());
                ui.painter().rect_filled(bar, CornerRadius::same(1), color);
                ui.add(egui::Label::new(RichText::new(&t.text).color(theme::TEXT)).wrap());
            });
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Copies and backups are info; other status messages are success.
    #[test]
    fn status_kinds() {
        assert_eq!(
            kind_for_status("Copied, clipboard clears in 30 s"),
            ToastKind::Info
        );
        assert_eq!(kind_for_status("Backup created: /x"), ToastKind::Info);
        assert_eq!(kind_for_status("Collection renamed"), ToastKind::Ok);
    }

    /// Category prefixes are stripped once; other messages are unchanged.
    #[test]
    fn user_message_strips_category() {
        assert_eq!(
            user_message("invalid input: Wrong password for a.keyring"),
            "Wrong password for a.keyring"
        );
        assert_eq!(
            user_message("unsupported: Not supported on this provider"),
            "Not supported on this provider"
        );
        assert_eq!(
            user_message("No Secret Service provider running"),
            "No Secret Service provider running"
        );
        assert_eq!(user_message("locked: /c/a"), "locked: /c/a");
        assert_eq!(
            user_message("Backup failed: invalid input: x"),
            "Backup failed: invalid input: x"
        );
    }

    /// Errors outlive other toasts; expired toasts are dropped.
    #[test]
    fn errors_last_longer() {
        let now = Instant::now();
        let mut t = Toasts::default();
        t.push(ToastKind::Ok, "ok", now);
        t.push(ToastKind::Error, "bad", now);
        t.expire(now + TOAST_TTL + Duration::from_millis(1));
        assert_eq!(t.0.len(), 1);
        assert_eq!(t.0[0].kind, ToastKind::Error);
        t.expire(now + ERROR_TTL + Duration::from_millis(1));
        assert!(t.0.is_empty());
    }

    /// The queue keeps only the newest toasts.
    #[test]
    fn queue_is_capped() {
        let now = Instant::now();
        let mut t = Toasts::default();
        for i in 0..MAX_TOASTS + 2 {
            t.push(ToastKind::Info, format!("m{i}"), now);
        }
        assert_eq!(t.0.len(), MAX_TOASTS);
        assert_eq!(t.0[0].text, "m2");
    }
}
