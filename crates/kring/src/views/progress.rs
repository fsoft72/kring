//! Progress modal of the destructive operation in flight, and the
//! confirmation that forgets the remembered passphrase.

use eframe::egui::{self, RichText};

use crate::operation::{Operation, Step, StepStatus};
use crate::session_secret::{MSG_FORGET_QUESTION, MSG_REMEMBER_WARNING};
use crate::ui::theme;
use crate::ui::widgets::{danger_button, primary_button, secondary_button, semibold};
use crate::views::dialogs::styled_modal;

/// Id of the progress modal.
const PROGRESS_ID: &str = "kring-progress";
/// Id of the forget confirmation.
const FORGET_ID: &str = "kring-forget-passphrase";
/// Width of the modal content.
const PROGRESS_WIDTH: f32 = 440.0;
/// Size of the modal title.
const TITLE_SIZE: f32 = 18.0;
/// Side of the step marker (spinner or dot).
const MARKER_SIZE: f32 = 14.0;
/// Radius of the step dot.
const DOT_RADIUS: f32 = 4.0;
/// Tooltip of Close while the operation runs.
const MSG_STILL_RUNNING: &str = "Available once the operation finished";

/// Returns the colour of a step text.
fn _color(status: StepStatus) -> egui::Color32 {
    match status {
        StepStatus::Running => theme::TEXT,
        StepStatus::Ok => theme::OK,
        StepStatus::Failed => theme::ERROR,
        StepStatus::Skipped => theme::MUTED,
    }
}

/// Renders one step: a spinner while it runs, a coloured dot afterwards.
fn _step(ui: &mut egui::Ui, step: &Step) {
    ui.horizontal(|ui| {
        let size = egui::vec2(MARKER_SIZE, MARKER_SIZE);
        if step.status == StepStatus::Running {
            ui.add_sized(
                size,
                egui::Spinner::new()
                    .size(MARKER_SIZE)
                    .color(theme::SECONDARY),
            );
        } else {
            let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
            ui.painter()
                .circle_filled(rect.center(), DOT_RADIUS, _color(step.status));
        }
        ui.add(egui::Label::new(RichText::new(&step.text).color(_color(step.status))).wrap());
    });
}

/// Shows the progress modal (it cannot be dismissed while running);
/// returns true when Close was clicked.
pub fn show(ctx: &egui::Context, op: &Operation) -> bool {
    let mut close = false;
    // Escape and backdrop clicks are ignored: only Close (once finished) ends it.
    let _ = styled_modal(ctx, PROGRESS_ID).show(ctx, |ui| {
        ui.set_width(PROGRESS_WIDTH);
        ui.label(semibold(op.title(), TITLE_SIZE));
        ui.add_space(8.0);
        for step in op.steps() {
            _step(ui, step);
        }
        ui.add_space(12.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let blocked = (!op.is_finished()).then_some(MSG_STILL_RUNNING);
            close = primary_button(ui, "Close", blocked);
        });
    });
    if !op.is_finished() {
        ctx.request_repaint();
    }
    close
}

/// Shows the confirmation that forgets the remembered passphrase; returns
/// `Some(true)` to forget, `Some(false)` when cancelled, `None` while open.
pub fn confirm_forget(ctx: &egui::Context) -> Option<bool> {
    let mut answer = None;
    let response = styled_modal(ctx, FORGET_ID).show(ctx, |ui| {
        ui.set_width(PROGRESS_WIDTH);
        ui.label(semibold(MSG_FORGET_QUESTION, TITLE_SIZE));
        ui.add_space(4.0);
        ui.label(RichText::new(MSG_REMEMBER_WARNING).color(theme::TERTIARY));
        ui.label(
            RichText::new("Passphrase requests will open their dialog again.")
                .color(theme::MUTED)
                .size(12.5),
        );
        ui.add_space(8.0);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if danger_button(ui, "Forget", None) {
                answer = Some(true);
            }
            if secondary_button(ui, "Cancel", None) {
                answer = Some(false);
            }
        });
    });
    if answer.is_none() && response.should_close() {
        return Some(false);
    }
    answer
}
