//! kring desktop application entry point.

use eframe::egui;

/// Empty application state.
struct KringApp;

impl eframe::App for KringApp {
    /// Renders nothing: the window is intentionally empty for now.
    fn ui(&mut self, _ui: &mut egui::Ui, _frame: &mut eframe::Frame) {}
}

/// Opens the main window titled `kring`.
fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "kring",
        options,
        Box::new(|_cc| Ok(Box::new(KringApp))),
    )
}
