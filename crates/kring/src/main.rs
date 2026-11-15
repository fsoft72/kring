//! kring desktop application entry point.

use eframe::egui;
use kring::app::KringApp;
use kring::startup::{self, Connected};
use kring::worker::{self, WorkerConfig};

/// Initial window size.
const WINDOW_SIZE: [f32; 2] = [1000.0, 680.0];

/// Connects to the Secret Service, starts the worker and opens the window.
fn main() -> eframe::Result<()> {
    let Connected {
        runtime: _bus_runtime,
        store,
        provider,
        error,
    } = startup::connect();
    match (&provider, &error) {
        (Some(p), _) => eprintln!("kring: Secret Service provider {:?}", p.kind),
        (None, Some(e)) => eprintln!("kring: Secret Service unavailable: {e}"),
        (None, None) => eprintln!("kring: Secret Service unavailable"),
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size(WINDOW_SIZE),
        ..Default::default()
    };
    eframe::run_native(
        "kring",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let notify = move || ctx.request_repaint();
            let handle = worker::spawn(store, provider, WorkerConfig::default_paths(), notify);
            Ok(Box::new(KringApp::new(handle)))
        }),
    )
}
