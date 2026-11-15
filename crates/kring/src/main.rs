//! kring desktop application entry point.

use eframe::egui;
use kring::app::KringApp;
use kring::startup::{self, Connected};
use kring::ui::theme;
use kring::worker::{self, WorkerConfig};

/// Initial window size.
const WINDOW_SIZE: [f32; 2] = [1280.0, 800.0];
/// Minimum window size.
const WINDOW_MIN_SIZE: [f32; 2] = [960.0, 600.0];

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
        viewport: egui::ViewportBuilder::default()
            .with_title("kring")
            .with_inner_size(WINDOW_SIZE)
            .with_min_inner_size(WINDOW_MIN_SIZE),
        // Return from `run_native` instead of `process::exit`, so `KringApp` is
        // dropped and its clipboard guard clears a still pending copied secret.
        run_and_return: true,
        ..Default::default()
    };
    eframe::run_native(
        "kring",
        options,
        Box::new(move |cc| {
            theme::apply(&cc.egui_ctx);
            let ctx = cc.egui_ctx.clone();
            let notify = move || ctx.request_repaint();
            let handle = worker::spawn(store, provider, WorkerConfig::default_paths(), notify);
            let app = KringApp::new(handle);
            // Screenshot presets exist only in debug builds and only inside
            // the isolated dev session (checked by `dev_preset::from_env`).
            #[cfg(debug_assertions)]
            let app = app.with_dev_preset(kring::dev_preset::from_env());
            Ok(Box::new(app))
        }),
    )
}
