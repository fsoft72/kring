//! kring desktop application entry point.

use eframe::egui;
use kring::app::{DevPreset, KringApp};
use kring::startup::{self, Connected};
use kring::ui::theme;
use kring::worker::{self, WorkerConfig};

/// Initial window size.
const WINDOW_SIZE: [f32; 2] = [1280.0, 800.0];
/// Minimum window size.
const WINDOW_MIN_SIZE: [f32; 2] = [960.0, 600.0];
/// Set only inside the isolated dev/it sessions; gates the dev preset.
const ENV_IT_RUNTIME: &str = "KRING_IT_RUNTIME";

/// Reads the screenshot preset (`KRING_DEV_SELECT`, `KRING_DEV_EXPAND`,
/// `KRING_DEV_REVEAL`, `KRING_DEV_DIALOG`), only inside the isolated session.
fn _dev_preset() -> DevPreset {
    if std::env::var_os(ENV_IT_RUNTIME).is_none() {
        return DevPreset::default();
    }
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    DevPreset {
        select: var("KRING_DEV_SELECT"),
        expand: var("KRING_DEV_EXPAND").and_then(|v| v.parse().ok()),
        reveal: var("KRING_DEV_REVEAL").is_some(),
        dialog: var("KRING_DEV_DIALOG"),
    }
}

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
            let app = KringApp::new(handle).with_dev_preset(_dev_preset());
            Ok(Box::new(app))
        }),
    )
}
