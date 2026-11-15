//! kring application library: background worker, UI state and egui views.

pub mod app;
pub mod app_state;
pub mod clipboard;
pub mod copy_flow;
#[cfg(debug_assertions)]
pub mod dev_preset;
pub mod local_time;
pub mod secret_display;
pub mod startup;
pub mod ui;
pub mod views;
pub mod worker;
mod worker_offline;
