//! The main window: wires worker events, views, dialogs, toasts and the clipboard.

use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};

use eframe::egui;

use crate::app_state::AppState;
use crate::clipboard::ArboardClipboard;
use crate::copy_flow::SecretCopier;
use crate::ui::theme;
use crate::ui::toasts::{ToastKind, Toasts, kind_for_status};
use crate::views::dialogs::{Dialog, DialogKind, Outcome};
use crate::views::item_detail::AttrEditor;
use crate::views::rail::WorkerActivity;
use crate::views::{Action, Gates, banners, collection, rail, sidebar};
use crate::worker::{Command, Event, WorkerHandle};

/// Repaint interval while a copied secret waits to be cleared.
const CLIPBOARD_REPAINT: Duration = Duration::from_secs(1);
/// Width of the nav rail.
const RAIL_WIDTH: f32 = 64.0;
/// Default width of the keyring list.
const LIST_WIDTH: f32 = 340.0;
/// Minimum width of the keyring list.
const LIST_MIN_WIDTH: f32 = 280.0;
/// Maximum width of the keyring list.
const LIST_MAX_WIDTH: f32 = 520.0;
/// Reading width cap of the detail pane.
const DETAIL_MAX_WIDTH: f32 = 860.0;
/// Horizontal margin of the detail pane.
const DETAIL_MARGIN_X: i8 = 28;
/// Vertical margin of the detail pane.
const DETAIL_MARGIN_Y: i8 = 22;

/// Initial state requested for screenshots, honoured only inside the
/// isolated dev session (see `main.rs`).
#[derive(Debug, Default, Clone)]
pub struct DevPreset {
    /// Display name of the keyring to select first.
    pub select: Option<String>,
    /// Index of the item to expand once items are loaded.
    pub expand: Option<usize>,
    /// Reveal the expanded item's secret.
    pub reveal: bool,
    /// Dialog to open at start: `new-keyring` or `unlock`.
    pub dialog: Option<String>,
}

/// The kring application.
pub struct KringApp {
    state: AppState,
    worker: WorkerHandle,
    worker_stopped: bool,
    /// True from sending a command until the next event arrives.
    awaiting_reply: bool,
    copier: SecretCopier<ArboardClipboard>,
    dialog: Option<Dialog>,
    editor: AttrEditor,
    /// Item search text.
    filter: String,
    /// Keyring search text.
    keyring_filter: String,
    toasts: Toasts,
    dev: DevPreset,
}

impl KringApp {
    /// Creates the application over a running worker.
    pub fn new(worker: WorkerHandle) -> Self {
        Self {
            state: AppState::default(),
            worker,
            worker_stopped: false,
            awaiting_reply: false,
            copier: SecretCopier::new(ArboardClipboard::new()),
            dialog: None,
            editor: AttrEditor::default(),
            filter: String::new(),
            keyring_filter: String::new(),
            toasts: Toasts::default(),
            dev: DevPreset::default(),
        }
    }

    /// Applies a dev preset (screenshots in the isolated dev session only).
    pub fn with_dev_preset(mut self, dev: DevPreset) -> Self {
        self.dev = dev;
        self
    }

    /// Applies every pending worker event; marks the worker stopped when disconnected.
    fn _drain_events(&mut self) {
        loop {
            match self.worker.rx.try_recv() {
                Ok(event) => {
                    self.awaiting_reply = false;
                    if matches!(event, Event::Error(_)) {
                        self.copier.cancel();
                    }
                    self.state.apply(event);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.worker_stopped = true;
                    break;
                }
            }
        }
    }

    /// Moves new status and error messages from the state into toasts.
    fn _feed_toasts(&mut self) {
        let now = Instant::now();
        let (status, errors) = self.state.drain_messages();
        if let Some(status) = status {
            self.toasts.push(kind_for_status(&status), status, now);
        }
        for e in errors {
            self.toasts.push(ToastKind::Error, e, now);
        }
    }

    /// Sends a command to the worker.
    fn _send(&mut self, cmd: Command) {
        if self.worker.tx.send(cmd).is_err() {
            self.worker_stopped = true;
            return;
        }
        self.awaiting_reply = true;
    }

    /// Executes an action requested by a view.
    fn _handle(&mut self, action: Action) {
        match action {
            Action::Send(cmd) => self._send(cmd),
            Action::SelectCollection(id) => {
                self.state.select_collection(id.clone());
                self.copier.cancel();
                self._send(Command::LoadItems(id));
            }
            Action::SelectItem(id) => {
                self.state.select_item(id);
                self.copier.cancel();
            }
            Action::DeselectItem => {
                self.state.selected_item = None;
                self.state.hide_secret();
                self.copier.cancel();
            }
            Action::HideSecret => self.state.hide_secret(),
            Action::CopySecret => {
                if let Some(cmd) = self.copier.request(&mut self.state) {
                    self._send(cmd);
                }
            }
            Action::Open(kind) => self.dialog = Some(Dialog::new(kind)),
        }
    }

    /// Drops a revealed secret whose item is now locked.
    fn _hide_locked_secret(&mut self) {
        let Some((id, _)) = &self.state.revealed else {
            return;
        };
        let locked = self.state.items.iter().any(|i| &i.id == id && i.locked);
        if locked {
            self.state.hide_secret();
        }
    }

    /// Selects the first collection (or the dev preset one) when nothing is selected.
    fn _auto_select(&mut self) {
        if self.state.selected.is_some() || self.worker_stopped {
            return;
        }
        let wanted = self.dev.select.as_deref();
        let preset = self
            .state
            .collections
            .iter()
            .find(|c| wanted == Some(collection::display_name(c).as_str()));
        let Some(first) = preset.or(self.state.collections.first()) else {
            return;
        };
        let id = first.id.clone();
        self._handle(Action::SelectCollection(id));
    }

    /// Applies the dev preset item expansion and dialog once their data exists.
    fn _apply_dev_preset(&mut self) {
        if let Some(index) = self.dev.expand
            && let Some(item) = self.state.items.get(index)
        {
            self.dev.expand = None;
            let id = item.id.clone();
            self._handle(Action::SelectItem(id.clone()));
            if self.dev.reveal {
                self._send(Command::RevealSecret(id));
            }
        }
        let Some(name) = self.dev.dialog.clone() else {
            return;
        };
        let locked = self.state.collections.iter().find(|c| c.locked);
        let kind = match (name.as_str(), locked) {
            ("new-keyring", _) => DialogKind::create_collection(),
            ("unlock", Some(c)) => DialogKind::unlock(c.id.clone(), collection::display_name(c)),
            _ => return,
        };
        self.dev.dialog = None;
        self.dialog = Some(Dialog::new(kind));
    }

    /// Opens the passphrase dialog when the worker asked for one.
    fn _open_passphrase_dialog(&mut self) {
        if self.dialog.is_some() {
            return;
        }
        let Some(cmd) = self.state.pending_passphrase.take() else {
            return;
        };
        self.dialog = Some(Dialog::new(DialogKind::passphrase(cmd)));
    }

    /// Shows the open dialog and handles its outcome.
    fn _dialog(&mut self, ctx: &egui::Context) {
        let Some(dialog) = &mut self.dialog else {
            return;
        };
        match dialog.show(ctx) {
            Outcome::Open => {}
            Outcome::Cancelled => self.dialog = None,
            Outcome::Submitted(cmd) => {
                self.dialog = None;
                self._send(cmd);
            }
        }
    }

    /// Renders the rail, the keyring list and the detail pane; returns the action.
    fn _panels(&mut self, ui: &mut egui::Ui, gates: Gates) -> Option<Action> {
        let mut action = None;
        let activity = WorkerActivity::from_flags(self.worker_stopped, self.awaiting_reply);
        egui::Panel::left("kring-rail")
            .exact_size(RAIL_WIDTH)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(theme::NAVY_DARK)
                    .stroke(egui::Stroke::new(1.0_f32, theme::FIELD_ROW_BORDER))
                    .inner_margin(egui::Margin::symmetric(8, 10)),
            )
            .show(ui, |ui| rail::show(ui, activity));
        egui::Panel::left("kring-keyrings")
            .resizable(true)
            .default_size(LIST_WIDTH)
            .size_range(LIST_MIN_WIDTH..=LIST_MAX_WIDTH)
            .frame(
                egui::Frame::new()
                    .fill(theme::DEEP_DARK)
                    .stroke(egui::Stroke::new(1.0_f32, theme::FIELD_ROW_BORDER))
                    .inner_margin(egui::Margin::same(12)),
            )
            .show(ui, |ui| {
                action = sidebar::show(ui, &self.state, &mut self.keyring_filter, gates);
            });
        let frame = egui::Frame::new()
            .fill(theme::DEEP_DARK)
            .inner_margin(egui::Margin::symmetric(DETAIL_MARGIN_X, DETAIL_MARGIN_Y));
        egui::CentralPanel::default().frame(frame).show(ui, |ui| {
            let full = ui.max_rect();
            let width = full.width().min(DETAIL_MAX_WIDTH);
            let col = egui::Rect::from_min_size(full.min, egui::vec2(width, full.height()));
            ui.scope_builder(egui::UiBuilder::new().max_rect(col), |ui| {
                banners::show(ui, &self.state, self.worker_stopped);
                let found =
                    collection::show(ui, &self.state, &mut self.filter, &mut self.editor, gates);
                action = found.or(action.take());
            });
        });
        action
    }
}

impl eframe::App for KringApp {
    /// Applies worker events, renders the window and runs the requested action.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self._drain_events();
        self.copier.finish(&mut self.state);
        self._hide_locked_secret();
        self._auto_select();
        self._apply_dev_preset();
        if self.copier.tick(Instant::now()) {
            ctx.request_repaint_after(CLIPBOARD_REPAINT);
        }
        self._open_passphrase_dialog();
        let gates = Gates::from_provider(self.state.provider.as_ref());
        let action = self._panels(ui, gates);
        self._dialog(&ctx);
        if let Some(action) = action {
            self._handle(action);
        }
        self._feed_toasts();
        self.toasts.draw(&ctx);
    }
}
