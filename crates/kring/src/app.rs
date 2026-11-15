//! The main window: wires worker events, views, dialogs and the clipboard.

use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};

use eframe::egui;

use crate::app_state::AppState;
use crate::clipboard::ArboardClipboard;
use crate::copy_flow::SecretCopier;
use crate::views::dialogs::{Dialog, DialogKind, Outcome};
use crate::views::item_detail::AttrEditor;
use crate::views::{Action, Gates, collection, item_detail, sidebar};
use crate::worker::{Command, Event, WorkerHandle};

/// Repaint interval while a copied secret waits to be cleared.
const CLIPBOARD_REPAINT: Duration = Duration::from_secs(1);
/// Banner shown when the worker thread is gone.
const MSG_WORKER_STOPPED: &str = "Background worker stopped, restart kring";
/// Banner shown when no provider owns the Secret Service name.
const MSG_NO_PROVIDER: &str = "No Secret Service provider running";
/// Default width of the sidebar.
const SIDEBAR_WIDTH: f32 = 200.0;

/// Returns the status bar summary of the collections.
pub fn status_line(state: &AppState) -> String {
    let locked = state.collections.iter().filter(|c| c.locked).count();
    format!("{} collections, {locked} locked", state.collections.len())
}

/// Returns the worker state shown in the status bar.
pub fn worker_label(stopped: bool, awaiting_reply: bool) -> &'static str {
    if stopped {
        return "worker: stopped";
    }
    if awaiting_reply {
        return "worker: busy";
    }
    "worker: idle"
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
    filter: String,
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
        }
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

    /// Selects the first collection when nothing is selected.
    fn _auto_select(&mut self) {
        if self.state.selected.is_some() || self.worker_stopped {
            return;
        }
        let Some(first) = self.state.collections.first() else {
            return;
        };
        let id = first.id.clone();
        self._handle(Action::SelectCollection(id));
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

    /// Renders the title, search field and banners.
    fn _top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("kring");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("search"));
            });
        });
        let error = ui.visuals().error_fg_color;
        let warn = ui.visuals().warn_fg_color;
        if self.worker_stopped {
            ui.colored_label(error, MSG_WORKER_STOPPED);
        }
        if self.state.provider_unavailable {
            ui.colored_label(error, MSG_NO_PROVIDER);
        }
        let competitors = self.state.provider.as_ref().map(|p| &p.competitors);
        if let Some(list) = competitors.filter(|l| !l.is_empty()) {
            let names = list.join(", ");
            let text = format!("Other services may claim org.freedesktop.secrets: {names}");
            ui.colored_label(warn, text);
        }
    }

    /// Renders the status bar.
    fn _status_bar(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(format!("status: {}", status_line(&self.state)));
            ui.weak(&self.state.status);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(worker_label(self.worker_stopped, self.awaiting_reply));
            });
        });
    }

    /// Renders the latest error with a dismiss button.
    fn _errors(&mut self, ui: &mut egui::Ui) {
        let Some(last) = self.state.errors.last() else {
            return;
        };
        let count = self.state.errors.len();
        let text = if count > 1 {
            format!("{last} (+{} more)", count - 1)
        } else {
            last.clone()
        };
        let mut dismiss = false;
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(ui.visuals().error_fg_color, text);
            dismiss = ui.small_button("Dismiss").clicked();
        });
        if dismiss {
            self.state.errors.clear();
        }
        ui.separator();
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
}

impl eframe::App for KringApp {
    /// Applies worker events, renders the window and runs the requested action.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self._drain_events();
        self.copier.finish(&mut self.state);
        self._hide_locked_secret();
        self._auto_select();
        if self.copier.tick(Instant::now()) {
            ctx.request_repaint_after(CLIPBOARD_REPAINT);
        }
        self._open_passphrase_dialog();
        let gates = Gates::from_provider(self.state.provider.as_ref());
        let mut action = None;
        egui::Panel::top("kring-top").show(ui, |ui| self._top_bar(ui));
        egui::Panel::bottom("kring-status").show(ui, |ui| self._status_bar(ui));
        egui::Panel::left("kring-sidebar")
            .resizable(true)
            .default_size(SIDEBAR_WIDTH)
            .show(ui, |ui| action = sidebar::show(ui, &self.state, gates));
        egui::CentralPanel::default().show(ui, |ui| {
            self._errors(ui);
            let found = collection::show(ui, &self.state, &self.filter, gates);
            action = found.or(action.take());
            ui.separator();
            let found = item_detail::show(ui, &self.state, &mut self.editor, gates);
            action = found.or(action.take());
        });
        self._dialog(&ctx);
        if let Some(action) = action {
            self._handle(action);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kring_core::model::{CollectionId, CollectionInfo};

    /// Builds a collection with the given lock state.
    fn col(path: &str, locked: bool) -> CollectionInfo {
        CollectionInfo {
            id: CollectionId(path.into()),
            label: path.into(),
            locked,
            item_count: 0,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        }
    }

    /// The status line counts collections and locked ones.
    #[test]
    fn status_counts_locked() {
        let mut s = AppState::default();
        s.apply(Event::Collections(vec![
            col("/c/a", true),
            col("/c/b", false),
            col("/c/c", true),
        ]));
        assert_eq!(status_line(&s), "3 collections, 2 locked");
    }

    /// The worker label prefers stopped over busy over idle.
    #[test]
    fn worker_label_states() {
        assert_eq!(worker_label(true, true), "worker: stopped");
        assert_eq!(worker_label(false, true), "worker: busy");
        assert_eq!(worker_label(false, false), "worker: idle");
    }
}
