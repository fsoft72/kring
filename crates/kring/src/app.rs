//! The main window: wires worker events, views, dialogs, toasts and the clipboard.

use std::path::PathBuf;
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};

use eframe::egui;

use crate::app_state::AppState;
use crate::clipboard::ArboardClipboard;
use crate::copy_flow::SecretCopier;
#[cfg(debug_assertions)]
use crate::dev_preset::DevPreset;
use crate::ui::theme;
use crate::ui::toasts::{ToastKind, Toasts, kind_for_status, user_message};
use crate::views::backups::{self, BackupView};
use crate::views::dialogs::{Dialog, DialogKind, Outcome};
use crate::views::file_items::FileView;
use crate::views::item_detail::AttrEditor;
use crate::views::rail::WorkerActivity;
use crate::views::{
    Action, Area, Gates, banners, collection, file_detail, files_list, rail, sidebar, switch_area,
};
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
    /// Area selected in the rail.
    area: Area,
    /// Keyring file search text.
    files_filter: String,
    /// Card state of the selected keyring file (expanded card, shown secrets).
    file_view: FileView,
    /// Selected backup and the files checked for a restore.
    backup_view: BackupView,
    /// Keyrings directory, where restores write (same as the worker's).
    keyrings_dir: PathBuf,
    toasts: Toasts,
    /// Screenshot preset (debug builds, isolated session only).
    #[cfg(debug_assertions)]
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
            area: Area::default(),
            files_filter: String::new(),
            file_view: FileView::default(),
            backup_view: BackupView::default(),
            keyrings_dir: kring_core::paths::keyrings_dir(),
            toasts: Toasts::default(),
            #[cfg(debug_assertions)]
            dev: DevPreset::default(),
        }
    }

    /// Applies a dev preset (screenshots in the isolated dev session only).
    #[cfg(debug_assertions)]
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

    /// Moves new status messages, notices and errors from the state into toasts.
    fn _feed_toasts(&mut self) {
        let now = Instant::now();
        let (status, errors) = self.state.drain_messages();
        if let Some(status) = status {
            self.toasts.push(kind_for_status(&status), status, now);
        }
        for notice in self.state.drain_notices() {
            self.toasts.push(ToastKind::Info, notice, now);
        }
        for e in errors {
            self.toasts.push(ToastKind::Error, user_message(&e), now);
        }
    }

    /// Sends a command to the worker.
    fn _send(&mut self, cmd: Command) {
        self.state.track_file_command(&cmd);
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
            Action::SwitchArea(to) => {
                let cmds = switch_area(&mut self.state, self.area, to);
                self.area = to;
                for cmd in cmds {
                    self._send(cmd);
                }
            }
            Action::SelectFile(name) => {
                self.copier.cancel();
                let cmd = file_detail::select_command(&self.state, &name);
                self.state.select_file(name);
                if let Some(cmd) = cmd {
                    self._send(cmd);
                }
            }
            Action::CopyFileSecret(index) => {
                let item = self.state.file_items.get(index);
                let Some(secret) = item.filter(|i| !i.secret_missing).map(|i| i.secret.clone())
                else {
                    return;
                };
                self.copier.copy_value(&secret, &mut self.state);
            }
        }
    }

    /// Reloads the backup list after a backup or restore while it is shown.
    fn _reload_stale_backups(&mut self) {
        if !self.state.take_backups_stale() || self.area != Area::Backups {
            return;
        }
        for cmd in crate::views::backups_commands() {
            self._send(cmd);
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
        #[cfg(debug_assertions)]
        let preset = self.dev.preferred_collection(&self.state);
        #[cfg(not(debug_assertions))]
        let preset = None;
        let first = self.state.collections.first().map(|c| c.id.clone());
        let Some(id) = preset.or(first) else {
            return;
        };
        self._handle(Action::SelectCollection(id));
    }

    /// Runs the dev preset actions whose data has arrived.
    #[cfg(debug_assertions)]
    fn _apply_dev_preset(&mut self) {
        if let Some(area) = self.dev.take_area() {
            self._handle(Action::SwitchArea(area));
        }
        let actions = match self.area {
            Area::Secrets => self.dev.take_actions(&self.state, &self.filter),
            Area::Files => self.dev.take_file_actions(&self.state),
            Area::Backups => {
                self.dev
                    .take_backup_actions(&self.state, &mut self.backup_view, &self.keyrings_dir)
            }
        };
        for action in actions {
            self._handle(action);
        }
        if self.area != Area::Files {
            return;
        }
        if let Some((index, reveal)) = self.dev.take_file_card(&self.state) {
            self.file_view.sync(&self.state);
            self.file_view.toggle_expanded(index);
            if reveal {
                self.file_view.toggle_revealed(index);
            }
        }
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

    /// Opens the password dialog when the selected binary file asked for one.
    fn _open_file_password_dialog(&mut self) {
        if self.dialog.is_some() {
            return;
        }
        let Some((name, action)) = self.state.take_password_request() else {
            return;
        };
        self.dialog = Some(Dialog::new(DialogKind::file_password(name, action)));
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
            .show(ui, |ui| {
                if let Some(area) = rail::show(ui, activity, self.area) {
                    action = Some(Action::SwitchArea(area));
                }
            });
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
                let found = match self.area {
                    Area::Secrets => {
                        sidebar::show(ui, &self.state, &mut self.keyring_filter, gates)
                    }
                    Area::Files => files_list::show(ui, &self.state, &mut self.files_filter),
                    Area::Backups => backups::list(ui, &self.state, &mut self.backup_view),
                };
                action = found.or(action.take());
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
                let found = match self.area {
                    Area::Secrets => {
                        collection::show(ui, &self.state, &mut self.filter, &mut self.editor, gates)
                    }
                    Area::Files => file_detail::show(ui, &self.state, &mut self.file_view, gates),
                    Area::Backups => {
                        backups::detail(ui, &self.state, &mut self.backup_view, &self.keyrings_dir)
                    }
                };
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
        self._reload_stale_backups();
        self.copier.finish(&mut self.state);
        self._hide_locked_secret();
        self._auto_select();
        #[cfg(debug_assertions)]
        self._apply_dev_preset();
        if self.copier.tick(Instant::now()) {
            ctx.request_repaint_after(CLIPBOARD_REPAINT);
        }
        self._open_passphrase_dialog();
        self._open_file_password_dialog();
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
