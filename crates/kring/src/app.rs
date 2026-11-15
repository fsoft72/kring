//! The main window: wires worker events, views, dialogs, toasts and the clipboard.

use std::path::PathBuf;
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};

use eframe::egui;
use kring_core::model::SecretValue;

use crate::app_state::AppState;
use crate::clipboard::ArboardClipboard;
use crate::copy_flow::SecretCopier;
#[cfg(debug_assertions)]
use crate::dev_preset::DevPreset;
use crate::operation::MSG_WORKER_STOPPED;
use crate::session_secret::{FollowUp, MSG_USED_REMEMBERED};
use crate::ui::theme;
use crate::ui::toasts::{ToastKind, Toasts, kind_for_status, user_message};
use crate::views::backups::{self, BackupView};
use crate::views::consolidate::{self, ConsolidateView, PassphraseNeeds};
use crate::views::dialogs::{Dialog, DialogKind, Outcome, WalletTarget};
use crate::views::file_items::FileView;
use crate::views::item_detail::AttrEditor;
use crate::views::progress;
use crate::views::rail::WorkerActivity;
use crate::views::transfer::{self, TransferView};
use crate::views::wallet_items::WalletView;
use crate::views::{
    Action, Area, Gates, banners, collection, file_detail, files_list, gpg_detail, gpg_list, rail,
    sidebar, ssh_detail, ssh_list, switch_area, wallet_detail, wallets_list,
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
/// Info toast after forgetting the remembered passphrase.
const MSG_FORGOTTEN: &str = "Forgot the remembered passphrase";
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
    /// Wallet search text.
    wallets_filter: String,
    /// Card state of the open wallet (folders, expanded card, shown secrets).
    wallet_view: WalletView,
    /// SSH key search text.
    ssh_filter: String,
    /// SSH key folder scanned by the worker (`None` when HOME is unset).
    ssh_dir: Option<PathBuf>,
    /// GPG key search text.
    gpg_filter: String,
    /// Selected backup and the files checked for a restore.
    backup_view: BackupView,
    /// Choices and shown offline secrets of the transfer preview.
    transfer_view: TransferView,
    /// Start card fields, choices and given passphrases of the Consolidate area.
    consolidate_view: ConsolidateView,
    /// Keyrings directory, where restores write (same as the worker's).
    keyrings_dir: PathBuf,
    toasts: Toasts,
    /// The forget confirmation of the remembered passphrase is open.
    forget_confirm: bool,
    /// Number of the next command sent; the worker numbers the commands it
    /// receives the same way, from 0 (see [`Event::CommandFinished`]).
    next_seq: u64,
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
            wallets_filter: String::new(),
            wallet_view: WalletView::default(),
            ssh_filter: String::new(),
            ssh_dir: kring_core::paths::ssh_dir(),
            gpg_filter: String::new(),
            backup_view: BackupView::default(),
            transfer_view: TransferView::default(),
            consolidate_view: ConsolidateView::default(),
            keyrings_dir: kring_core::paths::keyrings_dir(),
            toasts: Toasts::default(),
            forget_confirm: false,
            next_seq: 0,
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
                    let running = self.state.running_command();
                    let follow = self.state.session.observe(&event, running);
                    if matches!(event, Event::Error(_)) {
                        self.copier.cancel();
                    }
                    if matches!(event, Event::ConsolidationDone(..)) {
                        self.consolidate_view.forget_passphrases();
                    }
                    let is_scan = matches!(event, Event::SshKeys(_));
                    let had_public = self.state.ssh_public_key.is_some();
                    self.state.apply(event);
                    if is_scan && had_public && self.state.ssh_public_key.is_none() {
                        self._reread_ssh_public_key();
                    }
                    if let Some(follow) = follow {
                        self._follow_up(follow);
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.worker_stopped = true;
                    if let Some(op) = &mut self.state.operation {
                        op.fail(MSG_WORKER_STOPPED);
                    }
                    break;
                }
            }
        }
    }

    /// Requests the public key of the selected SSH key again (a rescan found
    /// it changed and dropped the cached text).
    fn _reread_ssh_public_key(&mut self) {
        let Some(name) = self.state.selected_ssh_key.clone() else {
            return;
        };
        let cmd = self
            .state
            .ssh_keys
            .iter()
            .find(|k| k.name == name)
            .and_then(ssh_detail::select_command);
        if let Some(cmd) = cmd {
            self._send(cmd);
        }
    }

    /// Acts on the judgement of an automatic use of the remembered
    /// passphrase: reopens the dialog it answered (wrong passphrase, or an
    /// SSH key that needs one), opens the password dialog of a failed
    /// unlock, or announces a used one.
    fn _follow_up(&mut self, follow: FollowUp) {
        let dialog = match follow {
            FollowUp::Dialog(kind) => Dialog::retry(*kind),
            FollowUp::KeyPassphrase(kind) => Dialog::key_passphrase_required(*kind),
            FollowUp::Unlock { collection, label } => {
                Dialog::new(DialogKind::unlock(collection, label))
            }
            FollowUp::UsedRemembered => {
                let text = MSG_USED_REMEMBERED.to_string();
                return self.toasts.push(ToastKind::Info, text, Instant::now());
            }
        };
        if self.dialog.is_none() {
            self.dialog = Some(dialog);
        }
    }

    /// Sends `cmd` answered with the remembered passphrase and says so.
    fn _send_remembered(&mut self, cmd: Command) {
        self._send(cmd);
        self.toasts.push(
            ToastKind::Info,
            MSG_USED_REMEMBERED.to_string(),
            Instant::now(),
        );
    }

    /// Opens a dialog requested by a view: an unlock is first tried with the
    /// remembered passphrase; other passphrase dialogs use it instead of
    /// their fields.
    fn _open_dialog(&mut self, kind: DialogKind) {
        let unlock = match &kind {
            DialogKind::Unlock {
                collection, label, ..
            } => self.state.session.unlock(collection, label, self.next_seq),
            _ => None,
        };
        if let Some(cmd) = unlock {
            return self._send(cmd);
        }
        self.dialog = Some(Dialog::with_remembered(kind, self.state.session.value()));
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

    /// Sends a command to the worker as command number `next_seq`.
    fn _send(&mut self, cmd: Command) {
        let id = self.next_seq;
        self.state.track_file_command(&cmd);
        self.state.track_wallet_command(&cmd, id);
        self.state.track_transfer_command(&cmd);
        self.state.track_operation(&cmd, id);
        self.consolidate_view.remember(&cmd);
        if self.worker.tx.send(cmd).is_err() {
            self.worker_stopped = true;
            if let Some(op) = &mut self.state.operation {
                op.fail(MSG_WORKER_STOPPED);
            }
            return;
        }
        self.next_seq += 1;
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
            Action::Open(kind) => self._open_dialog(kind),
            Action::AskForgetPassphrase => self.forget_confirm = true,
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
            Action::SelectWallet(name) => {
                self.copier.cancel();
                self.state.select_wallet(name);
            }
            Action::CopyWalletSecret(index) => {
                let Some(secret) = self.state.wallet_items.get(index).map(|i| i.secret.clone())
                else {
                    return;
                };
                self.copier.copy_value(&secret, &mut self.state);
            }
            Action::ToggleSelect(id) => transfer::selection_toggle(&mut self.state.selection, &id),
            Action::ClearSelection => self.state.selection.clear(),
            Action::CloseTransferPreview => {
                self.state.close_transfer_preview();
                self.transfer_view.sync(None);
                self._send(Command::DiscardPlan);
            }
            Action::ApplyTransfer => {
                let Some(plan_id) = self.state.transfer_preview.as_ref().map(|p| p.plan_id) else {
                    return;
                };
                self._send(Command::ApplyTransfer {
                    plan_id,
                    choices: self.transfer_view.choices.clone(),
                    backup_passphrase: None,
                });
            }
            Action::HideTransferSecret(id) => self.state.hide_transfer_secret(&id),
            Action::RevealPreviewSecret(id) => {
                // Sending clears older requests of the item (as for a card
                // reveal); this one is tracked afterwards.
                self._send(Command::RevealSecret(id.clone()));
                self.state.track_preview_reveal(id);
            }
            Action::CloseConsolidationPreview => {
                self.state.close_consolidation_preview();
                self._send(Command::DiscardPlan);
            }
            Action::DismissConsolidation => {
                self.state.last_consolidation = None;
                self.consolidate_view.forget_passphrases();
            }
            Action::SelectSshKey(name) => {
                let info = self.state.ssh_keys.iter().find(|k| k.name == name);
                let cmd = info.and_then(ssh_detail::select_command);
                self.state.select_ssh_key(name);
                if let Some(cmd) = cmd {
                    self._send(cmd);
                }
            }
            Action::SelectGpgKey(fpr) => {
                let key = self.state.gpg_keys.iter().find(|k| k.fingerprint == fpr);
                let cmd = key.map(gpg_detail::select_command);
                self.state.select_gpg_key(fpr);
                if let Some(cmd) = cmd {
                    self._send(cmd);
                }
            }
            Action::Info(text) => self.toasts.push(ToastKind::Info, text, Instant::now()),
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
        if let Some(value) = self.dev.take_remembered() {
            self.state.session.remember(value);
        }
        if let Some(area) = self.dev.take_area() {
            self._handle(Action::SwitchArea(area));
        }
        let actions = match self.area {
            Area::Secrets => self.dev.take_actions(&self.state, &self.filter),
            Area::Files => self.dev.take_file_actions(&self.state),
            Area::KWallet => {
                let gates = Gates::from_provider(self.state.provider.as_ref());
                self.dev.take_wallet_actions(&self.state, gates)
            }
            Area::Backups => {
                self.dev
                    .take_backup_actions(&self.state, &mut self.backup_view, &self.keyrings_dir)
            }
            Area::Consolidate => self.dev.take_consolidate_actions(&self.state),
            Area::Ssh => self.dev.take_ssh_actions(&self.state),
            Area::Gpg => self.dev.take_gpg_actions(&self.state),
        };
        let reveal = self.dev.take_transfer_reveal(&self.state);
        for action in actions.into_iter().chain(reveal) {
            self._handle(action);
        }
        if self.area == Area::KWallet {
            if let Some((index, reveal)) = self.dev.take_wallet_card(&self.state) {
                self.wallet_view.sync(&self.state);
                self.wallet_view.toggle_expanded(index);
                if reveal {
                    self.wallet_view.toggle_revealed(index);
                }
            }
            return;
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
        if let Some(full) = self.state.session.resend(&cmd, self.next_seq) {
            return self._send_remembered(full);
        }
        self.dialog = Some(Dialog::new(DialogKind::passphrase(cmd)));
    }

    /// Opens the passphrase dialog when the pending plan asked for
    /// passphrases, keeping the choices of its preview: the backup one for
    /// a transfer; for a consolidation only the asked ones, resending those
    /// given before.
    fn _open_apply_passphrase_dialog(&mut self) {
        if self.dialog.is_some() {
            return;
        }
        let Some(asked) = self.state.pending_apply_passphrases else {
            return;
        };
        let consolidation = self.state.consolidation_preview.as_ref().map(|p| p.0);
        if consolidation == Some(asked.plan_id) {
            self.state.pending_apply_passphrases = None;
            self.consolidate_view.sync(&self.state);
            let (backup, orphan_files) = self.consolidate_view.kept(asked.plan_id);
            if let Some(secret) = self
                .state
                .session
                .apply_passphrase(asked.plan_id, self.next_seq)
            {
                let pick = |asked: bool, kept: Option<SecretValue>| match asked {
                    true => Some(secret.clone()),
                    false => kept,
                };
                let cmd = Command::ApplyConsolidation {
                    plan_id: asked.plan_id,
                    choices: self.consolidate_view.choices.clone(),
                    backup_passphrase: pick(asked.backup, backup),
                    orphan_files_passphrase: pick(asked.orphan_files, orphan_files),
                };
                return self._send_remembered(cmd);
            }
            let missing = PassphraseNeeds {
                backup: asked.backup,
                orphan_files: asked.orphan_files,
            };
            let kind = DialogKind::consolidate_passphrases(
                asked.plan_id,
                self.consolidate_view.choices.clone(),
                missing,
                backup,
                orphan_files,
            );
            self.dialog = Some(Dialog::new(kind));
            return;
        }
        let preview = self.state.transfer_preview.as_ref().map(|p| p.plan_id);
        if preview != Some(asked.plan_id) || !asked.backup {
            return;
        }
        self.state.pending_apply_passphrases = None;
        let choices = self.transfer_view.choices.clone();
        if let Some(secret) = self
            .state
            .session
            .apply_passphrase(asked.plan_id, self.next_seq)
        {
            let cmd = Command::ApplyTransfer {
                plan_id: asked.plan_id,
                choices,
                backup_passphrase: Some(secret),
            };
            return self._send_remembered(cmd);
        }
        let kind = DialogKind::apply_passphrase(asked.plan_id, choices);
        self.dialog = Some(Dialog::new(kind));
    }

    /// Shows the transfer preview unless another dialog is on top (a
    /// passphrase request keeps the preview behind it); returns its action.
    fn _transfer_preview(&mut self, ctx: &egui::Context, gates: Gates) -> Option<Action> {
        self.transfer_view
            .sync(self.state.transfer_preview.as_ref());
        if self.dialog.is_some() {
            return None;
        }
        transfer::show(ctx, &self.state, &mut self.transfer_view, gates)
    }

    /// Continues the import after the keyring of the open wallet was
    /// created: sent right away into it when a passphrase is remembered for
    /// the session, otherwise the import dialog reopens with it preselected.
    fn _continue_wallet_import(&mut self) {
        if self.dialog.is_some() {
            return;
        }
        let Some(name) = self.state.take_wallet_created() else {
            return;
        };
        let Some(info) = self.state.wallets.iter().find(|w| w.name == name) else {
            return;
        };
        let gates = Gates::from_provider(self.state.provider.as_ref());
        let Some(kind) = wallet_detail::import_dialog(&self.state, info, gates) else {
            return;
        };
        let direct = match &kind {
            DialogKind::ImportWallet {
                name,
                password,
                target: Some(WalletTarget::Keyring(target)),
                ..
            } if self.state.session.is_remembered() => Some(Command::PlanWalletImport {
                name: name.clone(),
                password: password.clone(),
                target: target.clone(),
            }),
            _ => None,
        };
        match direct {
            Some(cmd) => self._send(cmd),
            None => self.dialog = Some(Dialog::new(kind)),
        }
    }

    /// Opens the password dialog when the selected binary file asked for one.
    fn _open_file_password_dialog(&mut self) {
        if self.dialog.is_some() {
            return;
        }
        let Some((name, action)) = self.state.take_password_request() else {
            return;
        };
        let kind = DialogKind::file_password(name, action);
        self.dialog = Some(Dialog::with_remembered(kind, self.state.session.value()));
    }

    /// Shows the open dialog and handles its outcome.
    fn _dialog(&mut self, ctx: &egui::Context) {
        let Some(dialog) = &mut self.dialog else {
            return;
        };
        match dialog.show(ctx) {
            Outcome::Open => {}
            Outcome::Cancelled => {
                self.dialog = None;
                // A cancelled passphrase request ends the operation waiting for it.
                if self
                    .state
                    .operation
                    .as_ref()
                    .is_some_and(|op| op.is_waiting())
                {
                    self.state.operation = None;
                }
            }
            Outcome::Submitted(cmd) => {
                let id = self.next_seq;
                if let Some(value) = dialog.to_remember(&cmd) {
                    // A password that reopens the dialog when wrong is kept
                    // only once its command proves it right.
                    if dialog.reopens_when_wrong() {
                        self.state.session.remember_if_correct(value, id);
                    } else {
                        self.state.session.remember(value);
                    }
                }
                let retry = dialog.retry_kind();
                self.dialog = None;
                self._send(cmd);
                if let Some(kind) = retry {
                    self.state.session.used_in_dialog(kind, id);
                }
            }
        }
    }

    /// Shows the progress modal of the destructive operation unless a
    /// dialog is on top (a passphrase request steps it aside); Close drops it.
    fn _progress(&mut self, ctx: &egui::Context) {
        if self.dialog.is_some() {
            return;
        }
        let Some(op) = self.state.operation.as_ref().filter(|op| !op.is_waiting()) else {
            return;
        };
        if progress::show(ctx, op) {
            self.state.operation = None;
        }
    }

    /// Shows the forget confirmation of the remembered passphrase.
    fn _forget_confirm(&mut self, ctx: &egui::Context) {
        if !self.forget_confirm {
            return;
        }
        let Some(forget) = progress::confirm_forget(ctx) else {
            return;
        };
        self.forget_confirm = false;
        if forget {
            self.state.session.forget();
            self.toasts
                .push(ToastKind::Info, MSG_FORGOTTEN.to_string(), Instant::now());
        }
    }

    /// Renders the rail, the keyring list and the detail pane; returns the action.
    fn _panels(&mut self, ui: &mut egui::Ui, gates: Gates) -> Option<Action> {
        let mut action = None;
        let activity = WorkerActivity::from_flags(self.worker_stopped, self.awaiting_reply);
        let remembered = self.state.session.is_remembered();
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
                action = rail::show(ui, activity, self.area, remembered);
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
                    Area::KWallet => wallets_list::show(ui, &self.state, &mut self.wallets_filter),
                    Area::Ssh => ssh_list::show(
                        ui,
                        &self.state,
                        &mut self.ssh_filter,
                        self.ssh_dir.as_deref(),
                    ),
                    Area::Gpg => gpg_list::show(ui, &self.state, &mut self.gpg_filter),
                    Area::Backups => backups::list(ui, &self.state, &mut self.backup_view),
                    Area::Consolidate => consolidate::list(ui, &self.state, &self.consolidate_view),
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
                    Area::KWallet => {
                        wallet_detail::show(ui, &self.state, &mut self.wallet_view, gates)
                    }
                    Area::Ssh => ssh_detail::show(ui, &self.state, gates, self.ssh_dir.as_deref()),
                    Area::Gpg => gpg_detail::show(ui, &self.state, gates),
                    Area::Backups => {
                        backups::detail(ui, &self.state, &mut self.backup_view, &self.keyrings_dir)
                    }
                    Area::Consolidate => {
                        consolidate::detail(ui, &self.state, &mut self.consolidate_view, gates)
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
        self._continue_wallet_import();
        self._open_apply_passphrase_dialog();
        self.state.drop_stuck_operation(self.dialog.is_some());
        let gates = Gates::from_provider(self.state.provider.as_ref())
            .with_operation(self.state.operation_open());
        let action = self._panels(ui, gates);
        let preview_action = self._transfer_preview(&ctx, gates);
        self._dialog(&ctx);
        self._progress(&ctx);
        self._forget_confirm(&ctx);
        for action in [action, preview_action].into_iter().flatten() {
            self._handle(action);
        }
        self._feed_toasts();
        self.toasts.draw(&ctx);
    }
}
