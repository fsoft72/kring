//! UI-side application state, updated by worker events.

use std::path::PathBuf;

use kring_core::backup::{BackupInfo, RestoreReport};
use kring_core::gpg::GpgKey;
use kring_core::keyring_file::textual::{OfflineItem, ParseWarning};
use kring_core::keyring_file::{KeyringFileInfo, RetireBatchReport};
use kring_core::model::{CollectionId, CollectionInfo, ItemId, ItemInfo, SecretValue};
use kring_core::pam::PamStatus;
use kring_core::provider::ProviderInfo;
use kring_core::ssh::{AgentIdentity, SshKeyInfo};
use kring_core::transfer::apply::{TransferMode, TransferReport};
use kring_core::transfer::consolidate_apply::{ConsolidationReport, StepOutcome};
use kring_core::transfer::import::ImportReport;
use kring_core::transfer::plan::TransferCounts;

use crate::operation::{self, Operation};
use crate::session_secret::SessionSecret;
use crate::views::collection::{collection_key, display_names};
use crate::views::locked_list::natural_cmp;
use crate::worker::{
    AgentStatus, Command, ConflictView, ConsolidationSummary, Event, OfflineItemView, WalletInfo,
};
use crate::worker_transfer::{MSG_ORPHANS_NOT_RETIRED, invalidates_plan};

/// Maximum number of error messages kept.
const MAX_ERRORS: usize = 20;
/// Alias of the default collection.
const DEFAULT_ALIAS: &str = "default";

/// File command waiting for the password of a binary keyring file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileAction {
    /// Show the items of the file.
    Open,
    /// Import the items of the file into `target`.
    Import { target: CollectionId },
}

/// Returns the toast text of a finished import, e.g.
/// `Imported 2 items, skipped 1 duplicate, 0 conflicts`, followed by
/// `, M without secret` and `, F failed` when those are not zero.
pub fn import_summary(report: &ImportReport) -> String {
    let mut text = format!(
        "Imported {}, skipped {}, {}",
        count_noun(report.created, "item"),
        count_noun(report.duplicates, "duplicate"),
        count_noun(report.conflicts.len(), "conflict"),
    );
    if report.no_secret > 0 {
        text.push_str(&format!(", {} without secret", report.no_secret));
    }
    if !report.failed.is_empty() {
        text.push_str(&format!(", {} failed", report.failed.len()));
    }
    text
}

/// Returns the toast text of a finished transfer, e.g.
/// `Transferred 2 items, 1 already there, 0 replaced, 1 kept`, followed by
/// the non-zero extras (removed from / left in the source, without secret,
/// skipped in batch, failed).
pub fn transfer_summary(report: &TransferReport) -> String {
    let mut text = format!(
        "Transferred {}, {} already there, {} replaced, {} kept",
        count_noun(report.created, "item"),
        report.duplicates,
        report.replaced,
        report.kept_target,
    );
    let extras = [
        (report.source_deleted, "removed from the source"),
        (report.source_kept.len(), "left in the source"),
        (report.no_secret, "without secret"),
        (report.same_batch_skipped, "skipped in batch"),
        (report.failed.len(), "failed"),
    ];
    for (n, what) in extras {
        if n > 0 {
            text.push_str(&format!(", {n} {what}"));
        }
    }
    text
}

/// Returns the toast text of a finished consolidation: `Consolidation
/// complete` (plus the retired orphan files) or the step it stopped at.
pub fn consolidation_status(
    report: &ConsolidationReport,
    retired: Option<&RetireBatchReport>,
) -> String {
    if !report.completed {
        return match report.outcomes.last() {
            Some(StepOutcome::Failed { step, error }) => {
                format!("Consolidation stopped at {step}: {error}")
            }
            _ => "Consolidation stopped".to_string(),
        };
    }
    match retired {
        Some(r) => format!(
            "Consolidation complete, retired {}",
            count_noun(r.removed.len(), "orphan file")
        ),
        None => "Consolidation complete".to_string(),
    }
}

/// Most failed keyrings named in the toast of an unlock of many keyrings.
const MAX_FAILED_NAMES: usize = 3;

/// Returns the toast text of a finished unlock of many keyrings, e.g.
/// `Unlocked 2 of 5 keyrings, 3 failed: A, B, C (invalid password)`: at
/// most [`MAX_FAILED_NAMES`] failed keyrings are named (`and N more`), and
/// the reason follows when every failure shares it.
pub fn unlock_many_summary(unlocked: usize, failed: &[(String, String)]) -> String {
    let total = unlocked + failed.len();
    let mut text = format!("Unlocked {unlocked} of {}", count_noun(total, "keyring"));
    if failed.is_empty() {
        return text;
    }
    let names: Vec<&str> = failed
        .iter()
        .take(MAX_FAILED_NAMES)
        .map(|(name, _)| name.as_str())
        .collect();
    text.push_str(&format!(", {} failed: {}", failed.len(), names.join(", ")));
    let more = failed.len().saturating_sub(MAX_FAILED_NAMES);
    if more > 0 {
        text.push_str(&format!(" and {more} more"));
    }
    let reason = &failed[0].1;
    if failed.iter().all(|(_, r)| r == reason) {
        text.push_str(&format!(" ({reason})"));
    }
    text
}

/// A transfer preview waiting for the user's choices (no secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferPreview {
    /// Plan id to send back with `ApplyTransfer`.
    pub plan_id: u64,
    /// Target collection.
    pub target: CollectionId,
    /// Copy or move.
    pub mode: TransferMode,
    /// Planned action counts.
    pub counts: TransferCounts,
    /// Conflicts, one choice each, in this order.
    pub conflicts: Vec<ConflictView>,
}

/// Passphrases the pending plan needs before the apply can run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplyPassphrases {
    /// Plan id to resend the apply command for.
    pub plan_id: u64,
    /// The pre-apply backup needs a passphrase.
    pub backup: bool,
    /// The orphan files retire needs a passphrase.
    pub orphan_files: bool,
}

/// Prefix of the worker error for an apply of a stale plan.
const STALE_PLAN_PREFIX: &str = "Plan is out of date";
/// Most secret requests of previews remembered at once (oldest dropped).
const MAX_REVEAL_REQUESTS: usize = 32;
/// Notice shown when a backup was written but old backups could not be pruned.
const MSG_PRUNE_FAILED: &str = "Backup created but old backups could not be pruned";
/// Error of a backup passphrase request for an SSH passphrase change or a
/// GPG key change or delete: the key changed although the dialog did not
/// ask for a backup passphrase (the request clears the key passphrases, so
/// no resend).
pub const MSG_KEY_CHANGED: &str =
    "The key changed since the dialog opened, nothing was changed: try again";

/// Formats `n noun`, adding `s` unless `n` is 1 (e.g. `2 items`).
pub fn count_noun(n: usize, noun: &str) -> String {
    let plural = if n == 1 { "" } else { "s" };
    format!("{n} {noun}{plural}")
}

/// Everything the UI renders.
#[derive(Debug, Default)]
pub struct AppState {
    pub provider: Option<ProviderInfo>,
    pub provider_unavailable: bool,
    pub pam: Option<PamStatus>,
    pub collections: Vec<CollectionInfo>,
    pub selected: Option<CollectionId>,
    pub items: Vec<ItemInfo>,
    pub selected_item: Option<ItemId>,
    pub revealed: Option<(ItemId, SecretValue)>,
    pub status: String,
    pub errors: Vec<String>,
    pub pending_passphrase: Option<Command>,
    /// Keyring files of the keyrings directory (last scan).
    pub files: Vec<KeyringFileInfo>,
    /// Name of the keyring file being viewed.
    pub selected_file: Option<String>,
    /// Items read offline from the selected file; holds secrets, cleared on file change.
    pub file_items: Vec<OfflineItem>,
    /// True once the items of the selected file arrived (even zero items).
    pub file_opened: bool,
    /// Parse warnings of the selected file.
    pub file_warnings: Vec<ParseWarning>,
    /// Binary keyring file waiting for its password.
    pub pending_file_password: Option<String>,
    /// Command of the selected file sent without a password, resent with one when asked.
    pub pending_file_action: Option<FileAction>,
    /// KWallet wallets of the KWallet directory (last scan).
    pub wallets: Vec<WalletInfo>,
    /// Name of the wallet being viewed.
    pub selected_wallet: Option<String>,
    /// Entries of the selected wallet; holds secrets, cleared on wallet
    /// change and when leaving the KWallet area ([`AppState::close_wallet`]).
    pub wallet_items: Vec<OfflineItemView>,
    /// True once the entries of the selected wallet arrived (even zero).
    pub wallet_opened: bool,
    /// Password of the open wallet, kept with its entries (which hold every
    /// secret of the wallet anyway) so an import needs no second prompt;
    /// dropped with them. `Debug` redacts it.
    wallet_password: Option<SecretValue>,
    /// Open request `(wallet, password)` waiting for its entries.
    pending_wallet_open: Option<(String, SecretValue)>,
    /// `CreateWalletCollection` in flight: `(wallet, command number)`.
    wallet_create: Option<(String, u64)>,
    /// Wallet whose keyring was just created: its import continues.
    wallet_created: Option<String>,
    /// SSH keys of the SSH key directory (last scan).
    pub ssh_keys: Vec<SshKeyInfo>,
    /// Name of the SSH key being viewed.
    pub selected_ssh_key: Option<String>,
    /// Public key `(name, text)` of the selected SSH key (not a secret).
    pub ssh_public_key: Option<(String, String)>,
    /// Identities loaded in the ssh-agent (empty while it is unavailable).
    pub agent_identities: Vec<AgentIdentity>,
    /// Why the ssh-agent cannot be reached, `None` once it answered.
    pub agent_unavailable: Option<String>,
    /// Keys of the GnuPG home (last scan; empty while gpg is unavailable).
    pub gpg_keys: Vec<GpgKey>,
    /// Why gpg cannot be used, `None` once a scan succeeded.
    pub gpg_unavailable: Option<String>,
    /// Full fingerprint of the GPG key being viewed.
    pub selected_gpg_key: Option<String>,
    /// Armored public key `(fingerprint, text)` last read (not a secret);
    /// dropped when its key is no longer listed.
    pub gpg_public_key: Option<(String, String)>,
    /// Backups, newest first.
    pub backups: Vec<BackupInfo>,
    /// Outcome of the last import.
    pub last_import: Option<ImportReport>,
    /// Outcome of the last restore.
    pub last_restore: Option<RestoreReport>,
    /// Transfer preview waiting for `ApplyTransfer`.
    pub transfer_preview: Option<TransferPreview>,
    /// Outcome of the last transfer.
    pub last_transfer: Option<TransferReport>,
    /// Consolidation preview `(plan id, summary)` waiting for `ApplyConsolidation`.
    pub consolidation_preview: Option<(u64, ConsolidationSummary)>,
    /// Progress `(done, total)` of the running consolidation.
    pub consolidation_progress: Option<(usize, usize)>,
    /// Passphrases the pending plan asked for (resend the apply with all of them).
    pub pending_apply_passphrases: Option<ApplyPassphrases>,
    /// Outcome of the last consolidation, with the orphan file retire report.
    pub last_consolidation: Option<(ConsolidationReport, Option<RetireBatchReport>)>,
    /// Checked items of the selected collection; cleared on collection change,
    /// after a transfer and pruned when the items reload without them.
    pub selection: Vec<ItemId>,
    /// Backups created by the running (or last) consolidation apply.
    pub consolidation_backups: Vec<PathBuf>,
    /// Secrets revealed in the transfer or consolidation preview; dropped
    /// when it closes.
    transfer_revealed: Vec<(ItemId, SecretValue)>,
    /// Items whose secret a preview asked for and that did not arrive yet,
    /// one entry per request; not cleared on close, so a late answer after
    /// the preview closed is recognised and dropped. A card request of the
    /// same item removes its entries (a failed preview request never gets
    /// a `Secret`), and at most [`MAX_REVEAL_REQUESTS`] are kept.
    transfer_reveal_requests: Vec<ItemId>,
    /// True from sending `ApplyTransfer` until the worker answers it.
    transfer_applying: bool,
    /// True from sending `ApplyConsolidation` until the worker answers it.
    consolidation_applying: bool,
    /// True while the Consolidate area (and its preview) is on screen.
    consolidation_shown: bool,
    /// Keyring file of the last file import sent: its items in `file_items`
    /// back the offline side of the preview conflicts.
    import_file: Option<String>,
    /// Wallet of the last wallet import sent: its entries in `wallet_items`
    /// back the offline side of the preview conflicts while it is open.
    import_wallet: Option<String>,
    /// Set when a backup was created or restored since the last listing.
    backups_stale: bool,
    /// Notices shown as toasts besides `status` (e.g. pruned backups).
    notices: Vec<String>,
    /// Passphrase remembered for the session (its `Debug` hides it).
    pub session: SessionSecret,
    /// Destructive operation in flight (or finished, until its modal is closed).
    pub operation: Option<Operation>,
    /// Last consolidation preview asked `(target, include orphan files)`,
    /// kept until its flow ends (cancel, apply, leaving the area).
    consolidation_request: Option<(CollectionId, bool)>,
    /// Number of the unlock command sent from the consolidation preview:
    /// once it finished the preview is asked again.
    repreview_after: Option<u64>,
    /// The consolidation preview must be asked again (see [`Self::take_repreview`]).
    repreview_due: bool,
    /// The unlock of `repreview_after` reported an error (nothing changed:
    /// no re-preview).
    repreview_failed: bool,
    /// Number of the command the worker is handling: every command before it
    /// sent [`Event::CommandFinished`] (events before the first one, such as
    /// the startup ones, count for command 0).
    running: u64,
}

/// Sort key: login first, then default alias, then label (case-insensitive).
fn _sort_key(c: &CollectionInfo) -> (bool, bool, String) {
    let is_default = c.aliases.iter().any(|a| a == DEFAULT_ALIAS);
    (!c.is_login, !is_default, c.label.to_lowercase())
}

impl AppState {
    /// Applies a worker event to the state.
    pub fn apply(&mut self, event: Event) {
        if let Some(op) = &mut self.operation {
            op.observe(&event, self.running);
        }
        match event {
            Event::CommandFinished(id) => {
                self.running = id + 1;
                if self.repreview_after == Some(id) {
                    self.repreview_after = None;
                    self.repreview_due = !std::mem::take(&mut self.repreview_failed);
                }
                if self.wallet_create.as_ref().is_some_and(|(_, c)| *c == id) {
                    self.wallet_create = None;
                }
            }
            Event::Provider(p) => {
                self.provider = Some(p);
                self.provider_unavailable = false;
            }
            Event::ProviderUnavailable => self.provider_unavailable = true,
            Event::Pam(p) => self.pam = Some(p),
            Event::Collections(v) => self._set_collections(v),
            Event::Items(id, v) => {
                if self.selected.as_ref() != Some(&id) {
                    return;
                }
                self.items = v;
                let items = &self.items;
                let usable = |id: &ItemId| items.iter().any(|i| &i.id == id && !i.locked);
                self.selection.retain(usable);
                let gone = self
                    .selected_item
                    .as_ref()
                    .is_some_and(|s| !self.items.iter().any(|i| &i.id == s));
                if gone {
                    self.selected_item = None;
                    self.revealed = None;
                }
            }
            Event::Secret(id, s) => {
                let asked = self.transfer_reveal_requests.iter().position(|r| r == &id);
                if let Some(pos) = asked {
                    // Asked by a preview: never shown on the item card.
                    self.transfer_reveal_requests.remove(pos);
                    if self._in_preview(&id) {
                        self.transfer_revealed.retain(|(r, _)| r != &id);
                        self.transfer_revealed.push((id, s));
                    }
                    return;
                }
                if self.selected_item.as_ref() == Some(&id) {
                    self.revealed = Some((id, s));
                }
            }
            Event::BackupCreated(info) => {
                self.status = format!("Backup created: {}", info.dir.display());
                if self.consolidation_applying {
                    self.consolidation_backups.push(info.dir.clone());
                }
                self.backups_stale = true;
                if !info.pruned.is_empty() {
                    let removed = count_noun(info.pruned.len(), "old backup");
                    self.notices.push(format!("Removed {removed}"));
                }
                // The backup itself is fine: a notice, never an error (an
                // error would end an apply that is still running).
                if let Some(w) = &info.prune_warning {
                    self.notices.push(format!("{MSG_PRUNE_FAILED}: {w}"));
                }
            }
            Event::PassphraseNeeded(cmd) => {
                if matches!(
                    *cmd,
                    Command::ChangeSshPassphrase { .. }
                        | Command::ChangeGpgPassphrase { .. }
                        | Command::DeleteGpgKey { .. }
                ) {
                    return self.errors.push(MSG_KEY_CHANGED.to_string());
                }
                self.pending_passphrase = Some(*cmd);
            }
            Event::UnlockManyDone { unlocked, failed } => {
                let names = display_names(&self.collections);
                let named: Vec<(String, String)> = failed
                    .into_iter()
                    .map(|(id, error)| {
                        let name = names.get(&id).cloned();
                        (name.unwrap_or_else(|| collection_key(&id)), error)
                    })
                    .collect();
                let text = unlock_many_summary(unlocked, &named);
                match (unlocked, named.is_empty()) {
                    (0, _) => self.errors.push(text),
                    (_, true) => self.status = text,
                    (_, false) => self.notices.push(text),
                }
            }
            Event::Files(v) => self._set_files(v),
            Event::FileItems {
                name,
                items,
                warnings,
            } => {
                if self.selected_file.as_ref() != Some(&name) {
                    return;
                }
                self.file_items = items;
                self.file_warnings = warnings;
                self.file_opened = true;
                self.pending_file_action = None;
            }
            Event::Wallets(v) => self._set_wallets(v),
            Event::WalletItems { name, items } => {
                if self.selected_wallet.as_ref() != Some(&name) {
                    return;
                }
                self.wallet_items = items;
                self.wallet_opened = true;
                let pending = self.pending_wallet_open.take();
                self.wallet_password = pending.filter(|(n, _)| *n == name).map(|(_, pw)| pw);
                self._sync_wallet_reveal();
            }
            Event::SshKeys(keys) => self._set_ssh_keys(keys),
            Event::AgentIdentities(AgentStatus::Available(ids)) => {
                self.agent_identities = ids;
                self.agent_unavailable = None;
            }
            Event::AgentIdentities(AgentStatus::Unavailable(reason)) => {
                self.agent_identities.clear();
                self.agent_unavailable = Some(reason);
            }
            Event::SshPublicKey { name, text } => {
                if self.selected_ssh_key.as_ref() == Some(&name) {
                    self.ssh_public_key = Some((name, text));
                }
            }
            Event::GpgKeys(keys) => self._set_gpg_keys(keys),
            Event::GpgUnavailable { reason, scan } => {
                if scan {
                    self.gpg_keys.clear();
                    self.gpg_public_key = None;
                    self.selected_gpg_key = None;
                }
                self.gpg_unavailable = Some(reason);
            }
            Event::GpgPublicKey { fpr, text } => {
                if self.gpg_keys.iter().any(|k| k.fingerprint == fpr) {
                    self.gpg_public_key = Some((fpr, text));
                }
            }
            Event::Notice(text) => self.notices.push(text),
            Event::PasswordNeeded(name) => {
                if self.selected_file.as_ref() == Some(&name) {
                    self.pending_file_password = Some(name);
                }
            }
            Event::ImportDone(report) => {
                self.status = import_summary(&report);
                self.last_import = Some(report);
            }
            Event::Backups(v) => {
                self.backups = v;
                self.backups_stale = false;
            }
            Event::RestoreDone(report) => {
                self.last_restore = Some(report);
                self.backups_stale = true;
            }
            Event::TransferPreview {
                plan_id,
                target,
                mode,
                counts,
                conflicts,
            } => {
                self.close_transfer_preview();
                self.transfer_preview = Some(TransferPreview {
                    plan_id,
                    target,
                    mode,
                    counts,
                    conflicts,
                });
                self._sync_wallet_reveal();
                self.consolidation_preview = None;
                self.consolidation_progress = None;
                self.pending_apply_passphrases = None;
            }
            Event::TransferDone(report) => {
                self.status = transfer_summary(&report);
                self.last_transfer = Some(report);
                self.close_transfer_preview();
                self.selection.clear();
            }
            Event::ConsolidationPreview { plan_id, summary } => {
                self.close_transfer_preview();
                self.consolidation_preview = Some((plan_id, summary));
                self.consolidation_progress = None;
                self.consolidation_applying = false;
                self.consolidation_backups.clear();
                self.last_consolidation = None;
            }
            Event::ConsolidationProgress { done, total } => {
                self.consolidation_progress = Some((done, total));
            }
            Event::ConsolidationDone(report, retired) => {
                self.status = consolidation_status(&report, retired.as_ref());
                self.forget_consolidation_request();
                self.close_consolidation_preview();
                self.pending_apply_passphrases = None;
                self.last_consolidation = Some((report, retired));
            }
            Event::ApplyPassphrasesNeeded {
                plan_id,
                backup,
                orphan_files,
            } => {
                self.transfer_applying = false;
                self.consolidation_applying = false;
                self.pending_apply_passphrases = Some(ApplyPassphrases {
                    plan_id,
                    backup,
                    orphan_files,
                });
            }
            Event::Done(msg) => {
                let created = self.wallet_create.take_if(|(_, c)| *c == self.running);
                if let Some((name, _)) = created {
                    self.wallet_created = Some(name);
                }
                self.status = msg;
            }
            Event::Error(msg) => {
                if self.repreview_after == Some(self.running) {
                    self.repreview_failed = true;
                }
                self.consolidation_progress = None;
                self.transfer_applying = false;
                // The consolidation apply runs to `ConsolidationDone` after
                // a failed orphan retire; every other error seen while it is
                // in flight ends it (the worker handles one command at a
                // time and an apply never continues past an error).
                if !msg.starts_with(MSG_ORPHANS_NOT_RETIRED) {
                    self.consolidation_applying = false;
                }
                // Only a stale plan closes a preview; any other error keeps
                // it open (an apply after a failure answers with a stale plan).
                if msg.starts_with(STALE_PLAN_PREFIX) {
                    self.close_transfer_preview();
                    self.close_consolidation_preview();
                    self.pending_apply_passphrases = None;
                }
                // The pending file command survives unrelated errors; it is
                // dropped on file change, on its items or when its dialog is taken.
                self.errors.push(msg);
                let excess = self.errors.len().saturating_sub(MAX_ERRORS);
                self.errors.drain(..excess);
            }
        }
    }

    /// Replaces and sorts collections, dropping a selection that no longer exists.
    fn _set_collections(&mut self, mut v: Vec<CollectionInfo>) {
        // Login, then default, then label; same labels (e.g. many "Default
        // keyring" orphans) fall back to the natural order of their ids, so
        // Default_keyring_3 comes before Default_keyring_10.
        v.sort_by(|a, b| {
            _sort_key(a)
                .cmp(&_sort_key(b))
                .then_with(|| natural_cmp(&collection_key(&a.id), &collection_key(&b.id)))
        });
        self.collections = v;
        let exists = self
            .selected
            .as_ref()
            .is_some_and(|s| self.collections.iter().any(|c| &c.id == s));
        if !exists && self.selected.is_some() {
            self.selected = None;
            self.selection.clear();
            self.items.clear();
            self.selected_item = None;
            self.revealed = None;
        }
    }

    /// Replaces the file list, closing a selected file that no longer exists.
    fn _set_files(&mut self, files: Vec<KeyringFileInfo>) {
        self.files = files;
        let exists = self
            .selected_file
            .as_ref()
            .is_some_and(|s| self.files.iter().any(|f| &f.name == s));
        if !exists {
            self.close_file();
        }
    }

    /// Replaces the wallet list, closing a selected wallet that no longer exists.
    fn _set_wallets(&mut self, wallets: Vec<WalletInfo>) {
        self.wallets = wallets;
        let exists = self
            .selected_wallet
            .as_ref()
            .is_some_and(|s| self.wallets.iter().any(|w| &w.name == s));
        if !exists {
            self.close_wallet();
        }
    }

    /// Replaces the SSH key list, deselecting a key that no longer exists.
    fn _set_ssh_keys(&mut self, keys: Vec<SshKeyInfo>) {
        let old_fingerprint = self
            .selected_ssh_key
            .as_ref()
            .and_then(|s| self.ssh_keys.iter().find(|k| &k.name == s))
            .map(|k| k.fingerprint.clone());
        self.ssh_keys = keys;
        let exists = self
            .selected_ssh_key
            .as_ref()
            .is_some_and(|s| self.ssh_keys.iter().any(|k| &k.name == s));
        if !exists {
            self.selected_ssh_key = None;
            self.ssh_public_key = None;
            return;
        }
        // The key was replaced (same name, new fingerprint): the cached public
        // key text is stale, so drop it and let the view request it again.
        let new_fingerprint = self
            .selected_ssh_key
            .as_ref()
            .and_then(|s| self.ssh_keys.iter().find(|k| &k.name == s))
            .map(|k| k.fingerprint.clone());
        if old_fingerprint != new_fingerprint {
            self.ssh_public_key = None;
        }
    }

    /// Replaces the GPG key list (gpg answered, so it is available) and drops
    /// the selection and the public key text of a key that is no longer listed.
    fn _set_gpg_keys(&mut self, keys: Vec<GpgKey>) {
        self.gpg_keys = keys;
        self.gpg_unavailable = None;
        let selected_listed = self
            .selected_gpg_key
            .as_ref()
            .is_some_and(|fpr| self.gpg_keys.iter().any(|k| &k.fingerprint == fpr));
        if !selected_listed {
            self.selected_gpg_key = None;
        }
        let listed = self
            .gpg_public_key
            .as_ref()
            .is_some_and(|(fpr, _)| self.gpg_keys.iter().any(|k| &k.fingerprint == fpr));
        if !listed {
            self.gpg_public_key = None;
        }
    }

    /// Selects GPG key `fpr`, dropping the public key text of another key.
    pub fn select_gpg_key(&mut self, fpr: String) {
        let other = self
            .gpg_public_key
            .as_ref()
            .is_some_and(|(shown, _)| *shown != fpr);
        if other {
            self.gpg_public_key = None;
        }
        self.selected_gpg_key = Some(fpr);
    }

    /// Selects SSH key `name`, dropping the public key text of the previous one.
    pub fn select_ssh_key(&mut self, name: String) {
        if self.selected_ssh_key.as_ref() != Some(&name) {
            self.ssh_public_key = None;
        }
        self.selected_ssh_key = Some(name);
    }

    /// Returns true when the agent holds `key` (same fingerprint; a legacy
    /// key without a known fingerprint never matches).
    pub fn ssh_key_in_agent(&self, key: &SshKeyInfo) -> bool {
        if key.fingerprint.is_empty() {
            return false;
        }
        self.agent_identities
            .iter()
            .any(|i| i.fingerprint == key.fingerprint)
    }

    /// Selects a wallet, dropping the entries (and secrets) of the previous one.
    pub fn select_wallet(&mut self, name: String) {
        self.close_wallet();
        self.last_import = None;
        self.selected_wallet = Some(name);
    }

    /// Closes the selected wallet and drops its entries and secrets (on
    /// wallet change and when leaving the KWallet area); the offline side
    /// of a wallet preview stops being revealable.
    pub fn close_wallet(&mut self) {
        self.selected_wallet = None;
        self.wallet_items.clear();
        self.wallet_opened = false;
        self.wallet_password = None;
        self.pending_wallet_open = None;
        self._sync_wallet_reveal();
    }

    /// Records a sent wallet command (command number `id`): the password
    /// of an [`Command::OpenWallet`] for the selected wallet, kept once the
    /// entries arrive; a [`Command::CreateWalletCollection`], whose `Done`
    /// continues the import (see [`Self::take_wallet_created`]).
    pub fn track_wallet_command(&mut self, cmd: &Command, id: u64) {
        match cmd {
            Command::OpenWallet { name, password } => {
                if self.selected_wallet.as_ref() != Some(name) {
                    return;
                }
                self.pending_wallet_open = Some((name.clone(), password.clone()));
            }
            Command::CreateWalletCollection { name, .. } => {
                self.wallet_create = Some((name.clone(), id));
                self.wallet_created = None;
            }
            _ => {}
        }
    }

    /// Returns (once) the wallet whose keyring was just created, when it is
    /// still the open wallet, so its import can continue.
    pub fn take_wallet_created(&mut self) -> Option<String> {
        let name = self.wallet_created.take()?;
        let open = self.selected_wallet.as_ref() == Some(&name) && self.wallet_password.is_some();
        open.then_some(name)
    }

    /// Returns the password of the open wallet (for its import).
    pub fn wallet_password(&self) -> Option<&SecretValue> {
        self.wallet_password.as_ref()
    }

    /// Returns true when the entries of wallet `name` are open (selected and loaded).
    fn _wallet_open(&self, name: &str) -> bool {
        self.wallet_opened && self.selected_wallet.as_deref() == Some(name)
    }

    /// Makes the offline conflicts of a wallet import preview revealable
    /// exactly while that wallet is open with its entries loaded.
    fn _sync_wallet_reveal(&mut self) {
        let Some(name) = self.import_wallet.clone() else {
            return;
        };
        let open = self._wallet_open(&name);
        let Some(preview) = &mut self.transfer_preview else {
            return;
        };
        for c in &mut preview.conflicts {
            if c.incoming_item.is_none() && c.offline_index.is_some() {
                c.incoming_revealable = open;
            }
        }
    }

    /// Selects a keyring file, dropping the items (and secrets) of the previous one.
    pub fn select_file(&mut self, name: String) {
        self.close_file();
        self.selected_file = Some(name);
    }

    /// Closes the selected file and drops its items and secrets (e.g. on area change).
    pub fn close_file(&mut self) {
        self.selected_file = None;
        self.file_items.clear();
        self.file_warnings.clear();
        self.file_opened = false;
        self.pending_file_password = None;
        self.pending_file_action = None;
        self.last_import = None;
    }

    /// Remembers a file command sent without a password, so a later
    /// [`Event::PasswordNeeded`] knows what to resend.
    pub fn track_file_command(&mut self, cmd: &Command) {
        let (name, action) = match cmd {
            Command::OpenFile { name, password } => {
                (name, password.is_none().then_some(FileAction::Open))
            }
            Command::ImportFile {
                name,
                password,
                target,
            }
            | Command::PlanFileImport {
                name,
                password,
                target,
            } => (
                name,
                password.is_none().then(|| FileAction::Import {
                    target: target.clone(),
                }),
            ),
            _ => return,
        };
        if self.selected_file.as_ref() != Some(name) {
            return;
        }
        self.pending_file_action = action;
    }

    /// Takes the password request of the selected file with the command to resend.
    pub fn take_password_request(&mut self) -> Option<(String, FileAction)> {
        let name = self.pending_file_password.take()?;
        let action = self.pending_file_action.take()?;
        if self.selected_file.as_ref() != Some(&name) {
            return None;
        }
        Some((name, action))
    }

    /// Takes the queued notices, oldest first, for display as toasts.
    pub fn drain_notices(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notices)
    }

    /// Returns true (once) when the backup list must be reloaded.
    pub fn take_backups_stale(&mut self) -> bool {
        std::mem::take(&mut self.backups_stale)
    }

    /// Selects a collection and clears everything below it, including the
    /// report of an earlier import.
    pub fn select_collection(&mut self, id: CollectionId) {
        self.selected = Some(id);
        self.selection.clear();
        self.last_import = None;
        self.items.clear();
        self.selected_item = None;
        self.revealed = None;
    }

    /// Selects an item and hides any revealed secret.
    pub fn select_item(&mut self, id: ItemId) {
        self.selected_item = Some(id);
        self.revealed = None;
    }

    /// Hides the revealed secret.
    pub fn hide_secret(&mut self) {
        self.revealed = None;
    }

    /// Closes the transfer preview, dropping its revealed secrets and its
    /// passphrase request.
    pub fn close_transfer_preview(&mut self) {
        let Some(preview) = self.transfer_preview.take() else {
            self.transfer_revealed.clear();
            self.transfer_applying = false;
            return;
        };
        let asked = self.pending_apply_passphrases.map(|p| p.plan_id);
        if asked == Some(preview.plan_id) {
            self.pending_apply_passphrases = None;
        }
        self.transfer_revealed.clear();
        self.transfer_applying = false;
    }

    /// Closes the consolidation preview: drops its progress, its revealed
    /// secrets and its passphrase request (the worker plan is discarded by
    /// the caller when needed).
    pub fn close_consolidation_preview(&mut self) {
        let Some((plan_id, _)) = self.consolidation_preview.take() else {
            return;
        };
        let asked = self.pending_apply_passphrases.map(|p| p.plan_id);
        if asked == Some(plan_id) {
            self.pending_apply_passphrases = None;
        }
        self.consolidation_progress = None;
        self.consolidation_applying = false;
        if self.transfer_preview.is_none() {
            self.transfer_revealed.clear();
        }
    }

    /// Records whether the Consolidate area is on screen; leaving it drops
    /// the secrets revealed in its preview.
    pub fn set_consolidation_shown(&mut self, shown: bool) {
        self.consolidation_shown = shown;
        if !shown {
            self.forget_consolidation_request();
        }
        if !shown && self.transfer_preview.is_none() {
            self.transfer_revealed.clear();
        }
    }

    /// Records a secret request sent by a preview: its answer goes to the
    /// preview (or is dropped once the preview closed), never to the card.
    pub fn track_preview_reveal(&mut self, id: ItemId) {
        self.transfer_reveal_requests.push(id);
        let excess = self
            .transfer_reveal_requests
            .len()
            .saturating_sub(MAX_REVEAL_REQUESTS);
        self.transfer_reveal_requests.drain(..excess);
    }

    /// Returns true when `id` is a revealable live item of an open preview
    /// (the transfer dialog, or the consolidation preview while shown).
    fn _in_preview(&self, id: &ItemId) -> bool {
        let is_side = |c: &ConflictView| {
            (!c.existing_planned && c.existing_item.as_ref() == Some(id))
                || c.incoming_item.as_ref() == Some(id)
        };
        if let Some(preview) = &self.transfer_preview {
            return preview.conflicts.iter().any(is_side);
        }
        let Some((_, summary)) = &self.consolidation_preview else {
            return false;
        };
        self.consolidation_shown
            && summary
                .steps
                .iter()
                .any(|step| step.conflicts.iter().any(is_side))
    }

    /// Returns true from sending `ApplyConsolidation` until the worker answers it.
    pub fn is_applying_consolidation(&self) -> bool {
        self.consolidation_applying
    }

    /// Returns true from sending `ApplyTransfer` until the worker answers it.
    pub fn is_applying_transfer(&self) -> bool {
        self.transfer_applying
    }

    /// Returns the secret of `id` revealed in the transfer preview.
    pub fn transfer_secret(&self, id: &ItemId) -> Option<&SecretValue> {
        self.transfer_revealed
            .iter()
            .find(|(r, _)| r == id)
            .map(|(_, s)| s)
    }

    /// Hides the secret of `id` revealed in the transfer preview.
    pub fn hide_transfer_secret(&mut self, id: &ItemId) {
        self.transfer_revealed.retain(|(r, _)| r != id);
    }

    /// Returns the offline item of the imported file backing conflict `c`,
    /// only while that file is still the selected one and the label matches.
    pub fn offline_incoming(&self, c: &ConflictView) -> Option<&OfflineItem> {
        let index = c.offline_index?;
        if self.import_file.is_none() || self.import_file != self.selected_file {
            return None;
        }
        self.file_items
            .get(index)
            .filter(|i| i.label == c.label_incoming)
    }

    /// Returns the wallet entry backing the offline side of conflict `c` of
    /// a wallet import, only while that wallet is open and the label matches.
    pub fn wallet_incoming(&self, c: &ConflictView) -> Option<&OfflineItemView> {
        let index = c.offline_index?;
        let name = self.import_wallet.as_deref()?;
        if c.incoming_item.is_some() || !self._wallet_open(name) {
            return None;
        }
        self.wallet_items
            .get(index)
            .filter(|i| i.label == c.label_incoming)
    }

    /// Returns the secret of the offline side of conflict `c`: from the
    /// imported keyring file or from the imported wallet, whichever backs it.
    pub fn offline_incoming_secret(&self, c: &ConflictView) -> Option<&SecretValue> {
        if let Some(item) = self.offline_incoming(c) {
            return Some(&item.secret);
        }
        self.wallet_incoming(c).map(|i| &i.secret)
    }

    /// Records what a sent command means for the transfer preview: an apply
    /// in flight, or the keyring file or wallet being imported.
    ///
    /// Any other command that drops the worker's pending plan also closes
    /// the consolidation preview (e.g. an Unlock from its shortcut), so a
    /// stale plan is never offered.
    pub fn track_transfer_command(&mut self, cmd: &Command) {
        match cmd {
            Command::ApplyTransfer { .. } => self.transfer_applying = true,
            Command::ApplyConsolidation { .. } => {
                self.consolidation_applying = true;
                self.consolidation_backups.clear();
            }
            Command::ImportFile { name, .. } | Command::PlanFileImport { name, .. } => {
                self.import_file = Some(name.clone());
                self.import_wallet = None;
                self.close_consolidation_preview();
            }
            Command::PlanWalletImport { name, .. } => {
                self.import_wallet = Some(name.clone());
                self.import_file = None;
                self.close_consolidation_preview();
            }
            // A card asks for this secret: an older preview request of the
            // same item (failed, so never answered) must not swallow it.
            // Preview requests are tracked after they are sent.
            Command::RevealSecret(id) => self.transfer_reveal_requests.retain(|r| r != id),
            other if invalidates_plan(other) && !matches!(other, Command::DiscardPlan) => {
                self.close_consolidation_preview();
            }
            _ => {}
        }
    }

    /// Records a sent command (number `id`) for the consolidation preview:
    /// the preview asked, or an unlock sent while the Consolidate area shows
    /// a preview flow, whose end asks that preview again (the unlock
    /// discarded the plan) unless its command reported an error.
    pub fn track_consolidation_command(&mut self, cmd: &Command, id: u64) {
        match cmd {
            Command::PlanConsolidation {
                target,
                include_orphan_files,
            } => self.consolidation_request = Some((target.clone(), *include_orphan_files)),
            Command::Unlock { .. } | Command::UnlockMany { .. }
                if self.consolidation_shown && self.consolidation_request.is_some() =>
            {
                self.repreview_after = Some(id);
                self.repreview_failed = false;
            }
            _ => {}
        }
    }

    /// Ends the consolidation preview flow: no preview is asked again.
    pub fn forget_consolidation_request(&mut self) {
        self.consolidation_request = None;
        self.repreview_after = None;
        self.repreview_due = false;
        self.repreview_failed = false;
    }

    /// Returns (once) the consolidation preview to ask again after an
    /// unlock sent from it finished.
    pub fn take_repreview(&mut self) -> Option<Command> {
        if !std::mem::take(&mut self.repreview_due) {
            return None;
        }
        let (target, include_orphan_files) = self.consolidation_request.clone()?;
        Some(Command::PlanConsolidation {
            target,
            include_orphan_files,
        })
    }

    /// Records a sent command for the progress modal: a destructive one
    /// starts an operation (or resumes the one waiting for its passphrase).
    pub fn track_operation(&mut self, cmd: &Command, id: u64) {
        let started = operation::describe(cmd, self, id);
        operation::track(&mut self.operation, started);
    }

    /// Drops an operation waiting for a passphrase when no dialog asks for
    /// it (`dialog_open` false after the passphrase dialogs had their
    /// chance, e.g. a request of another plan that opens nothing).
    pub fn drop_stuck_operation(&mut self, dialog_open: bool) {
        let waiting = self.operation.as_ref().is_some_and(|op| op.is_waiting());
        if waiting && !dialog_open {
            self.operation = None;
        }
    }

    /// Returns the number of the command the current events belong to.
    pub fn running_command(&self) -> u64 {
        self.running
    }

    /// Returns true while a destructive operation is shown (running or
    /// finished but not closed): destructive actions are disabled.
    pub fn operation_open(&self) -> bool {
        self.operation.is_some()
    }

    /// Takes the pending status message (if any) and errors, for display as toasts.
    pub fn drain_messages(&mut self) -> (Option<String>, Vec<String>) {
        let status = std::mem::take(&mut self.status);
        let errors = std::mem::take(&mut self.errors);
        ((!status.is_empty()).then_some(status), errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kring_core::model::LOGIN_COLLECTION_PATH;

    fn col(path: &str, label: &str, aliases: &[&str]) -> CollectionInfo {
        CollectionInfo {
            id: CollectionId(path.into()),
            label: label.into(),
            locked: false,
            item_count: 0,
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            is_login: path == LOGIN_COLLECTION_PATH,
            created: 0,
            modified: 0,
        }
    }

    fn item(id: &str, coll: &str) -> ItemInfo {
        ItemInfo {
            id: ItemId(id.into()),
            collection: CollectionId(coll.into()),
            label: id.into(),
            attributes: Default::default(),
            locked: false,
            created: 0,
            modified: 0,
        }
    }

    /// Login first, then default alias, then label.
    #[test]
    fn login_sorted_first() {
        let mut s = AppState::default();
        s.apply(Event::Collections(vec![
            col("/c/zeta", "Zeta", &[]),
            col("/c/beta", "beta", &[]),
            col("/c/def", "Mine", &["default"]),
            col(LOGIN_COLLECTION_PATH, "Login", &[]),
        ]));
        let labels: Vec<_> = s.collections.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(labels, ["Login", "Mine", "beta", "Zeta"]);
    }

    /// Items of a collection that is not selected are dropped.
    #[test]
    fn items_for_other_collection_ignored() {
        let mut s = AppState::default();
        s.apply(Event::Collections(vec![
            col("/c/a", "a", &[]),
            col("/c/b", "b", &[]),
        ]));
        s.select_collection(CollectionId("/c/a".into()));
        s.apply(Event::Items(
            CollectionId("/c/b".into()),
            vec![item("/i/1", "/c/b")],
        ));
        assert!(s.items.is_empty());
        s.apply(Event::Items(
            CollectionId("/c/a".into()),
            vec![item("/i/2", "/c/a")],
        ));
        assert_eq!(s.items.len(), 1);
    }

    /// Selecting an item hides the revealed secret; stale secrets are ignored.
    #[test]
    fn select_item_clears_revealed() {
        let mut s = AppState::default();
        s.apply(Event::Collections(vec![col("/c/a", "a", &[])]));
        s.select_collection(CollectionId("/c/a".into()));
        s.apply(Event::Items(
            CollectionId("/c/a".into()),
            vec![item("/i/1", "/c/a"), item("/i/2", "/c/a")],
        ));
        s.select_item(ItemId("/i/1".into()));
        s.apply(Event::Secret(
            ItemId("/i/2".into()),
            SecretValue::from_text("x"),
        ));
        assert!(s.revealed.is_none());
        s.apply(Event::Secret(
            ItemId("/i/1".into()),
            SecretValue::from_text("x"),
        ));
        assert!(s.revealed.is_some());
        s.select_item(ItemId("/i/2".into()));
        assert!(s.revealed.is_none());
    }

    /// A removed selected collection clears the dependent state.
    #[test]
    fn vanished_collection_clears_selection() {
        let mut s = AppState::default();
        s.apply(Event::Collections(vec![col("/c/a", "a", &[])]));
        s.select_collection(CollectionId("/c/a".into()));
        s.apply(Event::Collections(vec![col("/c/b", "b", &[])]));
        assert!(s.selected.is_none());
    }

    /// Draining returns the status and errors once, then nothing.
    #[test]
    fn drain_messages_once() {
        let mut s = AppState::default();
        s.apply(Event::Done("renamed".into()));
        s.apply(Event::Error("e1".into()));
        s.apply(Event::Error("e2".into()));
        let (status, errors) = s.drain_messages();
        assert_eq!(status.as_deref(), Some("renamed"));
        assert_eq!(errors, ["e1", "e2"]);
        assert!(s.status.is_empty() && s.errors.is_empty());
        assert_eq!(s.drain_messages(), (None, vec![]));
    }

    /// Builds a file info named `name`.
    fn file(name: &str) -> KeyringFileInfo {
        KeyringFileInfo {
            path: format!("/k/{name}.keyring").into(),
            name: name.into(),
            format: kring_core::keyring_file::KeyringFormat::Textual,
            size: 0,
            modified: 0,
            display_name: None,
            item_count: None,
            daemon_readable: None,
            plaintext: true,
            error: None,
        }
    }

    /// Builds an offline item with a secret.
    fn offline(label: &str) -> OfflineItem {
        OfflineItem {
            label: label.into(),
            attributes: Default::default(),
            secret: SecretValue::from_text("s"),
            created: 0,
            modified: 0,
            secret_missing: false,
        }
    }

    /// Items of another file are ignored; selecting another file drops the secrets.
    #[test]
    fn file_items_follow_selection() {
        let mut s = AppState::default();
        s.apply(Event::Files(vec![file("a"), file("b")]));
        s.select_file("a".into());
        s.apply(Event::FileItems {
            name: "b".into(),
            items: vec![offline("x")],
            warnings: vec![],
        });
        assert!(s.file_items.is_empty());
        s.apply(Event::FileItems {
            name: "a".into(),
            items: vec![offline("x")],
            warnings: vec![],
        });
        assert_eq!(s.file_items.len(), 1);
        s.select_file("b".into());
        assert!(s.file_items.is_empty());
        assert_eq!(s.selected_file.as_deref(), Some("b"));
    }

    /// A rescan without the selected file closes it; close_file drops the secrets.
    #[test]
    fn vanished_file_closes_selection() {
        let mut s = AppState::default();
        s.apply(Event::Files(vec![file("a")]));
        s.select_file("a".into());
        s.apply(Event::FileItems {
            name: "a".into(),
            items: vec![offline("x")],
            warnings: vec![],
        });
        s.apply(Event::Files(vec![file("a"), file("b")]));
        assert_eq!(s.file_items.len(), 1);
        s.apply(Event::Files(vec![file("b")]));
        assert!(s.selected_file.is_none() && s.file_items.is_empty());
        s.select_file("b".into());
        s.apply(Event::PasswordNeeded("b".into()));
        s.close_file();
        assert!(s.selected_file.is_none() && s.pending_file_password.is_none());
    }

    /// Import, backup and restore results are stored.
    #[test]
    fn offline_results_stored() {
        let mut s = AppState::default();
        s.apply(Event::ImportDone(ImportReport {
            created: 2,
            ..Default::default()
        }));
        assert_eq!(s.last_import.as_ref().map(|r| r.created), Some(2));
        s.apply(Event::Backups(vec![]));
        assert!(s.backups.is_empty());
        s.apply(Event::RestoreDone(RestoreReport {
            restored: vec!["/k/a.keyring".into()],
            pre_restore_backup: None,
        }));
        assert_eq!(s.last_restore.as_ref().map(|r| r.restored.len()), Some(1));
    }

    /// Selects file `name` and tracks `cmd` for it.
    fn tracked(name: &str, cmd: Command) -> AppState {
        let mut s = AppState::default();
        s.apply(Event::Files(vec![file("a"), file("b")]));
        s.select_file(name.into());
        s.track_file_command(&cmd);
        s
    }

    /// A password request opens only for the selected file with a tracked command, once.
    #[test]
    fn password_request_for_selected_file_only() {
        let open = Command::OpenFile {
            name: "a".into(),
            password: None,
        };
        let mut s = tracked("a", open.clone());
        s.apply(Event::PasswordNeeded("b".into()));
        assert!(s.take_password_request().is_none());
        s.apply(Event::PasswordNeeded("a".into()));
        assert_eq!(
            s.take_password_request(),
            Some(("a".to_string(), FileAction::Open))
        );
        assert!(s.take_password_request().is_none());
        let mut untracked = tracked("a", Command::ScanFiles);
        untracked.apply(Event::PasswordNeeded("a".into()));
        assert!(untracked.take_password_request().is_none());
        let mut other = tracked("b", open);
        other.apply(Event::PasswordNeeded("b".into()));
        assert!(other.take_password_request().is_none());
    }

    /// An import sent without a password resends the same target.
    #[test]
    fn import_request_keeps_target() {
        let target = CollectionId("/c/t".into());
        let mut s = tracked(
            "a",
            Command::ImportFile {
                name: "a".into(),
                password: None,
                target: target.clone(),
            },
        );
        s.apply(Event::PasswordNeeded("a".into()));
        assert_eq!(
            s.take_password_request(),
            Some(("a".to_string(), FileAction::Import { target }))
        );
    }

    /// A command with a password, the file's items or a file change drops the pending action.
    #[test]
    fn pending_action_cleared() {
        let open = Command::OpenFile {
            name: "a".into(),
            password: None,
        };
        let mut s = tracked("a", open.clone());
        s.track_file_command(&Command::OpenFile {
            name: "a".into(),
            password: Some(SecretValue::from_text("pw")),
        });
        assert!(s.pending_file_action.is_none());
        let mut s = tracked("a", open.clone());
        s.apply(Event::FileItems {
            name: "a".into(),
            items: vec![],
            warnings: vec![],
        });
        assert!(s.pending_file_action.is_none());
        let mut s = tracked("a", open.clone());
        s.select_file("b".into());
        assert!(s.pending_file_action.is_none());
        let mut s = tracked("a", open);
        s.apply(Event::PasswordNeeded("a".into()));
        s.close_file();
        assert!(s.pending_file_action.is_none() && s.take_password_request().is_none());
    }

    /// An unrelated error keeps the pending file command and its password request.
    #[test]
    fn unrelated_error_keeps_pending_action() {
        let open = Command::OpenFile {
            name: "a".into(),
            password: None,
        };
        let mut s = tracked("a", open);
        s.apply(Event::PasswordNeeded("a".into()));
        s.apply(Event::Error("clipboard failed".into()));
        assert_eq!(
            s.take_password_request(),
            Some(("a".to_string(), FileAction::Open))
        );
        let mut other = tracked(
            "a",
            Command::OpenFile {
                name: "a".into(),
                password: None,
            },
        );
        other.apply(Event::FileItems {
            name: "b".into(),
            items: vec![],
            warnings: vec![],
        });
        assert_eq!(other.pending_file_action, Some(FileAction::Open));
    }

    /// Items skipped for a missing secret are named in the summary.
    #[test]
    fn import_summary_counts_items_without_secret() {
        let report = ImportReport {
            created: 1,
            no_secret: 3,
            ..Default::default()
        };
        assert_eq!(
            import_summary(&report),
            "Imported 1 item, skipped 0 duplicates, 0 conflicts, 3 without secret"
        );
    }

    /// A prune failure after a backup is a notice, not an error: a running
    /// consolidation apply stays in flight.
    #[test]
    fn prune_warning_is_a_notice() {
        let mut s = AppState::default();
        s.track_transfer_command(&Command::ApplyConsolidation {
            plan_id: 1,
            choices: vec![],
            backup_passphrase: None,
            orphan_files_passphrase: None,
        });
        let info = BackupInfo {
            dir: "/b/new".into(),
            reason: "consolidate".into(),
            created: String::new(),
            files: vec![],
            seq: 1,
            prune_warning: Some("permission denied".into()),
            pruned: vec![],
        };
        s.apply(Event::BackupCreated(info));
        assert!(s.is_applying_consolidation());
        assert_eq!(
            s.drain_notices(),
            ["Backup created but old backups could not be pruned: permission denied"]
        );
        assert!(s.drain_messages().1.is_empty());
    }

    /// A backup that pruned old ones queues a notice, drained once.
    #[test]
    fn pruned_backups_queue_a_notice() {
        let mut s = AppState::default();
        let mut info = BackupInfo {
            dir: "/b/new".into(),
            reason: "t".into(),
            created: String::new(),
            files: vec![],
            seq: 3,
            prune_warning: None,
            pruned: vec![],
        };
        s.apply(Event::BackupCreated(info.clone()));
        assert!(s.drain_notices().is_empty());
        info.pruned = vec!["/b/1".into(), "/b/2".into()];
        s.apply(Event::BackupCreated(info.clone()));
        info.pruned = vec!["/b/3".into()];
        s.apply(Event::BackupCreated(info));
        s.apply(Event::Done("Collection deleted".into()));
        assert_eq!(
            s.drain_notices(),
            ["Removed 2 old backups", "Removed 1 old backup"]
        );
        assert!(s.drain_notices().is_empty());
        assert_eq!(s.status, "Collection deleted");
    }

    /// A finished import becomes a status message; closing the file drops the report.
    #[test]
    fn import_done_status_and_reset() {
        let report = ImportReport {
            created: 2,
            duplicates: 1,
            conflicts: vec!["x".into()],
            failed: vec![],
            no_secret: 0,
        };
        assert_eq!(
            import_summary(&report),
            "Imported 2 items, skipped 1 duplicate, 1 conflict"
        );
        let failed = ImportReport {
            created: 1,
            failed: vec![("y".into(), "e".into())],
            ..Default::default()
        };
        assert_eq!(
            import_summary(&failed),
            "Imported 1 item, skipped 0 duplicates, 0 conflicts, 1 failed"
        );
        let mut s = tracked("a", Command::ScanFiles);
        s.apply(Event::ImportDone(report));
        assert_eq!(
            s.status,
            "Imported 2 items, skipped 1 duplicate, 1 conflict"
        );
        s.close_file();
        assert!(s.last_import.is_none());
    }

    /// A file counts as opened once its items arrived, even with no items.
    #[test]
    fn file_opened_tracks_selected_file() {
        let mut s = AppState::default();
        s.apply(Event::Files(vec![file("a"), file("b")]));
        s.select_file("a".into());
        assert!(!s.file_opened);
        s.apply(Event::FileItems {
            name: "b".into(),
            items: vec![],
            warnings: vec![],
        });
        assert!(!s.file_opened, "items of another file");
        s.apply(Event::FileItems {
            name: "a".into(),
            items: vec![],
            warnings: vec![],
        });
        assert!(s.file_opened);
        s.select_file("b".into());
        assert!(!s.file_opened);
    }

    /// Backups and restores mark the backup list stale, once.
    #[test]
    fn backups_stale_after_changes() {
        let mut s = AppState::default();
        assert!(!s.take_backups_stale());
        s.apply(Event::RestoreDone(RestoreReport {
            restored: vec![],
            pre_restore_backup: None,
        }));
        assert!(s.take_backups_stale());
        assert!(!s.take_backups_stale());
        s.apply(Event::Backups(vec![]));
        assert!(!s.take_backups_stale());
    }

    /// Selecting a collection drops the report of an earlier import.
    #[test]
    fn select_collection_clears_import_report() {
        let mut s = AppState::default();
        s.apply(Event::ImportDone(ImportReport::default()));
        s.select_collection(CollectionId("/c/a".into()));
        assert!(s.last_import.is_none());
    }

    /// Errors are capped at the last 20.
    #[test]
    fn errors_capped() {
        let mut s = AppState::default();
        for i in 0..25 {
            s.apply(Event::Error(format!("e{i}")));
        }
        assert_eq!(s.errors.len(), 20);
        assert_eq!(s.errors[0], "e5");
    }

    /// A transfer preview is kept until the transfer is done.
    #[test]
    fn transfer_preview_cleared_when_done() {
        let mut s = AppState::default();
        s.apply(Event::TransferPreview {
            plan_id: 7,
            target: CollectionId("/c/t".into()),
            mode: TransferMode::Copy,
            counts: TransferCounts::default(),
            conflicts: vec![],
        });
        assert_eq!(s.transfer_preview.as_ref().map(|p| p.plan_id), Some(7));
        s.apply(Event::Error("unrelated".into()));
        assert!(s.transfer_preview.is_some());
        let report = TransferReport {
            created: 2,
            duplicates: 1,
            source_deleted: 3,
            ..TransferReport::default()
        };
        s.apply(Event::TransferDone(report));
        assert!(s.transfer_preview.is_none());
        assert_eq!(
            s.status,
            "Transferred 2 items, 1 already there, 0 replaced, 0 kept, 3 removed from the source"
        );
    }

    /// Consolidation preview, progress and result replace each other.
    #[test]
    fn consolidation_events_flow() {
        let mut s = AppState::default();
        let summary = ConsolidationSummary {
            target: CollectionId("/c/t".into()),
            steps: vec![],
            delete_empty: vec![],
            skipped: vec![],
            locked_count: 0,
            set_default: false,
            conflict_count: 0,
            orphan_files: vec![],
            backup_needs_passphrase: false,
        };
        s.apply(Event::ConsolidationPreview {
            plan_id: 3,
            summary,
        });
        s.apply(Event::ConsolidationProgress { done: 1, total: 4 });
        assert_eq!(s.consolidation_progress, Some((1, 4)));
        let failed = ConsolidationReport {
            outcomes: vec![StepOutcome::Failed {
                step: "Move Work".into(),
                error: "boom".into(),
            }],
            completed: false,
        };
        s.apply(Event::ConsolidationDone(failed, None));
        assert!(s.consolidation_preview.is_none() && s.consolidation_progress.is_none());
        assert_eq!(s.status, "Consolidation stopped at Move Work: boom");
        let done = ConsolidationReport {
            outcomes: vec![],
            completed: true,
        };
        let retired = RetireBatchReport {
            backup: None,
            removed: vec!["a".into()],
            without_backup: vec!["a".into()],
            kept: vec![],
        };
        assert_eq!(
            consolidation_status(&done, Some(&retired)),
            "Consolidation complete, retired 1 orphan file"
        );
    }

    /// A file import planned without a password resends the same target.
    #[test]
    fn plan_file_import_tracked() {
        let target = CollectionId("/c/t".into());
        let mut s = tracked(
            "a",
            Command::PlanFileImport {
                name: "a".into(),
                password: None,
                target: target.clone(),
            },
        );
        s.apply(Event::PasswordNeeded("a".into()));
        assert_eq!(
            s.take_password_request(),
            Some(("a".to_string(), FileAction::Import { target }))
        );
    }

    /// Builds an empty consolidation summary for state tests.
    fn empty_summary() -> ConsolidationSummary {
        ConsolidationSummary {
            target: CollectionId("/c/t".into()),
            steps: vec![],
            delete_empty: vec![],
            skipped: vec![],
            locked_count: 0,
            set_default: false,
            conflict_count: 0,
            orphan_files: vec![],
            backup_needs_passphrase: false,
        }
    }

    /// Builds a transfer preview event for state tests.
    fn preview_event(plan_id: u64) -> Event {
        Event::TransferPreview {
            plan_id,
            target: CollectionId("/c/t".into()),
            mode: TransferMode::Copy,
            counts: TransferCounts::default(),
            conflicts: vec![],
        }
    }

    /// A transfer preview and a consolidation preview replace each other.
    #[test]
    fn previews_replace_each_other() {
        let mut s = AppState::default();
        s.apply(preview_event(1));
        s.apply(Event::ConsolidationPreview {
            plan_id: 2,
            summary: empty_summary(),
        });
        assert!(s.transfer_preview.is_none());
        assert_eq!(s.consolidation_preview.as_ref().map(|p| p.0), Some(2));
        s.apply(preview_event(3));
        assert!(s.consolidation_preview.is_none());
        assert_eq!(s.transfer_preview.as_ref().map(|p| p.plan_id), Some(3));
    }

    /// A stale plan error drops both previews and the passphrase request.
    #[test]
    fn stale_plan_error_clears_previews() {
        let mut s = AppState::default();
        s.apply(preview_event(1));
        s.apply(Event::ApplyPassphrasesNeeded {
            plan_id: 1,
            backup: true,
            orphan_files: false,
        });
        assert_eq!(
            s.pending_apply_passphrases.map(|p| (p.plan_id, p.backup)),
            Some((1, true))
        );
        s.apply(Event::Error("Plan is out of date, preview again".into()));
        assert!(s.transfer_preview.is_none() && s.pending_apply_passphrases.is_none());
        s.apply(Event::ConsolidationPreview {
            plan_id: 2,
            summary: empty_summary(),
        });
        s.apply(Event::Error("Plan is out of date, preview again".into()));
        assert!(s.consolidation_preview.is_none());
    }

    /// Any error, and the end of a consolidation, drop the progress.
    #[test]
    fn progress_cleared_on_error_and_done() {
        let mut s = AppState::default();
        s.apply(Event::ConsolidationPreview {
            plan_id: 2,
            summary: empty_summary(),
        });
        s.apply(Event::ConsolidationProgress { done: 1, total: 3 });
        s.apply(Event::Error("boom".into()));
        assert!(s.consolidation_progress.is_none());
        assert!(s.consolidation_preview.is_some());
        s.apply(Event::ConsolidationProgress { done: 2, total: 3 });
        let done = ConsolidationReport {
            outcomes: vec![],
            completed: true,
        };
        s.apply(Event::ConsolidationDone(done, None));
        assert!(s.consolidation_progress.is_none());
    }

    /// Builds a conflict view between live items `existing` and `incoming`.
    fn live_conflict(existing: &str, incoming: &str) -> ConflictView {
        ConflictView {
            label_incoming: "x".into(),
            label_existing: "x".into(),
            modified_incoming: 0,
            modified_existing: 0,
            default_choice: kring_core::transfer::plan::Choice::KeepTarget,
            incoming_item: Some(ItemId(incoming.into())),
            incoming_revealable: true,
            existing_item: Some(ItemId(existing.into())),
            existing_planned: false,
            offline_index: None,
        }
    }

    /// Builds a preview event with the given conflicts.
    fn preview_with(plan_id: u64, conflicts: Vec<ConflictView>) -> Event {
        Event::TransferPreview {
            plan_id,
            target: CollectionId("/c/t".into()),
            mode: TransferMode::Copy,
            counts: TransferCounts::default(),
            conflicts,
        }
    }

    /// The selection is cleared on collection change and after a transfer,
    /// and pruned when the items reload without some of its ids.
    #[test]
    fn selection_follows_collection_and_items() {
        let a = CollectionId("/c/a".into());
        let mut s = AppState::default();
        s.apply(Event::Collections(vec![col("/c/a", "a", &[])]));
        s.select_collection(a.clone());
        s.apply(Event::Items(
            a.clone(),
            vec![item("/c/a/1", "/c/a"), item("/c/a/2", "/c/a")],
        ));
        s.selection = vec![ItemId("/c/a/1".into()), ItemId("/c/a/2".into())];
        s.apply(Event::Items(a.clone(), vec![item("/c/a/2", "/c/a")]));
        assert_eq!(s.selection, [ItemId("/c/a/2".into())]);
        let mut locked = item("/c/a/2", "/c/a");
        locked.locked = true;
        s.apply(Event::Items(a.clone(), vec![locked]));
        assert!(s.selection.is_empty(), "locked items cannot be transferred");
        s.selection = vec![ItemId("/c/a/2".into())];
        s.apply(Event::TransferDone(TransferReport::default()));
        assert!(s.selection.is_empty());
        s.selection = vec![ItemId("/c/a/2".into())];
        s.select_collection(a);
        assert!(s.selection.is_empty());
    }

    /// Secrets of preview items stay in the preview (not the item card) and
    /// are dropped when it closes; other secrets keep the card behavior.
    #[test]
    fn preview_secrets_scoped_to_dialog() {
        let mut s = AppState {
            selected_item: Some(ItemId("/c/s/1".into())),
            ..AppState::default()
        };
        s.apply(preview_with(1, vec![live_conflict("/c/t/1", "/c/s/1")]));
        s.track_preview_reveal(ItemId("/c/t/1".into()));
        s.track_preview_reveal(ItemId("/c/s/1".into()));
        s.track_preview_reveal(ItemId("/c/x/9".into()));
        s.apply(Event::Secret(
            ItemId("/c/t/1".into()),
            SecretValue::from_text("old"),
        ));
        s.apply(Event::Secret(
            ItemId("/c/s/1".into()),
            SecretValue::from_text("new"),
        ));
        s.apply(Event::Secret(
            ItemId("/c/x/9".into()),
            SecretValue::from_text("other"),
        ));
        let shown = |s: &AppState, id: &str| {
            s.transfer_secret(&ItemId(id.into()))
                .and_then(|v| v.as_text().map(str::to_string))
        };
        assert_eq!(shown(&s, "/c/t/1").as_deref(), Some("old"));
        assert_eq!(shown(&s, "/c/s/1").as_deref(), Some("new"));
        assert!(shown(&s, "/c/x/9").is_none());
        assert!(
            s.revealed.is_none(),
            "the card under the dialog stays masked"
        );
        s.hide_transfer_secret(&ItemId("/c/t/1".into()));
        assert!(shown(&s, "/c/t/1").is_none());
        s.apply(Event::ApplyPassphrasesNeeded {
            plan_id: 1,
            backup: true,
            orphan_files: false,
        });
        s.close_transfer_preview();
        assert!(s.transfer_preview.is_none() && s.pending_apply_passphrases.is_none());
        assert!(shown(&s, "/c/s/1").is_none());
        s.apply(Event::Secret(
            ItemId("/c/s/1".into()),
            SecretValue::from_text("new"),
        ));
        assert!(s.revealed.is_some(), "without a preview the card gets it");
    }

    /// A new preview or the end of the transfer drops revealed secrets.
    #[test]
    fn preview_secrets_dropped_on_replace_and_done() {
        let mut s = AppState::default();
        let conflicts = vec![live_conflict("/c/t/1", "/c/s/1")];
        s.apply(preview_with(1, conflicts.clone()));
        s.track_preview_reveal(ItemId("/c/t/1".into()));
        s.apply(Event::Secret(
            ItemId("/c/t/1".into()),
            SecretValue::from_text("old"),
        ));
        assert!(s.transfer_secret(&ItemId("/c/t/1".into())).is_some());
        s.apply(preview_with(2, conflicts.clone()));
        assert!(s.transfer_secret(&ItemId("/c/t/1".into())).is_none());
        s.track_preview_reveal(ItemId("/c/t/1".into()));
        s.apply(Event::Secret(
            ItemId("/c/t/1".into()),
            SecretValue::from_text("old"),
        ));
        s.apply(Event::TransferDone(TransferReport::default()));
        assert!(s.transfer_preview.is_none());
        s.apply(preview_with(3, conflicts));
        assert!(s.transfer_secret(&ItemId("/c/t/1".into())).is_none());
    }

    /// Errors keep the preview open (the toast shows them) and end the
    /// apply in flight; only a stale plan closes it.
    #[test]
    fn apply_error_keeps_preview_unless_stale() {
        let apply = Command::ApplyTransfer {
            plan_id: 1,
            choices: vec![],
            backup_passphrase: None,
        };
        let mut s = AppState::default();
        s.apply(preview_with(1, vec![]));
        s.apply(Event::Error("clipboard failed".into()));
        assert!(s.transfer_preview.is_some());
        s.track_transfer_command(&apply);
        assert!(s.is_applying_transfer());
        s.apply(Event::Error(
            "Items changed since the preview, preview again".into(),
        ));
        assert!(s.transfer_preview.is_some(), "kept, the toast explains");
        assert!(!s.is_applying_transfer(), "Apply is enabled again");
        s.track_transfer_command(&apply);
        s.apply(Event::Error("Plan is out of date, preview again".into()));
        assert!(s.transfer_preview.is_none());
    }

    /// A secret asked by a preview that arrives after it closed is dropped:
    /// it reaches neither the preview nor the item card.
    #[test]
    fn late_preview_secret_dropped_after_close() {
        let id = ItemId("/c/s/1".into());
        let mut s = AppState {
            selected_item: Some(id.clone()),
            ..AppState::default()
        };
        s.apply(preview_with(1, vec![live_conflict("/c/t/1", "/c/s/1")]));
        s.track_preview_reveal(id.clone());
        s.close_transfer_preview();
        s.apply(Event::Secret(id.clone(), SecretValue::from_text("late")));
        assert!(s.revealed.is_none());
        assert!(s.transfer_secret(&id).is_none());
        s.apply(Event::Secret(id.clone(), SecretValue::from_text("card")));
        assert!(s.revealed.is_some(), "the ledger entry was used once");
    }

    /// A preview request answered with an error does not swallow a later
    /// card reveal of the same item; the ledger is capped.
    #[test]
    fn failed_preview_reveal_does_not_swallow_card_reveal() {
        let id = ItemId("/c/s/1".into());
        let mut s = AppState {
            selected_item: Some(id.clone()),
            ..AppState::default()
        };
        s.apply(preview_with(1, vec![live_conflict("/c/t/1", "/c/s/1")]));
        s.track_transfer_command(&Command::RevealSecret(id.clone()));
        s.track_preview_reveal(id.clone());
        s.apply(Event::Error("Locked: item is locked".into()));
        s.close_transfer_preview();
        s.track_transfer_command(&Command::RevealSecret(id.clone()));
        s.apply(Event::Secret(id.clone(), SecretValue::from_text("card")));
        assert!(s.revealed.is_some());
        for n in 0..(MAX_REVEAL_REQUESTS + 5) {
            s.track_preview_reveal(ItemId(format!("/c/x/{n}")));
        }
        assert_eq!(s.transfer_reveal_requests.len(), MAX_REVEAL_REQUESTS);
        assert_eq!(s.transfer_reveal_requests[0].0, "/c/x/5", "oldest dropped");
    }

    /// The Apply button stays disabled through the orphan retire error that
    /// precedes `ConsolidationDone`; other errors, a passphrase request and
    /// the end of the apply re-enable it.
    #[test]
    fn consolidation_applying_until_answered() {
        let apply = Command::ApplyConsolidation {
            plan_id: 2,
            choices: vec![],
            backup_passphrase: None,
            orphan_files_passphrase: None,
        };
        let mut s = AppState::default();
        s.apply(Event::ConsolidationPreview {
            plan_id: 2,
            summary: empty_summary(),
        });
        s.track_transfer_command(&apply);
        s.apply(Event::ConsolidationProgress { done: 1, total: 2 });
        s.apply(Event::Error("Orphan files not retired: busy".into()));
        assert!(s.is_applying_consolidation(), "the apply goes on");
        s.apply(Event::ConsolidationDone(
            ConsolidationReport::default(),
            None,
        ));
        assert!(!s.is_applying_consolidation());
        s.apply(Event::ConsolidationPreview {
            plan_id: 3,
            summary: empty_summary(),
        });
        s.track_transfer_command(&apply);
        s.apply(Event::ApplyPassphrasesNeeded {
            plan_id: 3,
            backup: true,
            orphan_files: false,
        });
        assert!(!s.is_applying_consolidation());
        s.track_transfer_command(&apply);
        s.apply(Event::Error("Backup failed: disk full".into()));
        assert!(!s.is_applying_consolidation());
        assert!(s.consolidation_preview.is_some());
    }

    /// Builds a consolidation preview event with one step holding `conflict`.
    fn consolidation_with(plan_id: u64, conflict: ConflictView) -> Event {
        use crate::worker::StepSummary;
        let mut summary = empty_summary();
        summary.steps.push(StepSummary {
            source: CollectionId("/c/s".into()),
            label: "s".into(),
            counts: TransferCounts::default(),
            conflicts: vec![conflict],
        });
        Event::ConsolidationPreview { plan_id, summary }
    }

    /// Consolidation preview secrets are kept only while its area is shown;
    /// planned target items are never revealable.
    #[test]
    fn consolidation_preview_secrets_need_area() {
        let incoming = ItemId("/c/s/1".into());
        let mut s = AppState::default();
        s.apply(consolidation_with(4, live_conflict("/c/t/1", "/c/s/1")));
        s.track_preview_reveal(incoming.clone());
        s.apply(Event::Secret(incoming.clone(), SecretValue::from_text("v")));
        assert!(s.transfer_secret(&incoming).is_none(), "area not shown");
        s.set_consolidation_shown(true);
        s.track_preview_reveal(incoming.clone());
        s.apply(Event::Secret(incoming.clone(), SecretValue::from_text("v")));
        assert!(s.transfer_secret(&incoming).is_some());
        s.set_consolidation_shown(false);
        assert!(s.transfer_secret(&incoming).is_none());
        let mut planned = live_conflict("planned:0", "/c/s/2");
        planned.existing_planned = true;
        s.set_consolidation_shown(true);
        s.apply(consolidation_with(5, planned));
        s.track_preview_reveal(ItemId("planned:0".into()));
        s.apply(Event::Secret(
            ItemId("planned:0".into()),
            SecretValue::from_text("v"),
        ));
        assert!(s.transfer_secret(&ItemId("planned:0".into())).is_none());
    }

    /// A command dropping the worker plan closes the consolidation preview;
    /// reads keep it. The apply records its backups and an error ends it
    /// with the preview kept.
    #[test]
    fn consolidation_preview_follows_plan() {
        let mut s = AppState::default();
        s.apply(Event::ConsolidationPreview {
            plan_id: 2,
            summary: empty_summary(),
        });
        s.track_transfer_command(&Command::ScanFiles);
        s.track_transfer_command(&Command::RevealSecret(ItemId("/c/a/1".into())));
        assert!(s.consolidation_preview.is_some());
        s.track_transfer_command(&Command::ApplyConsolidation {
            plan_id: 2,
            choices: vec![],
            backup_passphrase: None,
            orphan_files_passphrase: None,
        });
        assert!(s.is_applying_consolidation());
        s.apply(Event::BackupCreated(BackupInfo {
            dir: "/b/1".into(),
            reason: "consolidate".into(),
            created: String::new(),
            files: vec![],
            seq: 0,
            prune_warning: None,
            pruned: vec![],
        }));
        assert_eq!(s.consolidation_backups, [PathBuf::from("/b/1")]);
        s.apply(Event::Error("backup failed".into()));
        assert!(!s.is_applying_consolidation());
        assert!(s.consolidation_preview.is_some());
        s.track_transfer_command(&Command::Unlock {
            collection: CollectionId("/c/d".into()),
            password: SecretValue::from_text("p"),
        });
        assert!(s.consolidation_preview.is_none());
    }

    /// The offline side of a conflict comes from the imported file only while
    /// it is still selected and the label matches.
    #[test]
    fn offline_incoming_needs_imported_file() {
        let mut s = AppState::default();
        s.apply(Event::Files(vec![file("a"), file("b")]));
        s.select_file("a".into());
        s.apply(Event::FileItems {
            name: "a".into(),
            items: vec![offline("x"), offline("y")],
            warnings: vec![],
        });
        let mut c = live_conflict("/c/t/1", "/unused");
        c.incoming_item = None;
        c.offline_index = Some(1);
        c.label_incoming = "y".into();
        assert!(s.offline_incoming(&c).is_none(), "no import sent yet");
        s.track_transfer_command(&Command::ImportFile {
            name: "a".into(),
            password: None,
            target: CollectionId("/c/t".into()),
        });
        assert_eq!(s.offline_incoming(&c).map(|i| i.label.as_str()), Some("y"));
        c.label_incoming = "x".into();
        assert!(s.offline_incoming(&c).is_none(), "label mismatch");
        c.label_incoming = "y".into();
        s.select_file("b".into());
        assert!(s.offline_incoming(&c).is_none(), "another file selected");
    }

    /// Builds a wallet info named `name`.
    fn wallet(name: &str) -> WalletInfo {
        WalletInfo {
            name: name.into(),
            path: format!("/w/{name}.kwl").into(),
            size: 0,
            modified: 0,
            header: None,
            has_attributes: false,
            suggested_target: None,
        }
    }

    /// Builds a wallet entry view labelled `label` with secret `secret`.
    fn wallet_view(label: &str, secret: &str) -> OfflineItemView {
        OfflineItemView {
            label: label.into(),
            attributes: Default::default(),
            folder: "F".into(),
            key: label.into(),
            kind: crate::worker::WalletEntryKind::Password,
            app_entry: false,
            modified: 0,
            secret: SecretValue::from_text(secret),
        }
    }

    /// Builds the event of the entries of wallet `name`.
    fn wallet_items(name: &str, labels: &[&str]) -> Event {
        Event::WalletItems {
            name: name.into(),
            items: labels.iter().map(|l| wallet_view(l, "ws")).collect(),
        }
    }

    /// Entries of another wallet are ignored; changing or closing the wallet
    /// and a rescan without it drop the secrets.
    #[test]
    fn wallet_items_follow_selection() {
        let mut s = AppState::default();
        s.apply(Event::Wallets(vec![wallet("a"), wallet("b")]));
        s.select_wallet("a".into());
        s.apply(wallet_items("b", &["x"]));
        assert!(s.wallet_items.is_empty() && !s.wallet_opened);
        s.apply(wallet_items("a", &["x"]));
        assert_eq!(s.wallet_items.len(), 1);
        assert!(s.wallet_opened);
        s.select_wallet("b".into());
        assert!(s.wallet_items.is_empty() && !s.wallet_opened);
        s.apply(wallet_items("b", &["y"]));
        s.close_wallet();
        assert!(s.wallet_items.is_empty());
        assert_eq!(s.selected_wallet, None);
        s.select_wallet("a".into());
        s.apply(wallet_items("a", &["x"]));
        s.apply(Event::Wallets(vec![wallet("b")]));
        assert_eq!(s.selected_wallet, None, "vanished wallet closed");
        assert!(s.wallet_items.is_empty());
    }

    /// The password of an open request is kept once its entries arrive and
    /// dropped with them (wallet change, close, select again).
    #[test]
    fn wallet_password_kept_while_open() {
        let open = |name: &str, pw: &str| Command::OpenWallet {
            name: name.into(),
            password: SecretValue::from_text(pw),
        };
        let kept = |s: &AppState| {
            s.wallet_password()
                .and_then(|p| p.as_text())
                .map(String::from)
        };
        let mut s = AppState::default();
        s.apply(Event::Wallets(vec![wallet("a"), wallet("b")]));
        s.select_wallet("a".into());
        s.track_wallet_command(&open("a", "pw"), 0);
        assert_eq!(kept(&s), None, "not before the entries");
        s.apply(wallet_items("a", &["x"]));
        assert_eq!(kept(&s).as_deref(), Some("pw"));
        s.select_wallet("b".into());
        assert_eq!(kept(&s), None);
        s.track_wallet_command(&open("b", "pb"), 0);
        s.select_wallet("a".into());
        s.apply(wallet_items("b", &["x"]));
        s.apply(wallet_items("a", &["x"]));
        assert_eq!(kept(&s), None, "request of another selection");
        s.track_wallet_command(&open("a", "zq-wallet-pw"), 0);
        s.apply(wallet_items("a", &["x"]));
        assert_eq!(kept(&s).as_deref(), Some("zq-wallet-pw"));
        assert!(!format!("{s:?}").contains("zq-wallet-pw"));
        s.close_wallet();
        assert_eq!(kept(&s), None);
    }

    /// The `Done` of a wallet keyring creation (and only that command's)
    /// continues the import of the still open wallet, once.
    #[test]
    fn wallet_created_continues_import() {
        let mut s = AppState::default();
        s.apply(Event::Wallets(vec![wallet("a")]));
        s.select_wallet("a".into());
        s.track_wallet_command(
            &Command::OpenWallet {
                name: "a".into(),
                password: SecretValue::from_text("pw"),
            },
            0,
        );
        s.apply(wallet_items("a", &["x"]));
        s.apply(Event::CommandFinished(0));
        let create = Command::CreateWalletCollection {
            name: "a".into(),
            password: SecretValue::from_text("n"),
        };
        s.track_wallet_command(&create, 1);
        s.apply(Event::Error("Cannot rescan the wallets: x".into()));
        s.apply(Event::Done("Keyring 'a' created".into()));
        s.apply(Event::CommandFinished(1));
        assert_eq!(s.take_wallet_created().as_deref(), Some("a"));
        assert_eq!(s.take_wallet_created(), None, "once");

        s.track_wallet_command(&create, 2);
        s.apply(Event::Error("A keyring named 'a' already exists".into()));
        s.apply(Event::CommandFinished(2));
        s.apply(Event::Done("Item deleted".into()));
        assert_eq!(s.take_wallet_created(), None, "failed creation");

        s.track_wallet_command(&create, 3);
        s.apply(Event::Done("Keyring 'a' created".into()));
        s.close_wallet();
        assert_eq!(s.take_wallet_created(), None, "wallet closed");
    }

    /// The offline side of a wallet import preview is revealable only while
    /// the imported wallet is open with its entries.
    #[test]
    fn wallet_preview_reveal_needs_open_wallet() {
        let mut s = AppState::default();
        s.apply(Event::Wallets(vec![wallet("a"), wallet("b")]));
        let mut c = live_conflict("/c/t/1", "/unused");
        c.incoming_item = None;
        c.offline_index = Some(1);
        c.label_incoming = "y".into();
        let import = Command::PlanWalletImport {
            name: "a".into(),
            password: SecretValue::from_text("pw"),
            target: CollectionId("/c/t".into()),
        };
        s.track_transfer_command(&import);
        s.apply(preview_with(1, vec![c.clone()]));
        let shown = |s: &AppState| s.transfer_preview.as_ref().unwrap().conflicts[0].clone();
        assert!(!shown(&s).incoming_revealable, "wallet not open");
        assert!(s.wallet_incoming(&shown(&s)).is_none());
        s.select_wallet("a".into());
        s.apply(wallet_items("a", &["x", "y"]));
        assert!(shown(&s).incoming_revealable);
        let secret = s
            .offline_incoming_secret(&shown(&s))
            .and_then(|v| v.as_text());
        assert_eq!(secret, Some("ws"));
        s.select_wallet("b".into());
        s.apply(wallet_items("b", &["x", "y"]));
        assert!(!shown(&s).incoming_revealable, "another wallet open");
        assert!(s.offline_incoming_secret(&shown(&s)).is_none());
        s.select_wallet("a".into());
        s.apply(wallet_items("a", &["x", "y"]));
        s.apply(preview_with(2, vec![c.clone()]));
        assert!(
            shown(&s).incoming_revealable,
            "new preview of the open wallet"
        );
        s.close_wallet();
        assert!(!shown(&s).incoming_revealable, "closed on area switch");
        s.track_transfer_command(&Command::PlanFileImport {
            name: "f".into(),
            password: None,
            target: CollectionId("/c/t".into()),
        });
        s.select_wallet("a".into());
        s.apply(wallet_items("a", &["x", "y"]));
        assert!(
            s.wallet_incoming(&c).is_none(),
            "a file import is not the wallet's"
        );
    }

    /// A worker notice is queued as a toast, not as an error.
    #[test]
    fn notice_is_queued() {
        let mut s = AppState::default();
        s.apply(Event::Notice("KWallet is still running".into()));
        assert_eq!(s.drain_notices(), ["KWallet is still running"]);
        assert!(s.errors.is_empty());
    }

    /// The remembered passphrase never shows in the `Debug` output of the state.
    #[test]
    fn debug_hides_remembered_passphrase() {
        const PASS: &str = "s3ssion-passphrase-xyz";
        let mut s = AppState::default();
        s.session.remember(SecretValue::from_text(PASS));
        let text = format!("{s:?}");
        assert!(s.session.is_remembered());
        assert!(!text.contains(PASS));
        assert!(text.contains("SessionSecret { remembered: true }"));
    }

    /// A destructive command opens the operation, its events finish it.
    #[test]
    fn operation_follows_events() {
        let mut s = AppState::default();
        s.track_operation(&Command::Refresh, 0);
        assert!(!s.operation_open());
        s.track_operation(
            &Command::DeleteFile {
                name: "old".into(),
                backup: false,
                backup_passphrase: None,
            },
            1,
        );
        assert!(s.operation_open());
        // The Done of command 0 is not the delete's.
        s.apply(Event::Done("Refreshed".into()));
        s.apply(Event::CommandFinished(0));
        assert!(!s.operation.as_ref().unwrap().is_finished());
        assert_eq!(s.running_command(), 1);
        s.apply(Event::Done("File old deleted".into()));
        s.apply(Event::CommandFinished(1));
        let op = s.operation.as_ref().unwrap();
        assert!(op.is_finished() && !op.is_failed());
        s.drop_stuck_operation(false);
        assert!(s.operation_open(), "a finished operation waits for Close");
    }

    /// An operation waiting for a passphrase that no dialog asks for is dropped.
    #[test]
    fn stuck_waiting_operation_dropped() {
        let mut s = AppState::default();
        s.track_operation(
            &Command::DeleteFile {
                name: "p".into(),
                backup: true,
                backup_passphrase: None,
            },
            0,
        );
        s.apply(Event::ApplyPassphrasesNeeded {
            plan_id: 9,
            backup: true,
            orphan_files: false,
        });
        s.apply(Event::CommandFinished(0));
        assert!(s.operation.as_ref().unwrap().is_waiting());
        s.drop_stuck_operation(true);
        assert!(s.operation_open(), "kept while its dialog is open");
        s.drop_stuck_operation(false);
        assert!(!s.operation_open());
    }
    /// A scanned SSH key named `name` with fingerprint `fp`.
    fn ssh_key(name: &str, fp: &str) -> SshKeyInfo {
        SshKeyInfo {
            name: name.into(),
            private_path: Some(PathBuf::from(format!("/k/{name}"))),
            public_path: None,
            algorithm: kring_core::ssh::SshAlgorithm::Ed25519,
            bits: Some(256),
            fingerprint: fp.into(),
            comment: String::new(),
            encrypted: Some(false),
            legacy_format: false,
            pub_mismatch: false,
        }
    }

    /// SSH keys replace the list; a selected key that disappears is
    /// deselected with its public key text.
    #[test]
    fn ssh_keys_and_selection() {
        let mut s = AppState::default();
        s.apply(Event::SshKeys(vec![
            ssh_key("a", "SHA256:a"),
            ssh_key("b", "SHA256:b"),
        ]));
        s.select_ssh_key("a".into());
        s.apply(Event::SshPublicKey {
            name: "a".into(),
            text: "ssh-ed25519 AAAA a".into(),
        });
        assert_eq!(
            s.ssh_public_key.as_ref().map(|(n, _)| n.as_str()),
            Some("a")
        );
        // A late answer for another key is dropped.
        s.apply(Event::SshPublicKey {
            name: "b".into(),
            text: "ssh-ed25519 BBBB b".into(),
        });
        assert_eq!(
            s.ssh_public_key.as_ref().map(|(n, _)| n.as_str()),
            Some("a")
        );
        s.apply(Event::SshKeys(vec![ssh_key("a", "SHA256:a")]));
        assert_eq!(s.selected_ssh_key.as_deref(), Some("a"));
        assert!(s.ssh_public_key.is_some());
        s.apply(Event::SshKeys(vec![ssh_key("a", "SHA256:changed")]));
        assert!(
            s.ssh_public_key.is_none(),
            "dropped when the fingerprint changed"
        );
        s.apply(Event::SshPublicKey {
            name: "a".into(),
            text: "ssh-ed25519 AAAA a".into(),
        });
        s.select_ssh_key("b".into());
        assert!(s.ssh_public_key.is_none(), "dropped on selection change");
        s.apply(Event::SshKeys(vec![ssh_key("a", "SHA256:a")]));
        assert!(s.selected_ssh_key.is_none());
    }

    /// GPG keys and unavailability replace each other; a public key text is
    /// kept only while its key is listed. Only a scan result clears the
    /// list: an action finding gpg unusable keeps it (banner only).
    #[test]
    fn gpg_keys_and_unavailability() {
        let listing = include_bytes!("../../kring-core/tests/fixtures/gpg/list-keys.txt");
        let keys = kring_core::gpg::parse_listing(listing);
        let fpr = keys[0].fingerprint.clone();
        let unavailable = |reason: &str, scan: bool| Event::GpgUnavailable {
            reason: reason.into(),
            scan,
        };
        let mut s = AppState::default();
        s.apply(Event::GpgPublicKey {
            fpr: fpr.clone(),
            text: "armored".into(),
        });
        assert!(s.gpg_public_key.is_none(), "unknown key dropped");
        s.apply(unavailable("no gpg", true));
        assert_eq!(s.gpg_unavailable.as_deref(), Some("no gpg"));
        s.apply(Event::GpgKeys(keys.clone()));
        assert!(s.gpg_unavailable.is_none());
        assert_eq!(s.gpg_keys.len(), keys.len());
        s.apply(Event::GpgPublicKey {
            fpr: fpr.clone(),
            text: "armored".into(),
        });
        assert_eq!(
            s.gpg_public_key.as_ref().map(|(f, _)| f.as_str()),
            Some(fpr.as_str())
        );
        s.apply(Event::GpgKeys(keys[1..].to_vec()));
        assert!(s.gpg_public_key.is_none(), "dropped with its key");
        s.apply(Event::GpgKeys(keys.clone()));
        s.apply(Event::GpgPublicKey {
            fpr,
            text: "armored".into(),
        });
        s.apply(unavailable("refused", false));
        assert_eq!(s.gpg_unavailable.as_deref(), Some("refused"));
        assert_eq!(s.gpg_keys.len(), keys.len(), "an action keeps the list");
        assert!(s.gpg_public_key.is_some());
        s.apply(unavailable("refused", true));
        assert!(s.gpg_keys.is_empty() && s.gpg_public_key.is_none());
        assert!(s.errors.is_empty(), "never an error toast");
    }

    /// Selecting a GPG key drops the public key text of another one; a
    /// selection whose key is no longer listed is dropped.
    #[test]
    fn gpg_key_selection() {
        let listing = include_bytes!("../../kring-core/tests/fixtures/gpg/list-keys.txt");
        let keys = kring_core::gpg::parse_listing(listing);
        let (a, b) = (keys[0].fingerprint.clone(), keys[1].fingerprint.clone());
        let mut s = AppState::default();
        s.apply(Event::GpgKeys(keys.clone()));
        s.select_gpg_key(a.clone());
        s.apply(Event::GpgPublicKey {
            fpr: a.clone(),
            text: "armored".into(),
        });
        s.select_gpg_key(a.clone());
        assert!(s.gpg_public_key.is_some(), "same key keeps its text");
        s.select_gpg_key(b.clone());
        assert!(s.gpg_public_key.is_none());
        assert_eq!(s.selected_gpg_key.as_deref(), Some(b.as_str()));
        s.apply(Event::GpgKeys(keys[..1].to_vec()));
        assert!(s.selected_gpg_key.is_none(), "deleted key deselected");
    }

    /// A backup passphrase request for a GPG command cannot be answered by
    /// a resend (the key passphrases were cleared): it becomes an error.
    #[test]
    fn gpg_passphrase_requests() {
        let mut s = AppState::default();
        let delete = Command::DeleteGpgKey {
            fpr: "A".repeat(40),
            key_passphrase: None,
            backup_passphrase: None,
        };
        s.apply(Event::PassphraseNeeded(Box::new(delete)));
        let change = Command::ChangeGpgPassphrase {
            fpr: "A".repeat(40),
            old: None,
            new: None,
            backup_passphrase: None,
        };
        s.apply(Event::PassphraseNeeded(Box::new(change)));
        assert!(s.pending_passphrase.is_none());
        assert_eq!(s.errors, [MSG_KEY_CHANGED, MSG_KEY_CHANGED]);
    }

    /// Agent identities and unavailability replace each other; a key is in
    /// the agent when its fingerprint is listed.
    #[test]
    fn agent_status() {
        use kring_core::ssh::{AgentIdentity, SshAlgorithm};
        let mut s = AppState::default();
        let id = AgentIdentity {
            fingerprint: "SHA256:a".into(),
            comment: "c".into(),
            algorithm: SshAlgorithm::Ed25519,
        };
        s.apply(Event::AgentIdentities(AgentStatus::Available(vec![id])));
        assert_eq!(s.agent_identities.len(), 1);
        assert!(s.agent_unavailable.is_none());
        assert!(s.ssh_key_in_agent(&ssh_key("a", "SHA256:a")));
        assert!(!s.ssh_key_in_agent(&ssh_key("b", "SHA256:b")));
        assert!(!s.ssh_key_in_agent(&ssh_key("legacy", "")));
        s.apply(Event::AgentIdentities(AgentStatus::Unavailable(
            "gone".into(),
        )));
        assert!(s.agent_identities.is_empty());
        assert_eq!(s.agent_unavailable.as_deref(), Some("gone"));
        assert!(!s.ssh_key_in_agent(&ssh_key("a", "SHA256:a")));
        assert!(s.errors.is_empty(), "never an error toast");
    }

    /// A backup passphrase request for an SSH command whose key
    /// passphrases were cleared cannot be answered by a resend: it becomes
    /// an error; a delete request still opens the passphrase dialog.
    #[test]
    fn ssh_passphrase_requests() {
        let mut s = AppState::default();
        s.apply(Event::PassphraseNeeded(Box::new(
            Command::ChangeSshPassphrase {
                name: "k".into(),
                old: None,
                new: None,
                allow_unencrypted: false,
                backup_passphrase: None,
            },
        )));
        assert!(s.pending_passphrase.is_none());
        assert_eq!(s.errors, [MSG_KEY_CHANGED]);
        let delete = Command::DeleteSshKey {
            name: "k".into(),
            backup_passphrase: None,
        };
        s.apply(Event::PassphraseNeeded(Box::new(delete)));
        assert!(matches!(
            s.pending_passphrase,
            Some(Command::DeleteSshKey { .. })
        ));
    }

    /// Failed keyrings of an unlock-many summary named `names`, all with `reason`.
    fn failures(names: &[&str], reason: &str) -> Vec<(String, String)> {
        names
            .iter()
            .map(|n| (n.to_string(), reason.to_string()))
            .collect()
    }

    /// The summary counts the unlocked keyrings and names at most three
    /// failed ones; a reason they share follows in parentheses.
    #[test]
    fn unlock_many_summary_texts() {
        assert_eq!(unlock_many_summary(3, &[]), "Unlocked 3 of 3 keyrings");
        let one = failures(&["A"], "invalid password");
        assert_eq!(
            unlock_many_summary(2, &one),
            "Unlocked 2 of 3 keyrings, 1 failed: A (invalid password)"
        );
        let five = failures(&["A", "B", "C", "D", "E"], "invalid password");
        assert_eq!(
            unlock_many_summary(0, &five),
            "Unlocked 0 of 5 keyrings, 5 failed: A, B, C and 2 more (invalid password)"
        );
        let mixed = vec![
            ("A".to_string(), "invalid password".to_string()),
            ("B".to_string(), "gone".to_string()),
        ];
        assert_eq!(
            unlock_many_summary(1, &mixed),
            "Unlocked 1 of 3 keyrings, 2 failed: A, B"
        );
    }

    /// All unlocked is a success status, some failed an info notice, none
    /// unlocked an error.
    #[test]
    fn unlock_many_done_toasts() {
        let mut s = AppState::default();
        // Failed keyrings are named as the list shows them.
        s.apply(Event::Collections(vec![
            col("/c/A", "Dk", &[]),
            col("/c/B", "Dk", &[]),
        ]));
        s.apply(Event::UnlockManyDone {
            unlocked: 1,
            failed: vec![(CollectionId("/c/B".into()), "x".into())],
        });
        assert_eq!(
            s.drain_notices(),
            ["Unlocked 1 of 2 keyrings, 1 failed: Dk · B (x)"]
        );
        // An unlisted keyring falls back to its object path name.
        s.apply(Event::UnlockManyDone {
            unlocked: 0,
            failed: vec![(CollectionId("/c/gone".into()), "x".into())],
        });
        assert_eq!(
            s.drain_messages(),
            (
                None,
                vec!["Unlocked 0 of 1 keyring, 1 failed: gone (x)".to_string()]
            )
        );
        s.apply(Event::UnlockManyDone {
            unlocked: 2,
            failed: vec![],
        });
        assert_eq!(
            s.drain_messages(),
            (Some("Unlocked 2 of 2 keyrings".to_string()), vec![])
        );
        assert_eq!(s.drain_messages(), (None, vec![]));
        assert!(s.drain_notices().is_empty());
    }

    /// The consolidation preview asked last.
    fn plan(target: &str) -> Command {
        Command::PlanConsolidation {
            target: CollectionId(target.into()),
            include_orphan_files: true,
        }
    }

    /// An unlock sent from the Consolidate area after a preview re-runs
    /// that preview once its command finished (and only then, once).
    #[test]
    fn unlock_from_consolidate_repreviews() {
        let mut s = AppState::default();
        s.set_consolidation_shown(true);
        s.track_consolidation_command(&plan("/c/login"), 0);
        let many = Command::UnlockMany {
            collections: vec![CollectionId("/c/a".into())],
            password: SecretValue::from_text("pw"),
        };
        s.track_consolidation_command(&many, 1);
        s.apply(Event::CommandFinished(0));
        assert!(s.take_repreview().is_none());
        s.apply(Event::CommandFinished(1));
        let Some(Command::PlanConsolidation {
            target,
            include_orphan_files: true,
        }) = s.take_repreview()
        else {
            panic!("expected the same preview again");
        };
        assert_eq!(target.0, "/c/login");
        assert!(s.take_repreview().is_none(), "only once");
        let single = Command::Unlock {
            collection: CollectionId("/c/a".into()),
            password: SecretValue::from_text("pw"),
        };
        s.track_consolidation_command(&single, 2);
        s.apply(Event::CommandFinished(2));
        assert!(s.take_repreview().is_some(), "a single unlock too");
    }

    /// A failed unlock (an error in its command window) changed nothing:
    /// no re-preview; an error of another command does not count.
    #[test]
    fn failed_unlock_skips_repreview() {
        let unlock = Command::Unlock {
            collection: CollectionId("/c/a".into()),
            password: SecretValue::from_text("pw"),
        };
        let mut s = AppState::default();
        s.set_consolidation_shown(true);
        s.track_consolidation_command(&plan("/c/login"), 0);
        s.apply(Event::CommandFinished(0));
        s.track_consolidation_command(&unlock, 1);
        s.apply(Event::Error("invalid password".into()));
        s.apply(Event::CommandFinished(1));
        assert!(s.take_repreview().is_none(), "failed unlock");
        // Command 2 is still running when unlock 3 is sent.
        s.track_consolidation_command(&unlock, 3);
        s.apply(Event::Error("error of command 2".into()));
        s.apply(Event::CommandFinished(2));
        s.apply(Event::Done("Collection unlocked".into()));
        s.apply(Event::CommandFinished(3));
        assert!(s.take_repreview().is_some(), "clean unlock");
    }

    /// No re-preview outside the Consolidate area, without a preview asked,
    /// or after the flow ended (cancel, apply, leaving the area).
    #[test]
    fn repreview_only_in_preview_flow() {
        let unlock = Command::Unlock {
            collection: CollectionId("/c/a".into()),
            password: SecretValue::from_text("pw"),
        };
        let mut s = AppState::default();
        s.track_consolidation_command(&plan("/c/login"), 0);
        s.track_consolidation_command(&unlock, 1);
        s.apply(Event::CommandFinished(1));
        assert!(s.take_repreview().is_none(), "area not shown");
        let mut s = AppState::default();
        s.set_consolidation_shown(true);
        s.track_consolidation_command(&unlock, 0);
        s.apply(Event::CommandFinished(0));
        assert!(s.take_repreview().is_none(), "no preview asked");
        s.track_consolidation_command(&plan("/c/login"), 1);
        s.forget_consolidation_request();
        s.track_consolidation_command(&unlock, 2);
        s.apply(Event::CommandFinished(2));
        assert!(s.take_repreview().is_none(), "cancelled");
        s.track_consolidation_command(&plan("/c/login"), 3);
        s.apply(Event::ConsolidationDone(
            ConsolidationReport {
                outcomes: vec![],
                completed: true,
            },
            None,
        ));
        s.track_consolidation_command(&unlock, 4);
        s.apply(Event::CommandFinished(4));
        assert!(s.take_repreview().is_none(), "applied");
        s.track_consolidation_command(&plan("/c/login"), 5);
        s.track_consolidation_command(&unlock, 6);
        s.set_consolidation_shown(false);
        s.apply(Event::CommandFinished(6));
        assert!(s.take_repreview().is_none(), "area left");
    }
    /// Same-label keyrings are listed in the natural order of their ids.
    #[test]
    fn same_labels_sorted_naturally_by_id() {
        let mut state = AppState::default();
        let mk = |id: &str| CollectionInfo {
            id: CollectionId(format!("/org/freedesktop/secrets/collection/{id}")),
            label: "Default keyring".into(),
            locked: true,
            item_count: 0,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        };
        state.apply(Event::Collections(vec![
            mk("Default_5fkeyring_5f10"),
            mk("Default_5fkeyring_5f3"),
            mk("Default_5fkeyring"),
        ]));
        let keys: Vec<String> = state
            .collections
            .iter()
            .map(|c| collection_key(&c.id))
            .collect();
        assert_eq!(
            keys,
            ["Default_keyring", "Default_keyring_3", "Default_keyring_10"]
        );
    }
}
