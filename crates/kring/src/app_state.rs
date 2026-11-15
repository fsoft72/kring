//! UI-side application state, updated by worker events.

use kring_core::backup::{BackupInfo, RestoreReport};
use kring_core::keyring_file::textual::{OfflineItem, ParseWarning};
use kring_core::keyring_file::{KeyringFileInfo, RetireBatchReport};
use kring_core::model::{CollectionId, CollectionInfo, ItemId, ItemInfo, SecretValue};
use kring_core::pam::PamStatus;
use kring_core::provider::ProviderInfo;
use kring_core::transfer::apply::{TransferMode, TransferReport};
use kring_core::transfer::consolidate_apply::{ConsolidationReport, StepOutcome};
use kring_core::transfer::import::ImportReport;
use kring_core::transfer::plan::TransferCounts;

use crate::worker::{Command, ConflictView, ConsolidationSummary, Event};

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
        _count(report.created, "item"),
        _count(report.duplicates, "duplicate"),
        _count(report.conflicts.len(), "conflict"),
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
        _count(report.created, "item"),
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
            _count(r.removed.len(), "orphan file")
        ),
        None => "Consolidation complete".to_string(),
    }
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

/// Formats `n noun`, adding `s` unless `n` is 1.
fn _count(n: usize, noun: &str) -> String {
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
    /// Set when a backup was created or restored since the last listing.
    backups_stale: bool,
    /// Notices shown as toasts besides `status` (e.g. pruned backups).
    notices: Vec<String>,
}

/// Sort key: login first, then default alias, then label (case-insensitive).
fn _sort_key(c: &CollectionInfo) -> (bool, bool, String) {
    let is_default = c.aliases.iter().any(|a| a == DEFAULT_ALIAS);
    (!c.is_login, !is_default, c.label.to_lowercase())
}

impl AppState {
    /// Applies a worker event to the state.
    pub fn apply(&mut self, event: Event) {
        match event {
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
                if self.selected_item.as_ref() == Some(&id) {
                    self.revealed = Some((id, s));
                }
            }
            Event::BackupCreated(info) => {
                self.status = format!("Backup created: {}", info.dir.display());
                self.backups_stale = true;
                if !info.pruned.is_empty() {
                    let removed = _count(info.pruned.len(), "old backup");
                    self.notices.push(format!("Removed {removed}"));
                }
            }
            Event::PassphraseNeeded(cmd) => self.pending_passphrase = Some(*cmd),
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
                self.transfer_preview = Some(TransferPreview {
                    plan_id,
                    target,
                    mode,
                    counts,
                    conflicts,
                });
                self.consolidation_preview = None;
                self.consolidation_progress = None;
                self.pending_apply_passphrases = None;
            }
            Event::TransferDone(report) => {
                self.status = transfer_summary(&report);
                self.last_transfer = Some(report);
                self.transfer_preview = None;
                self.pending_apply_passphrases = None;
            }
            Event::ConsolidationPreview { plan_id, summary } => {
                self.consolidation_preview = Some((plan_id, summary));
                self.consolidation_progress = None;
                self.last_consolidation = None;
                self.transfer_preview = None;
                self.pending_apply_passphrases = None;
            }
            Event::ConsolidationProgress { done, total } => {
                self.consolidation_progress = Some((done, total));
            }
            Event::ConsolidationDone(report, retired) => {
                self.status = consolidation_status(&report, retired.as_ref());
                self.consolidation_preview = None;
                self.consolidation_progress = None;
                self.pending_apply_passphrases = None;
                self.last_consolidation = Some((report, retired));
            }
            Event::ApplyPassphrasesNeeded {
                plan_id,
                backup,
                orphan_files,
            } => {
                self.pending_apply_passphrases = Some(ApplyPassphrases {
                    plan_id,
                    backup,
                    orphan_files,
                });
            }
            Event::Done(msg) => self.status = msg,
            Event::Error(msg) => {
                self.consolidation_progress = None;
                if msg.starts_with(STALE_PLAN_PREFIX) {
                    self.transfer_preview = None;
                    self.consolidation_preview = None;
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
        v.sort_by_cached_key(_sort_key);
        self.collections = v;
        let exists = self
            .selected
            .as_ref()
            .is_some_and(|s| self.collections.iter().any(|c| &c.id == s));
        if !exists && self.selected.is_some() {
            self.selected = None;
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
}
