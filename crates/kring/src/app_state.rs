//! UI-side application state, updated by worker events.

use kring_core::backup::{BackupInfo, RestoreReport};
use kring_core::keyring_file::KeyringFileInfo;
use kring_core::keyring_file::textual::{OfflineItem, ParseWarning};
use kring_core::model::{CollectionId, CollectionInfo, ItemId, ItemInfo, SecretValue};
use kring_core::pam::PamStatus;
use kring_core::provider::ProviderInfo;
use kring_core::transfer::import::ImportReport;

use crate::worker::{Command, Event};

/// Maximum number of error messages kept.
const MAX_ERRORS: usize = 20;
/// Alias of the default collection.
const DEFAULT_ALIAS: &str = "default";

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
    /// Parse warnings of the selected file.
    pub file_warnings: Vec<ParseWarning>,
    /// Binary keyring file waiting for its password.
    pub pending_file_password: Option<String>,
    /// Backups, newest first.
    pub backups: Vec<BackupInfo>,
    /// Outcome of the last import.
    pub last_import: Option<ImportReport>,
    /// Outcome of the last restore.
    pub last_restore: Option<RestoreReport>,
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
            }
            Event::PasswordNeeded(name) => self.pending_file_password = Some(name),
            Event::ImportDone(report) => self.last_import = Some(report),
            Event::Backups(v) => self.backups = v,
            Event::RestoreDone(report) => self.last_restore = Some(report),
            Event::Done(msg) => self.status = msg,
            Event::Error(msg) => {
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
        self.pending_file_password = None;
    }

    /// Selects a collection and clears everything below it.
    pub fn select_collection(&mut self, id: CollectionId) {
        self.selected = Some(id);
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
}
