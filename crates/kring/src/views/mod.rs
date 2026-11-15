//! Views of the main window and the actions they request.

pub mod attr_diff;
pub mod backups;
pub mod banners;
pub mod collection;
pub mod dialog_body;
pub mod dialog_submit;
pub mod dialogs;
pub mod file_detail;
pub mod file_items;
pub mod files_list;
pub mod item_detail;
pub mod item_list;
pub mod rail;
pub mod sidebar;

use kring_core::model::{CollectionId, ItemId};
use kring_core::provider::ProviderInfo;

use crate::app_state::AppState;
use crate::worker::Command;
use dialogs::DialogKind;

/// Tooltip of write actions when the provider is not gnome-keyring.
pub const MSG_READ_ONLY: &str = "Read only: provider is not gnome-keyring";
/// Tooltip of master password actions when the private interface is missing.
pub const MSG_NEEDS_GNOME_KEYRING: &str = "Requires gnome-keyring";
/// Tooltip of every action while no provider is available.
pub const MSG_NO_PROVIDER: &str = "No Secret Service provider running";

/// Something a view asks the application to do.
pub enum Action {
    /// Send a command to the worker.
    Send(Command),
    /// Select a collection and load its items.
    SelectCollection(CollectionId),
    /// Select (expand) an item; does not reveal its secret.
    SelectItem(ItemId),
    /// Collapse the expanded item and hide its secret.
    DeselectItem,
    /// Hide the revealed secret.
    HideSecret,
    /// Copy the secret of the selected item to the clipboard.
    CopySecret,
    /// Open a modal dialog.
    Open(DialogKind),
    /// Switch to another area of the rail.
    SwitchArea(Area),
    /// Select a keyring file (textual files are opened right away).
    SelectFile(String),
    /// Copy the secret of `state.file_items[index]` to the clipboard.
    CopyFileSecret(usize),
}

/// Area of the window selected in the nav rail.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Area {
    /// Secret Service keyrings and their items.
    #[default]
    Secrets,
    /// Keyring files on disk, read offline.
    Files,
    /// Backups of the keyring files and their restore.
    Backups,
}

/// Commands that load the data of the Backups area: the backups, and the
/// keyring files to tell which restore destinations are plaintext.
pub fn backups_commands() -> Vec<Command> {
    vec![Command::ListBackups, Command::ScanFiles]
}

/// Switches from area `from` to `to`; returns the commands to send on entry.
///
/// Leaving the Offline files area closes the selected file, dropping its
/// secrets; leaving the Backups area forgets the last restore. Any switch
/// drops the report of the last import. Entering Files rescans the keyrings
/// directory; entering Backups lists the backups too.
pub fn switch_area(state: &mut AppState, from: Area, to: Area) -> Vec<Command> {
    if from == to {
        return Vec::new();
    }
    match from {
        Area::Files => state.close_file(),
        Area::Backups => state.last_restore = None,
        Area::Secrets => {}
    }
    state.last_import = None;
    match to {
        Area::Files => vec![Command::ScanFiles],
        Area::Backups => backups_commands(),
        Area::Secrets => Vec::new(),
    }
}

/// Why groups of actions are disabled; `None` means allowed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Gates {
    /// Blocks write and destructive actions.
    pub write: Option<&'static str>,
    /// Blocks master password actions (create, unlock, change password).
    pub master: Option<&'static str>,
}

impl Gates {
    /// Computes the gates from the detected provider.
    pub fn from_provider(provider: Option<&ProviderInfo>) -> Self {
        let Some(p) = provider else {
            return Self {
                write: Some(MSG_NO_PROVIDER),
                master: Some(MSG_NO_PROVIDER),
            };
        };
        Self {
            write: (!p.allows_writes()).then_some(MSG_READ_ONLY),
            master: (!p.has_master_password_iface).then_some(MSG_NEEDS_GNOME_KEYRING),
        }
    }

    /// Gate of actions needing both writes and the master password interface.
    pub fn write_and_master(&self) -> Option<&'static str> {
        self.write.or(self.master)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kring_core::provider::ProviderKind;

    /// Builds a provider of the given kind.
    fn provider(kind: ProviderKind, master: bool) -> ProviderInfo {
        ProviderInfo {
            kind,
            pid: None,
            process_name: None,
            competitors: vec![],
            has_master_password_iface: master,
        }
    }

    /// gnome-keyring with the private interface allows everything.
    #[test]
    fn gnome_keyring_allows_all() {
        let g = Gates::from_provider(Some(&provider(ProviderKind::GnomeKeyring, true)));
        assert_eq!(
            g,
            Gates {
                write: None,
                master: None
            }
        );
        assert_eq!(g.write_and_master(), None);
    }

    /// Other providers are read only and lack master password support.
    #[test]
    fn other_provider_read_only() {
        let g = Gates::from_provider(Some(&provider(ProviderKind::KWallet, false)));
        assert_eq!(g.write, Some(MSG_READ_ONLY));
        assert_eq!(g.master, Some(MSG_NEEDS_GNOME_KEYRING));
        assert_eq!(g.write_and_master(), Some(MSG_READ_ONLY));
    }

    /// gnome-keyring without the private interface blocks only master actions.
    #[test]
    fn missing_master_iface() {
        let g = Gates::from_provider(Some(&provider(ProviderKind::GnomeKeyring, false)));
        assert_eq!(g.write, None);
        assert_eq!(g.write_and_master(), Some(MSG_NEEDS_GNOME_KEYRING));
    }

    /// Leaving the files area closes the file; entering it rescans; staying does nothing.
    #[test]
    fn switch_area_closes_file_and_rescans() {
        let mut s = AppState::default();
        s.select_file("a".into());
        assert!(switch_area(&mut s, Area::Files, Area::Files).is_empty());
        assert_eq!(s.selected_file.as_deref(), Some("a"));
        assert!(switch_area(&mut s, Area::Files, Area::Secrets).is_empty());
        assert!(s.selected_file.is_none());
        let cmds = switch_area(&mut s, Area::Secrets, Area::Files);
        assert!(matches!(&cmds[..], [Command::ScanFiles]));
    }

    /// Entering Backups lists backups and files; leaving forgets the restore
    /// and the import report.
    #[test]
    fn switch_area_backups() {
        use kring_core::backup::RestoreReport;
        use kring_core::transfer::import::ImportReport;
        let mut s = AppState::default();
        let cmds = switch_area(&mut s, Area::Secrets, Area::Backups);
        assert!(matches!(
            &cmds[..],
            [Command::ListBackups, Command::ScanFiles]
        ));
        s.last_restore = Some(RestoreReport {
            restored: vec![],
            pre_restore_backup: None,
        });
        s.last_import = Some(ImportReport::default());
        assert!(switch_area(&mut s, Area::Backups, Area::Secrets).is_empty());
        assert!(s.last_restore.is_none() && s.last_import.is_none());
    }

    /// No provider blocks everything.
    #[test]
    fn no_provider_blocks_all() {
        let g = Gates::from_provider(None);
        assert_eq!(g.write, Some(MSG_NO_PROVIDER));
        assert_eq!(g.master, Some(MSG_NO_PROVIDER));
    }
}
