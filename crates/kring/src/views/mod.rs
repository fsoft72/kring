//! Views of the main window and the actions they request.

pub mod attr_diff;
pub mod collection;
pub mod dialog_body;
pub mod dialog_submit;
pub mod dialogs;
pub mod item_detail;
pub mod sidebar;

use eframe::egui;
use kring_core::model::{CollectionId, ItemId};
use kring_core::provider::ProviderInfo;

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
    /// Select an item (does not reveal its secret).
    SelectItem(ItemId),
    /// Hide the revealed secret.
    HideSecret,
    /// Copy the secret of the selected item to the clipboard.
    CopySecret,
    /// Open a modal dialog.
    Open(DialogKind),
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

/// Adds a button that is disabled with `blocked` as tooltip; returns true when clicked.
pub fn gated_button(ui: &mut egui::Ui, text: &str, blocked: Option<&str>) -> bool {
    let response = ui.add_enabled(blocked.is_none(), egui::Button::new(text));
    match blocked {
        Some(reason) => response.on_disabled_hover_text(reason).clicked(),
        None => response.clicked(),
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

    /// No provider blocks everything.
    #[test]
    fn no_provider_blocks_all() {
        let g = Gates::from_provider(None);
        assert_eq!(g.write, Some(MSG_NO_PROVIDER));
        assert_eq!(g.master, Some(MSG_NO_PROVIDER));
    }
}
