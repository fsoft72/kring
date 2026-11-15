//! List panel "SSH keys": rescan, New key / Import, search, the key rows
//! and, at the bottom, the identities loaded in the ssh-agent.

use std::path::Path;

use eframe::egui::{self, Align, Color32, Layout, RichText, Sense, Ui, UiBuilder};
use kring_core::ssh::{AgentIdentity, SshAlgorithm, SshKeyInfo};

use crate::app_state::{AppState, count_noun};
use crate::ui::glyphs::Ico;
use crate::ui::theme;
use crate::ui::widgets::{
    card, chip, field_label, ico_button, muted, muted_text, primary_button, search_box,
    secondary_button, semibold,
};
use crate::views::Action;
use crate::views::dialog_ssh::SshDialog;
use crate::views::dialogs::DialogKind;
use crate::views::sidebar::row_background;
use crate::worker::{Command, MSG_NO_SSH_DIR};

/// Height of a key row (name and fingerprint lines).
const ROW_HEIGHT: f32 = 56.0;
/// Horizontal padding inside a row.
const ROW_PADDING: f32 = 12.0;
/// Height kept for the agent section at the bottom of the panel.
const AGENT_HEIGHT: f32 = 210.0;
/// Height of an agent identity row.
const AGENT_ROW_HEIGHT: f32 = 40.0;
/// Text of the agent section without identities.
const MSG_AGENT_EMPTY: &str = "No identities loaded";
/// Tooltip of "Remove all" without identities.
const MSG_NOTHING_TO_REMOVE: &str = "The agent holds no identities";
/// Tooltip of "Remove all" while the agent is unavailable.
pub const MSG_AGENT_UNAVAILABLE: &str = "The ssh-agent is not available";

/// A chip of an SSH key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyChip {
    /// Key type, e.g. `ed25519` or `rsa 3072` (painted uppercase).
    Algorithm(String),
    /// Legacy PEM / PKCS#8 private key (read only).
    Legacy,
    /// The private key is passphrase-protected.
    Encrypted,
    /// The private key is stored in clear (TERTIARY warning).
    Unencrypted,
    /// Only the public key is present.
    PublicOnly,
    /// The ssh-agent holds the key.
    InAgent,
}

impl KeyChip {
    /// Chip text (painted uppercase).
    pub fn label(&self) -> &str {
        match self {
            Self::Algorithm(text) => text,
            Self::Legacy => "legacy",
            Self::Encrypted => "encrypted",
            Self::Unencrypted => "unencrypted",
            Self::PublicOnly => "public only",
            Self::InAgent => "in agent",
        }
    }

    /// Tint of the chip text and border.
    pub fn color(&self) -> Color32 {
        match self {
            Self::Algorithm(_) | Self::Encrypted => theme::SECONDARY,
            Self::Legacy | Self::Unencrypted => theme::TERTIARY,
            Self::PublicOnly => theme::LABEL,
            Self::InAgent => theme::OK,
        }
    }
}

/// Returns the key type text, e.g. `ed25519`, `rsa 3072`, `ecdsa p-256`;
/// a legacy key without a `.pub` has none.
pub fn algorithm_label(algorithm: &SshAlgorithm, bits: Option<u32>) -> Option<String> {
    let text = match algorithm {
        SshAlgorithm::Ed25519 => "ed25519".to_string(),
        SshAlgorithm::EcdsaP256 => "ecdsa p-256".to_string(),
        SshAlgorithm::EcdsaP384 => "ecdsa p-384".to_string(),
        SshAlgorithm::EcdsaP521 => "ecdsa p-521".to_string(),
        SshAlgorithm::Rsa => match bits {
            Some(bits) => format!("rsa {bits}"),
            None => "rsa".to_string(),
        },
        SshAlgorithm::Other(name) if name == "legacy" => return None,
        SshAlgorithm::Other(name) => name.clone(),
    };
    Some(text)
}

/// Returns the type chips of a key: its algorithm and LEGACY.
pub fn type_chips(info: &SshKeyInfo) -> Vec<KeyChip> {
    let mut chips: Vec<KeyChip> = algorithm_label(&info.algorithm, info.bits)
        .map(KeyChip::Algorithm)
        .into_iter()
        .collect();
    if info.legacy_format {
        chips.push(KeyChip::Legacy);
    }
    chips
}

/// Returns the status chips of a key: protection, then IN AGENT.
pub fn status_chips(info: &SshKeyInfo, in_agent: bool) -> Vec<KeyChip> {
    let mut chips = vec![match info.encrypted {
        Some(true) => KeyChip::Encrypted,
        Some(false) => KeyChip::Unencrypted,
        None => KeyChip::PublicOnly,
    }];
    if in_agent {
        chips.push(KeyChip::InAgent);
    }
    chips
}

/// Returns the muted summary line, e.g. `4 keys - 1 in the agent`.
pub fn keys_summary(state: &AppState) -> String {
    let loaded = state
        .ssh_keys
        .iter()
        .filter(|k| state.ssh_key_in_agent(k))
        .count();
    format!(
        "{} - {loaded} in the agent",
        count_noun(state.ssh_keys.len(), "key")
    )
}

/// Returns true when the name, comment or fingerprint contains `filter`
/// (case-insensitive).
pub fn key_matches(info: &SshKeyInfo, filter: &str) -> bool {
    let needle = filter.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    [&info.name, &info.comment, &info.fingerprint]
        .iter()
        .any(|text| text.to_lowercase().contains(&needle))
}

/// Returns the name shown for an agent identity: the local key with the
/// same fingerprint, else its comment, else its fingerprint.
pub fn identity_name(identity: &AgentIdentity, keys: &[SshKeyInfo]) -> String {
    let local = keys
        .iter()
        .find(|k| !k.fingerprint.is_empty() && k.fingerprint == identity.fingerprint);
    if let Some(k) = local {
        return k.name.clone();
    }
    if !identity.comment.is_empty() {
        return identity.comment.clone();
    }
    identity.fingerprint.clone()
}

/// Returns the identity count, e.g. `1 identity`, `2 identities`.
pub fn identities_count(n: usize) -> String {
    match n {
        1 => "1 identity".to_string(),
        n => format!("{n} identities"),
    }
}

/// Returns why "Remove all" is disabled, `None` when allowed.
pub fn remove_all_blocked(state: &AppState) -> Option<&'static str> {
    if state.agent_unavailable.is_some() {
        return Some(MSG_AGENT_UNAVAILABLE);
    }
    if state.agent_identities.is_empty() {
        return Some(MSG_NOTHING_TO_REMOVE);
    }
    None
}

/// Renders chips right to left (the caller's layout).
fn _chips(ui: &mut Ui, chips: &[KeyChip]) {
    for c in chips.iter().rev() {
        chip(ui, c.label(), c.color());
    }
}

/// Renders one key row; returns true when clicked.
fn _row(ui: &mut Ui, info: &SshKeyInfo, in_agent: bool, selected: bool) -> bool {
    let size = egui::vec2(ui.available_width(), ROW_HEIGHT);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    row_background(ui, rect, selected, resp.hovered());
    let inner = rect.shrink2(egui::vec2(ROW_PADDING, 8.0));
    let (top, bottom) = inner.split_top_bottom_at_fraction(0.5);
    // Each line right to left: the chips keep their room, the text truncates.
    let line = |ui: &mut Ui, rect: egui::Rect, chips: Vec<KeyChip>, text: RichText| {
        let builder = UiBuilder::new()
            .max_rect(rect)
            .layout(Layout::right_to_left(Align::Center));
        ui.scope_builder(builder, |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            _chips(ui, &chips);
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                ui.add(egui::Label::new(text).truncate().selectable(false));
            });
        });
    };
    let name = RichText::new(&info.name)
        .family(theme::medium())
        .size(14.0)
        .color(theme::TEXT);
    line(ui, top, type_chips(info), name);
    let fingerprint = match info.fingerprint.is_empty() {
        true => muted_text("no fingerprint (no .pub)"),
        false => RichText::new(&info.fingerprint)
            .monospace()
            .size(11.5)
            .color(theme::MUTED),
    };
    line(ui, bottom, status_chips(info, in_agent), fingerprint);
    resp.clicked()
}

/// Renders one agent identity with its Remove button; returns the action.
fn _identity_row(ui: &mut Ui, identity: &AgentIdentity, keys: &[SshKeyInfo]) -> Option<Action> {
    let mut action = None;
    let size = egui::vec2(ui.available_width(), AGENT_ROW_HEIGHT);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let builder = UiBuilder::new()
        .max_rect(rect)
        .layout(Layout::right_to_left(Align::Center));
    ui.scope_builder(builder, |ui| {
        let tip = "Remove from the agent";
        if ico_button(ui, Ico::Close, tip, None, true) {
            action = Some(Action::Send(Command::AgentRemove {
                fingerprint: identity.fingerprint.clone(),
            }));
        }
        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                let name = RichText::new(identity_name(identity, keys))
                    .size(13.0)
                    .color(theme::TEXT);
                ui.add(egui::Label::new(name).truncate().selectable(false));
                let fp = RichText::new(&identity.fingerprint)
                    .monospace()
                    .size(11.0)
                    .color(theme::MUTED);
                ui.add(egui::Label::new(fp).truncate().selectable(false));
            });
        });
    });
    action
}

/// Renders the agent section: count, "Remove all" and the identities (or
/// why the agent cannot be reached).
fn _agent(ui: &mut Ui, state: &AppState) -> Option<Action> {
    let mut action = None;
    card(ui, |ui| {
        ui.horizontal(|ui| {
            field_label(ui, "ssh-agent");
            if state.agent_unavailable.is_none() {
                muted(ui, &identities_count(state.agent_identities.len()));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if secondary_button(ui, "Remove all", remove_all_blocked(state)) {
                    action = Some(Action::Send(Command::AgentRemoveAll));
                }
                if ico_button(ui, Ico::Refresh, "List the agent again", None, false) {
                    action = Some(Action::Send(Command::AgentList));
                }
            });
        });
        if let Some(reason) = &state.agent_unavailable {
            ui.label(RichText::new(reason).color(theme::TERTIARY).size(12.5));
            return;
        }
        if state.agent_identities.is_empty() {
            muted(ui, MSG_AGENT_EMPTY);
            return;
        }
        egui::ScrollArea::vertical()
            .id_salt("kring-agent")
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for identity in &state.agent_identities {
                    if let Some(a) = _identity_row(ui, identity, &state.ssh_keys) {
                        action = Some(a);
                    }
                }
            });
    });
    action
}

/// Renders the SSH keys list panel and returns the requested action;
/// `ssh_dir` is `None` when HOME is unset (nothing can be scanned).
pub fn show(
    ui: &mut Ui,
    state: &AppState,
    filter: &mut String,
    ssh_dir: Option<&Path>,
) -> Option<Action> {
    let mut action = None;
    let blocked = ssh_dir.is_none().then_some(MSG_NO_SSH_DIR);
    ui.horizontal(|ui| {
        ui.label(semibold("SSH keys", 18.0));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ico_button(ui, Ico::Refresh, "Rescan the SSH key folder", None, false) {
                action = Some(Action::Send(Command::ScanSshKeys));
            }
        });
    });
    ui.add_space(2.0);
    ui.horizontal(|ui| {
        if primary_button(ui, "+ New key", blocked) {
            let dialog = SshDialog::generate(&state.ssh_keys);
            action = Some(Action::Open(DialogKind::Ssh(dialog)));
        }
        if secondary_button(ui, "Import", blocked) {
            action = Some(Action::Open(DialogKind::Ssh(SshDialog::import())));
        }
    });
    search_box(ui, filter, "Search keys");
    match ssh_dir {
        Some(_) => muted(ui, &keys_summary(state)),
        None => {
            ui.label(RichText::new(MSG_NO_SSH_DIR).color(theme::TERTIARY));
        }
    }
    ui.add_space(2.0);
    let list_height = (ui.available_height() - AGENT_HEIGHT).max(ROW_HEIGHT);
    egui::ScrollArea::vertical()
        .id_salt("kring-ssh-keys")
        .max_height(list_height)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for info in state.ssh_keys.iter().filter(|k| key_matches(k, filter)) {
                let selected = state.selected_ssh_key.as_ref() == Some(&info.name);
                let in_agent = state.ssh_key_in_agent(info);
                if _row(ui, info, in_agent, selected) && !selected {
                    action = Some(Action::SelectSshKey(info.name.clone()));
                }
            }
        });
    ui.add_space(8.0);
    if let Some(a) = _agent(ui, state) {
        action = Some(a);
    }
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::dialog_ssh::tests::key;
    use crate::worker::{AgentStatus, Event};

    /// An identity with `fingerprint` and `comment`.
    fn identity(fingerprint: &str, comment: &str) -> AgentIdentity {
        AgentIdentity {
            fingerprint: fingerprint.into(),
            comment: comment.into(),
            algorithm: SshAlgorithm::Ed25519,
        }
    }

    /// Type chips name the algorithm with its size; legacy keys get LEGACY.
    #[test]
    fn type_chip_labels() {
        let label = |a: SshAlgorithm, bits| algorithm_label(&a, bits);
        assert_eq!(label(SshAlgorithm::Ed25519, Some(256)).unwrap(), "ed25519");
        assert_eq!(label(SshAlgorithm::Rsa, Some(3072)).unwrap(), "rsa 3072");
        assert_eq!(
            label(SshAlgorithm::EcdsaP256, Some(256)).unwrap(),
            "ecdsa p-256"
        );
        assert_eq!(
            label(SshAlgorithm::Other("ssh-dss".into()), None).unwrap(),
            "ssh-dss"
        );
        assert!(label(SshAlgorithm::Other("legacy".into()), None).is_none());
        let mut legacy = key("old", Some(false));
        legacy.legacy_format = true;
        legacy.algorithm = SshAlgorithm::Other("legacy".into());
        assert_eq!(type_chips(&legacy), [KeyChip::Legacy]);
        assert_eq!(KeyChip::Legacy.color(), theme::TERTIARY);
    }

    /// Status chips: ENCRYPTED, UNENCRYPTED (warning) or PUBLIC ONLY, then IN AGENT.
    #[test]
    fn status_chip_order() {
        assert_eq!(
            status_chips(&key("a", Some(true)), true),
            [KeyChip::Encrypted, KeyChip::InAgent]
        );
        assert_eq!(
            status_chips(&key("b", Some(false)), false),
            [KeyChip::Unencrypted]
        );
        assert_eq!(status_chips(&key("c", None), false), [KeyChip::PublicOnly]);
        assert_eq!(KeyChip::Unencrypted.color(), theme::TERTIARY);
        assert_eq!(KeyChip::InAgent.label(), "in agent");
    }

    /// The summary counts keys and those in the agent; the filter looks at
    /// name, comment and fingerprint.
    #[test]
    fn summary_and_filter() {
        let mut s = AppState::default();
        s.apply(Event::SshKeys(vec![key("a", Some(true)), key("b", None)]));
        assert_eq!(keys_summary(&s), "2 keys - 0 in the agent");
        s.apply(Event::AgentIdentities(AgentStatus::Available(vec![
            identity("SHA256:a", "x"),
        ])));
        assert_eq!(keys_summary(&s), "2 keys - 1 in the agent");
        let a = key("id_work", Some(true));
        assert!(key_matches(&a, " "));
        assert!(key_matches(&a, "WORK"));
        assert!(key_matches(&a, "id_work@test"));
        assert!(key_matches(&a, "sha256:id_"));
        assert!(!key_matches(&a, "home"));
    }

    /// Agent identities are named after the local key, else the comment,
    /// else the fingerprint; Remove all needs a reachable agent with identities.
    #[test]
    fn agent_names_and_remove_all() {
        let keys = [key("id_a", Some(true))];
        assert_eq!(identity_name(&identity("SHA256:id_a", "c"), &keys), "id_a");
        assert_eq!(
            identity_name(&identity("SHA256:z", "laptop"), &keys),
            "laptop"
        );
        assert_eq!(identity_name(&identity("SHA256:z", ""), &keys), "SHA256:z");
        let mut s = AppState::default();
        assert_eq!(remove_all_blocked(&s), Some(MSG_NOTHING_TO_REMOVE));
        s.apply(Event::AgentIdentities(AgentStatus::Available(vec![
            identity("SHA256:z", ""),
        ])));
        assert_eq!(remove_all_blocked(&s), None);
        s.apply(Event::AgentIdentities(AgentStatus::Unavailable(
            "gone".into(),
        )));
        assert_eq!(remove_all_blocked(&s), Some(MSG_AGENT_UNAVAILABLE));
        assert_eq!(identities_count(1), "1 identity");
        assert_eq!(identities_count(2), "2 identities");
        assert_eq!(identities_count(0), "0 identities");
    }
}
