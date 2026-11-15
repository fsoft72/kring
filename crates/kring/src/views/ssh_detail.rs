//! The selected SSH key: header with chips and agent action, key actions,
//! notes, details and the public key with Copy.

use std::path::Path;

use eframe::egui::{self, RichText};
use kring_core::ssh::SshKeyInfo;

use crate::app_state::AppState;
use crate::ui::glyphs::Ico;
use crate::ui::theme;
use crate::ui::widgets::{
    card, danger_button, field_label, glyph_tile, heading, ico_button, muted, note, primary_button,
    secondary_button, semibold,
};
use crate::views::dialog_ssh::SshDialog;
use crate::views::dialogs::DialogKind;
use crate::views::ssh_list::{
    KeyChip, MSG_AGENT_UNAVAILABLE, algorithm_label, status_chips, type_chips,
};
use crate::views::{Action, Gates};
use crate::worker::{Command, MSG_NO_SSH_DIR};

/// Tooltip of the actions refused on legacy keys.
pub const MSG_LEGACY_READ_ONLY: &str = "Legacy PEM keys are read-only in kring";
/// Tooltip of the actions needing the private key.
pub const MSG_NO_PRIVATE: &str = "Only the public key is in the folder";
/// Note of a legacy key.
const MSG_LEGACY_NOTE: &str = "Legacy PEM key: read-only in kring. Convert it to the OpenSSH \
     format with `ssh-keygen -p -f <file>` to manage it here.";
/// Note of an unencrypted private key.
const MSG_UNENCRYPTED_NOTE: &str =
    "Not protected by a passphrase: anyone who can read the file can use the key.";
/// Note of a public key without its private key.
const MSG_PUBLIC_ONLY_NOTE: &str = "Public key only: the private key is not in this folder.";
/// Note of a key whose `.pub` holds another key.
const MSG_MISMATCH_NOTE: &str = "The .pub file holds another key than the private file: the \
     details show the private key.";
/// Info toast after copying the public key.
pub const MSG_PUBLIC_COPIED: &str = "Public key copied";
/// Width of the labels of the detail rows.
const LABEL_WIDTH: f32 = 120.0;

/// Returns the selected key, if it is still listed.
pub fn selected_key(state: &AppState) -> Option<&SshKeyInfo> {
    let name = state.selected_ssh_key.as_ref()?;
    state.ssh_keys.iter().find(|k| &k.name == name)
}

/// Returns the public key text of `info` once read.
pub fn public_key<'a>(state: &'a AppState, info: &SshKeyInfo) -> Option<&'a str> {
    state
        .ssh_public_key
        .as_ref()
        .filter(|(name, _)| *name == info.name)
        .map(|(_, text)| text.as_str())
}

/// Returns true when a public key can be read for `info` (an OpenSSH
/// private key, or a `.pub`).
pub fn has_public_key(info: &SshKeyInfo) -> bool {
    info.public_path.is_some() || (info.private_path.is_some() && !info.legacy_format)
}

/// Returns the command reading the public key of the newly selected `info`.
pub fn select_command(info: &SshKeyInfo) -> Option<Command> {
    has_public_key(info).then(|| Command::ReadSshPublicKey {
        name: info.name.clone(),
    })
}

/// Returns why the private key actions (agent, export, passphrase) are
/// refused, `None` when allowed.
pub fn private_blocked(info: &SshKeyInfo) -> Option<&'static str> {
    if info.private_path.is_none() {
        return Some(MSG_NO_PRIVATE);
    }
    if info.legacy_format {
        return Some(MSG_LEGACY_READ_ONLY);
    }
    None
}

/// Returns why "Add to agent" / "Remove from agent" is disabled.
pub fn agent_blocked(state: &AppState, info: &SshKeyInfo) -> Option<&'static str> {
    if state.agent_unavailable.is_some() {
        return Some(MSG_AGENT_UNAVAILABLE);
    }
    if state.ssh_key_in_agent(info) {
        return None;
    }
    private_blocked(info)
}

/// Returns why "Change passphrase" is disabled: private key rules, then
/// the destructive gate (progress modal open).
pub fn change_blocked(info: &SshKeyInfo, gates: Gates) -> Option<&'static str> {
    private_blocked(info).or(gates.busy)
}

/// Returns the type line, e.g. `ED25519, 256 bits`.
pub fn type_line(info: &SshKeyInfo) -> String {
    let name = algorithm_label(&info.algorithm, None)
        .unwrap_or_else(|| "unknown".into())
        .to_uppercase();
    match info.bits {
        Some(bits) => format!("{name}, {bits} bits"),
        None => name,
    }
}

/// Renders chips left to right.
fn _chips(ui: &mut egui::Ui, chips: &[KeyChip]) {
    for c in chips {
        crate::ui::widgets::chip(ui, c.label(), c.color());
    }
}

/// Renders name, chips and the agent action.
fn _header(ui: &mut egui::Ui, state: &AppState, info: &SshKeyInfo) -> Option<Action> {
    let mut action = None;
    let in_agent = state.ssh_key_in_agent(info);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.add(egui::Label::new(semibold(&info.name, 22.0)).truncate());
        _chips(ui, &type_chips(info));
        _chips(ui, &status_chips(info, in_agent));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let blocked = agent_blocked(state, info);
            if in_agent {
                if secondary_button(ui, "Remove from agent", blocked) {
                    action = Some(Action::Send(Command::AgentRemove {
                        fingerprint: info.fingerprint.clone(),
                    }));
                }
            } else if primary_button(ui, "Add to agent", blocked) {
                let dialog = SshDialog::agent_add(info);
                action = Some(Action::Open(DialogKind::Ssh(dialog)));
            }
        });
    });
    action
}

/// Renders the key actions: export, change passphrase, delete.
fn _actions(
    ui: &mut egui::Ui,
    state: &AppState,
    info: &SshKeyInfo,
    gates: Gates,
) -> Option<Action> {
    let mut action = None;
    let open = |dialog: SshDialog| Some(Action::Open(DialogKind::Ssh(dialog)));
    ui.horizontal(|ui| {
        if secondary_button(ui, "Export private key...", private_blocked(info)) {
            action = open(SshDialog::export(info));
        }
        if secondary_button(ui, "Change passphrase...", change_blocked(info, gates)) {
            action = open(SshDialog::change_passphrase(info));
        }
        if danger_button(ui, "Delete...", gates.busy) {
            let in_agent = state.ssh_key_in_agent(info);
            action = open(SshDialog::delete(info, in_agent));
        }
    });
    action
}

/// Renders the notes: format problems and missing protection.
fn _notes(ui: &mut egui::Ui, info: &SshKeyInfo) {
    if info.pub_mismatch {
        note(ui, theme::ERROR, MSG_MISMATCH_NOTE, theme::ERROR);
    }
    if info.legacy_format {
        note(ui, theme::TERTIARY, MSG_LEGACY_NOTE, theme::TERTIARY);
    }
    match info.encrypted {
        Some(false) => note(ui, theme::TERTIARY, MSG_UNENCRYPTED_NOTE, theme::TERTIARY),
        None => note(ui, theme::SECONDARY, MSG_PUBLIC_ONLY_NOTE, theme::MUTED),
        Some(true) => {}
    }
}

/// Renders one detail row: label, then a (monospace) value.
fn _row(ui: &mut egui::Ui, label: &str, value: &str, mono: bool) {
    ui.horizontal(|ui| {
        ui.allocate_ui(egui::vec2(LABEL_WIDTH, 18.0), |ui| {
            ui.set_min_width(LABEL_WIDTH);
            field_label(ui, label);
        });
        let text = RichText::new(value).color(theme::TEXT);
        let text = match mono {
            true => text.monospace().size(12.5),
            false => text.size(13.5),
        };
        ui.add(egui::Label::new(text).truncate());
    });
}

/// Renders the details card.
fn _details(ui: &mut egui::Ui, info: &SshKeyInfo) {
    card(ui, |ui| {
        ui.spacing_mut().item_spacing.y = 8.0;
        let fingerprint = match info.fingerprint.is_empty() {
            true => "unknown (no .pub)",
            false => info.fingerprint.as_str(),
        };
        _row(ui, "Fingerprint", fingerprint, true);
        _row(ui, "Type", &type_line(info), false);
        let comment = match info.comment.is_empty() {
            true => "-",
            false => info.comment.as_str(),
        };
        _row(ui, "Comment", comment, false);
        let path = |p: &Option<std::path::PathBuf>| {
            p.as_ref()
                .map_or_else(|| "-".to_string(), |p| p.display().to_string())
        };
        _row(ui, "Private key", &path(&info.private_path), true);
        _row(ui, "Public key", &path(&info.public_path), true);
    });
}

/// Renders the public key box with its Copy button; returns the info
/// action after a copy.
fn _public_key(ui: &mut egui::Ui, state: &AppState, info: &SshKeyInfo) -> Option<Action> {
    if !has_public_key(info) {
        return None;
    }
    let mut action = None;
    let text = public_key(state, info);
    card(ui, |ui| {
        ui.horizontal(|ui| {
            field_label(ui, "Public key");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let blocked = text.is_none().then_some("Reading the public key...");
                if ico_button(ui, Ico::Copy, "Copy the public key", blocked, false)
                    && let Some(text) = text
                {
                    ui.ctx().copy_text(text.to_string());
                    action = Some(Action::Info(MSG_PUBLIC_COPIED.to_string()));
                }
            });
        });
        let frame = egui::Frame::new()
            .fill(theme::INPUT_FILL)
            .stroke(egui::Stroke::new(1.0_f32, theme::FIELD_ROW_BORDER))
            .corner_radius(egui::CornerRadius::same(theme::RADIUS_CTRL))
            .inner_margin(egui::Margin::same(10));
        frame.show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            match text {
                Some(text) => {
                    let label = RichText::new(text)
                        .monospace()
                        .size(12.0)
                        .color(theme::TEXT);
                    ui.add(egui::Label::new(label).wrap());
                }
                None => muted(ui, "Reading the public key..."),
            }
        });
    });
    action
}

/// Renders the empty state shown when no key is selected.
pub fn empty_state(ui: &mut egui::Ui, ssh_dir: Option<&Path>) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        glyph_tile(ui, Ico::Terminal, 64.0);
        ui.add_space(8.0);
        let Some(dir) = ssh_dir else {
            heading(ui, "No SSH key folder");
            ui.label(RichText::new(MSG_NO_SSH_DIR).color(theme::TERTIARY));
            return;
        };
        heading(ui, "Select a key");
        muted(
            ui,
            "SSH keys of your key folder: load them into the ssh-agent, export, change \
             their passphrase or delete them (after a backup).",
        );
        ui.add_space(12.0);
        ui.label(
            RichText::new(dir.display().to_string())
                .monospace()
                .size(12.0)
                .color(theme::MUTED),
        );
    });
}

/// Renders the selected key; `ssh_dir` is the scanned folder (`None`
/// without HOME).
pub fn show(
    ui: &mut egui::Ui,
    state: &AppState,
    gates: Gates,
    ssh_dir: Option<&Path>,
) -> Option<Action> {
    let Some(info) = selected_key(state) else {
        empty_state(ui, ssh_dir);
        return None;
    };
    let mut action = _header(ui, state, info);
    ui.add_space(6.0);
    action = _actions(ui, state, info, gates).or(action);
    ui.add_space(8.0);
    _notes(ui, info);
    ui.add_space(4.0);
    _details(ui, info);
    ui.add_space(8.0);
    _public_key(ui, state, info).or(action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::dialog_ssh::tests::key;
    use crate::worker::{AgentStatus, Event};
    use kring_core::ssh::{AgentIdentity, SshAlgorithm};

    /// A legacy key with its `.pub`.
    fn legacy() -> SshKeyInfo {
        SshKeyInfo {
            legacy_format: true,
            algorithm: SshAlgorithm::Rsa,
            bits: Some(2048),
            ..key("id_legacy", Some(false))
        }
    }

    /// Private key actions need an OpenSSH private key; change passphrase
    /// is also blocked while an operation is shown.
    #[test]
    fn private_actions_gating() {
        let free = Gates::from_provider(None);
        assert_eq!(private_blocked(&key("a", Some(true))), None);
        assert_eq!(private_blocked(&key("orphan", None)), Some(MSG_NO_PRIVATE));
        assert_eq!(private_blocked(&legacy()), Some(MSG_LEGACY_READ_ONLY));
        assert_eq!(change_blocked(&key("a", Some(true)), free), None);
        let busy = free.with_operation(true);
        assert!(change_blocked(&key("a", Some(true)), busy).is_some());
    }

    /// The agent action needs a reachable agent; a key already in the
    /// agent can be removed even when it could not be added.
    #[test]
    fn agent_action_gating() {
        let mut s = AppState::default();
        let a = key("a", Some(true));
        assert_eq!(agent_blocked(&s, &a), None);
        assert_eq!(agent_blocked(&s, &legacy()), Some(MSG_LEGACY_READ_ONLY));
        let orphan = key("orphan", None);
        s.apply(Event::AgentIdentities(AgentStatus::Available(vec![
            AgentIdentity {
                fingerprint: orphan.fingerprint.clone(),
                comment: String::new(),
                algorithm: SshAlgorithm::Ed25519,
            },
        ])));
        assert_eq!(agent_blocked(&s, &orphan), None, "removable");
        s.apply(Event::AgentIdentities(AgentStatus::Unavailable("x".into())));
        assert_eq!(agent_blocked(&s, &a), Some(MSG_AGENT_UNAVAILABLE));
    }

    /// The public key is read for keys that have one; only the selected
    /// key's text is shown.
    #[test]
    fn public_key_reading() {
        assert!(matches!(
            select_command(&key("a", Some(true))),
            Some(Command::ReadSshPublicKey { name }) if name == "a"
        ));
        let bare = SshKeyInfo {
            public_path: None,
            ..legacy()
        };
        assert!(select_command(&bare).is_none());
        let mut s = AppState::default();
        s.apply(Event::SshKeys(vec![key("a", Some(true))]));
        s.select_ssh_key("a".into());
        let info = selected_key(&s).unwrap().clone();
        assert!(public_key(&s, &info).is_none());
        s.apply(Event::SshPublicKey {
            name: "a".into(),
            text: "ssh-ed25519 AAAA a@test".into(),
        });
        assert_eq!(public_key(&s, &info), Some("ssh-ed25519 AAAA a@test"));
    }

    /// The type line names the algorithm and its size.
    #[test]
    fn type_lines() {
        assert_eq!(type_line(&key("a", Some(true))), "ED25519, 256 bits");
        assert_eq!(type_line(&legacy()), "RSA, 2048 bits");
    }
}
