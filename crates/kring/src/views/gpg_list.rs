//! List panel "GPG keys": rescan, New key / Import, search and the key rows
//! (first user id and key id, with type and status chips).

use eframe::egui::{self, Align, Color32, Layout, RichText, Sense, Ui, UiBuilder};
use kring_core::gpg::{GpgAlgorithm, GpgKey};

use crate::app_state::{AppState, count_noun};
use crate::ui::glyphs::Ico;
use crate::ui::theme;
use crate::ui::widgets::{
    accent_card, chip, ico_button, muted, primary_button, search_box, secondary_button, semibold,
};
use crate::views::Action;
use crate::views::dialog_gpg::{GpgDialog, key_label};
use crate::views::dialogs::DialogKind;
use crate::views::sidebar::row_background;
use crate::worker::Command;

/// Height of a key row (user id and key id lines).
const ROW_HEIGHT: f32 = 56.0;
/// Horizontal padding inside a row.
const ROW_PADDING: f32 = 12.0;
/// Tooltip of the actions while gpg cannot be used.
pub const MSG_GPG_UNAVAILABLE: &str = "GnuPG cannot be used: see the notice in the detail pane";
/// Text of the list without keys.
const MSG_NO_KEYS: &str = "No keys in the GnuPG keyring";
/// Title of the card explaining why gpg cannot be used.
const MSG_UNAVAILABLE_TITLE: &str = "GnuPG is not usable";

/// A chip of a GPG key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyChip {
    /// Key type, e.g. `ed25519` or `rsa 3072` (painted uppercase).
    Algorithm(String),
    /// The secret key is in the keyring.
    Secret,
    /// Only the public key is in the keyring.
    Public,
    /// The secret primary key lives on a smartcard.
    Card,
    /// The secret primary key is an offline stub.
    Stub,
    /// The key is revoked.
    Revoked,
    /// The key expired.
    Expired,
    /// Validity of the key in the web of trust, e.g. `ultimate`.
    Validity(&'static str),
}

impl KeyChip {
    /// Chip text (painted uppercase).
    pub fn label(&self) -> &str {
        match self {
            Self::Algorithm(text) => text,
            Self::Secret => "secret",
            Self::Public => "public",
            Self::Card => "card",
            Self::Stub => "offline",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Validity(text) => text,
        }
    }

    /// Tint of the chip text and border.
    pub fn color(&self) -> Color32 {
        match self {
            Self::Algorithm(_) | Self::Secret => theme::SECONDARY,
            Self::Public => theme::LABEL,
            Self::Card | Self::Stub | Self::Expired => theme::TERTIARY,
            Self::Revoked => theme::ERROR,
            Self::Validity(text) if TRUSTED_VALIDITY.contains(text) => theme::OK,
            Self::Validity(_) => theme::MUTED,
        }
    }
}

/// Validity labels painted as trusted (OK).
const TRUSTED_VALIDITY: [&str; 2] = ["ultimate", "full"];

/// Returns the key type text, e.g. `ed25519`, `cv25519`, `rsa 3072`.
pub fn algorithm_label(algorithm: &GpgAlgorithm, bits: u32) -> String {
    let sized = |name: &str| match bits {
        0 => name.to_string(),
        bits => format!("{name} {bits}"),
    };
    let curve = |curve: &str, name: &str| match curve.is_empty() {
        true => name.to_string(),
        false => curve.to_string(),
    };
    match algorithm {
        GpgAlgorithm::Rsa => sized("rsa"),
        GpgAlgorithm::Dsa => sized("dsa"),
        GpgAlgorithm::Elgamal => sized("elgamal"),
        GpgAlgorithm::EdDsa(c) => curve(c, "eddsa"),
        GpgAlgorithm::Ecdh(c) => curve(c, "ecdh"),
        GpgAlgorithm::Ecdsa(c) => curve(c, "ecdsa"),
        GpgAlgorithm::Other(n) => format!("algorithm {n}"),
    }
}

/// Returns the readable validity of a validity flag (`None` when unknown).
pub fn validity_label(flag: char) -> Option<&'static str> {
    match flag {
        'u' => Some("ultimate"),
        'f' => Some("full"),
        'm' => Some("marginal"),
        'n' => Some("not valid"),
        'i' => Some("invalid"),
        'd' => Some("disabled"),
        _ => None,
    }
}

/// True when the key is revoked.
pub fn is_revoked(key: &GpgKey) -> bool {
    key.validity == 'r'
}

/// True when the key expired (validity flag, or its date passed at `now`,
/// seconds since the epoch).
pub fn is_expired(key: &GpgKey, now: u64) -> bool {
    key.validity == 'e' || key.expires.is_some_and(|t| t <= now)
}

/// Returns the current time in seconds since the epoch.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Returns the type chips of a key: its algorithm.
pub fn type_chips(key: &GpgKey) -> Vec<KeyChip> {
    vec![KeyChip::Algorithm(algorithm_label(
        &key.algorithm,
        key.bits,
    ))]
}

/// Returns the status chips of a key at `now`: SECRET or PUBLIC, where an
/// unusable secret primary key lives, then REVOKED / EXPIRED, else its validity.
pub fn status_chips(key: &GpgKey, now: u64) -> Vec<KeyChip> {
    let mut chips = vec![match key.secret {
        true => KeyChip::Secret,
        false => KeyChip::Public,
    }];
    if key.secret && !key.primary_secret {
        chips.push(match key.card {
            true => KeyChip::Card,
            false => KeyChip::Stub,
        });
    }
    if is_revoked(key) {
        chips.push(KeyChip::Revoked);
    } else if is_expired(key, now) {
        chips.push(KeyChip::Expired);
    } else if let Some(text) = validity_label(key.validity) {
        chips.push(KeyChip::Validity(text));
    }
    chips
}

/// Returns the muted summary line, e.g. `3 keys - 1 secret`.
pub fn keys_summary(state: &AppState) -> String {
    let secret = state.gpg_keys.iter().filter(|k| k.secret).count();
    format!(
        "{} - {secret} secret",
        count_noun(state.gpg_keys.len(), "key")
    )
}

/// Returns true when a user id, the fingerprint or the key id contains
/// `filter` (case-insensitive).
pub fn key_matches(key: &GpgKey, filter: &str) -> bool {
    let needle = filter.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    let ids = [&key.fingerprint, &key.key_id];
    key.uids
        .iter()
        .map(|u| &u.uid)
        .chain(ids)
        .any(|text| text.to_lowercase().contains(&needle))
}

/// Returns why the area actions are disabled (gpg unusable), `None` when allowed.
pub fn gpg_blocked(state: &AppState) -> Option<&'static str> {
    state
        .gpg_unavailable
        .is_some()
        .then_some(MSG_GPG_UNAVAILABLE)
}

/// Renders the card explaining why gpg cannot be used, when it cannot.
pub fn unavailable_card(ui: &mut Ui, state: &AppState) {
    let Some(reason) = &state.gpg_unavailable else {
        return;
    };
    accent_card(ui, theme::TERTIARY, |ui| {
        ui.label(semibold(MSG_UNAVAILABLE_TITLE, 14.0).color(theme::TERTIARY));
        ui.label(RichText::new(reason).color(theme::TEXT).size(12.5));
    });
    ui.add_space(6.0);
}

/// Renders chips right to left (the caller's layout).
fn _chips(ui: &mut Ui, chips: &[KeyChip]) {
    for c in chips.iter().rev() {
        chip(ui, c.label(), c.color());
    }
}

/// Renders one key row; returns true when clicked.
fn _row(ui: &mut Ui, key: &GpgKey, now: u64, selected: bool) -> bool {
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
    let mut name = key_label(key);
    if key.uids.len() > 1 {
        name.push_str(&format!(" (+{})", key.uids.len() - 1));
    }
    let name = RichText::new(name)
        .family(theme::medium())
        .size(14.0)
        .color(theme::TEXT);
    line(ui, top, type_chips(key), name);
    let id = RichText::new(&key.key_id)
        .monospace()
        .size(11.5)
        .color(theme::MUTED);
    line(ui, bottom, status_chips(key, now), id);
    resp.clicked()
}

/// Renders the GPG keys list panel and returns the requested action.
pub fn show(ui: &mut Ui, state: &AppState, filter: &mut String) -> Option<Action> {
    let mut action = None;
    let blocked = gpg_blocked(state);
    let open = |dialog: GpgDialog| Some(Action::Open(DialogKind::Gpg(dialog)));
    ui.horizontal(|ui| {
        ui.label(semibold("GPG keys", 18.0));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ico_button(ui, Ico::Refresh, "Rescan the GnuPG keyring", None, false) {
                action = Some(Action::Send(Command::ScanGpgKeys));
            }
        });
    });
    ui.add_space(2.0);
    ui.horizontal(|ui| {
        if primary_button(ui, "+ New key", blocked) {
            action = open(GpgDialog::create());
        }
        if secondary_button(ui, "Import", blocked) {
            action = open(GpgDialog::import());
        }
    });
    search_box(ui, filter, "Search keys");
    match state.gpg_keys.is_empty() {
        true => muted(ui, MSG_NO_KEYS),
        false => muted(ui, &keys_summary(state)),
    }
    ui.add_space(2.0);
    let now = now_secs();
    egui::ScrollArea::vertical()
        .id_salt("kring-gpg-keys")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for key in state.gpg_keys.iter().filter(|k| key_matches(k, filter)) {
                let selected = state.selected_gpg_key.as_ref() == Some(&key.fingerprint);
                if _row(ui, key, now, selected) && !selected {
                    action = Some(Action::SelectGpgKey(key.fingerprint.clone()));
                }
            }
        });
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::dialog_gpg::tests::{public_key, secret_key};
    use crate::worker::Event;

    /// Type chips name the algorithm: the curve, or the family with its size.
    #[test]
    fn algorithm_labels() {
        let label = |a: GpgAlgorithm, bits| algorithm_label(&a, bits);
        assert_eq!(label(GpgAlgorithm::EdDsa("ed25519".into()), 255), "ed25519");
        assert_eq!(label(GpgAlgorithm::Ecdh(String::new()), 256), "ecdh");
        assert_eq!(label(GpgAlgorithm::Rsa, 3072), "rsa 3072");
        assert_eq!(label(GpgAlgorithm::Dsa, 0), "dsa");
        assert_eq!(label(GpgAlgorithm::Other(99), 1), "algorithm 99");
        assert_eq!(
            type_chips(&secret_key()),
            [KeyChip::Algorithm("ed25519".into())]
        );
    }

    /// Status chips: SECRET or PUBLIC, CARD / OFFLINE for an unusable
    /// primary secret, then REVOKED, EXPIRED or the validity.
    #[test]
    fn status_chip_order() {
        let key = secret_key();
        assert_eq!(
            status_chips(&key, 0),
            [KeyChip::Secret, KeyChip::Validity("ultimate")]
        );
        assert_eq!(KeyChip::Validity("ultimate").color(), theme::OK);
        let mut stub = key.clone();
        stub.primary_secret = false;
        assert_eq!(status_chips(&stub, 0)[1], KeyChip::Stub);
        stub.card = true;
        assert_eq!(status_chips(&stub, 0)[1], KeyChip::Card);
        let public = public_key();
        let expires = public.expires.unwrap();
        assert_eq!(status_chips(&public, expires - 1)[0], KeyChip::Public);
        assert_eq!(
            status_chips(&public, expires),
            [KeyChip::Public, KeyChip::Expired]
        );
        let mut revoked = public;
        revoked.validity = 'r';
        assert_eq!(status_chips(&revoked, 0)[1], KeyChip::Revoked);
        assert_eq!(KeyChip::Revoked.color(), theme::ERROR);
        assert_eq!(validity_label('-'), None);
    }

    /// The summary counts keys and secret keys; the filter looks at user
    /// ids, fingerprint and key id.
    #[test]
    fn summary_and_filter() {
        let mut s = AppState::default();
        s.apply(Event::GpgKeys(vec![secret_key(), public_key()]));
        assert_eq!(keys_summary(&s), "2 keys - 1 secret");
        let key = secret_key();
        assert!(key_matches(&key, " "));
        assert!(key_matches(&key, "FIXTURE@example"));
        assert!(key_matches(&key, &key.key_id.to_lowercase()));
        assert!(key_matches(&key, &key.fingerprint[30..]));
        assert!(!key_matches(&key, "colon"));
    }

    /// Actions are blocked while gpg is unusable, even with keys listed.
    #[test]
    fn unavailable_blocks_actions() {
        let mut s = AppState::default();
        assert_eq!(gpg_blocked(&s), None);
        s.apply(Event::GpgUnavailable {
            reason: "refused".into(),
            scan: false,
        });
        assert_eq!(gpg_blocked(&s), Some(MSG_GPG_UNAVAILABLE));
    }
}
