//! The selected GPG key: header with chips, key actions, notes, details,
//! user ids, subkeys and the armored public key with Copy.

use eframe::egui::{self, RichText};
use kring_core::gpg::{GpgKey, MSG_PRIMARY_SECRET_UNAVAILABLE};

use crate::app_state::AppState;
use crate::local_time;
use crate::ui::glyphs::Ico;
use crate::ui::theme;
use crate::ui::widgets::{
    card, chip, danger_button, field_label, glyph_tile, heading, ico_button, muted, note,
    secondary_button, semibold,
};
use crate::views::dialog_gpg::{GpgDialog, key_label};
use crate::views::dialogs::DialogKind;
use crate::views::gpg_list::{
    KeyChip, algorithm_label, gpg_blocked, is_expired, is_revoked, now_secs, status_chips,
    type_chips, unavailable_card, validity_label,
};
use crate::views::{Action, Gates};
use crate::worker::Command;

/// Tooltip of the actions needing the secret key.
pub const MSG_PUBLIC_ONLY: &str = "Only the public key is in the keyring";
/// Info toast after copying the public key.
pub const MSG_PUBLIC_COPIED: &str = "Public key copied";
/// Note of a key whose primary secret is a stub or on a smartcard.
const MSG_STUB_NOTE: &str = "The secret primary key is not on this computer (offline stub or \
     smartcard): kring can show and export the public key, but cannot export the secret key, \
     change its passphrase or delete it. Use gpg directly for such keys.";
/// Note of a public-only key.
const MSG_PUBLIC_NOTE: &str = "Public key only: you can encrypt to it and verify its \
     signatures, the secret key is not in this keyring.";
/// Note of an expired key.
const MSG_EXPIRED_NOTE: &str = "This key expired: gpg no longer uses it for new signatures or \
     encryption (its expiry can be extended with gpg --quick-set-expire).";
/// Note of a revoked key.
const MSG_REVOKED_NOTE: &str = "This key is revoked: it must not be used any more.";
/// Text of the public key box while the export runs.
const MSG_READING: &str = "Reading the public key...";
/// Width of the labels of the detail rows.
const LABEL_WIDTH: f32 = 120.0;
/// Hex digits per fingerprint group.
const GROUP_LEN: usize = 4;
/// Groups after which a v4 fingerprint gets a wider gap (as gpg prints it).
const HALF_GROUPS: usize = 5;
/// Largest height of the public key box before it scrolls.
const PUBLIC_MAX_HEIGHT: f32 = 180.0;
/// Width of the subkey table columns: key id, type, created, expires.
const SUBKEY_COLUMNS: [f32; 4] = [150.0, 110.0, 100.0, 100.0];

/// Returns the selected key, if it is still listed.
pub fn selected_key(state: &AppState) -> Option<&GpgKey> {
    let fpr = state.selected_gpg_key.as_ref()?;
    state.gpg_keys.iter().find(|k| &k.fingerprint == fpr)
}

/// Returns the armored public key of `key` once read.
pub fn public_key<'a>(state: &'a AppState, key: &GpgKey) -> Option<&'a str> {
    state
        .gpg_public_key
        .as_ref()
        .filter(|(fpr, _)| *fpr == key.fingerprint)
        .map(|(_, text)| text.as_str())
}

/// Returns the command reading the public key of the newly selected `key`.
pub fn select_command(key: &GpgKey) -> Command {
    Command::ExportGpgPublic {
        fpr: key.fingerprint.clone(),
    }
}

/// Groups a fingerprint by 4 hex digits, with a wider gap in the middle of
/// a v4 fingerprint (e.g. `F304 378C ... 3CEF  2CA8 ...`).
pub fn grouped_fingerprint(fpr: &str) -> String {
    let groups: Vec<&str> = fpr
        .as_bytes()
        .chunks(GROUP_LEN)
        .filter_map(|c| std::str::from_utf8(c).ok())
        .collect();
    let wide = groups.len() == 2 * HALF_GROUPS;
    let mut out = String::new();
    for (i, group) in groups.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if wide && i == HALF_GROUPS {
            out.push(' ');
        }
        out.push_str(group);
    }
    out
}

/// Returns the readable usage of capability letters, e.g. `sign, certify`
/// (only the lower case letters: those of the key itself).
pub fn usage_label(capabilities: &str) -> String {
    let names: Vec<&str> = capabilities
        .chars()
        .filter_map(|c| match c {
            'c' => Some("certify"),
            's' => Some("sign"),
            'e' => Some("encrypt"),
            'a' => Some("authenticate"),
            _ => None,
        })
        .collect();
    match names.is_empty() {
        true => "-".to_string(),
        false => names.join(", "),
    }
}

/// Returns the readable owner trust of a trust flag.
pub fn trust_label(flag: char) -> &'static str {
    match flag {
        'u' => "ultimate",
        'f' => "full",
        'm' => "marginal",
        'n' => "never",
        _ => "unknown",
    }
}

/// Returns the date `YYYY-MM-DD` of `secs` at `offset` (`-` when unknown).
pub fn date_text(secs: u64, offset: time::UtcOffset) -> String {
    let full = local_time::format_unix(secs, offset);
    full.split(' ').next().unwrap_or("-").to_string()
}

/// Returns the expiry of a key or subkey: `never`, or its date, marked
/// `(expired)` once passed at `now`.
pub fn expiry_text(expires: Option<u64>, now: u64, offset: time::UtcOffset) -> String {
    let Some(t) = expires else {
        return "never".to_string();
    };
    let date = date_text(t, offset);
    match t <= now {
        true => format!("{date} (expired)"),
        false => date,
    }
}

/// Returns why the secret key actions are refused (no secret part, or the
/// primary secret is not on this computer), `None` when allowed.
pub fn secret_blocked(key: &GpgKey) -> Option<&'static str> {
    if !key.secret {
        return Some(MSG_PUBLIC_ONLY);
    }
    if !key.primary_secret {
        return Some(MSG_PRIMARY_SECRET_UNAVAILABLE);
    }
    None
}

/// Returns why "Export secret key" is disabled.
pub fn export_blocked(state: &AppState, key: &GpgKey) -> Option<&'static str> {
    gpg_blocked(state).or(secret_blocked(key))
}

/// Returns why "Change passphrase" is disabled: gpg unusable, the secret
/// key rules, then the destructive gate (progress modal open).
pub fn change_blocked(state: &AppState, key: &GpgKey, gates: Gates) -> Option<&'static str> {
    export_blocked(state, key).or(gates.busy)
}

/// Returns why "Delete" is disabled: gpg unusable, a secret primary key
/// that is not on this computer (it cannot be backed up), then the
/// destructive gate.
pub fn delete_blocked(state: &AppState, key: &GpgKey, gates: Gates) -> Option<&'static str> {
    let stub = (key.secret && !key.primary_secret).then_some(MSG_PRIMARY_SECRET_UNAVAILABLE);
    gpg_blocked(state).or(stub).or(gates.busy)
}

/// Returns the type line, e.g. `EdDSA ed25519, 255 bits`.
pub fn type_line(key: &GpgKey) -> String {
    match key.bits {
        0 => key.algorithm.to_string(),
        bits => format!("{}, {bits} bits", key.algorithm),
    }
}

/// Renders chips left to right.
fn _chips(ui: &mut egui::Ui, chips: &[KeyChip]) {
    for c in chips {
        chip(ui, c.label(), c.color());
    }
}

/// Renders the first user id and the chips.
fn _header(ui: &mut egui::Ui, key: &GpgKey, now: u64) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.add(egui::Label::new(semibold(key_label(key), 22.0)).truncate());
        _chips(ui, &type_chips(key));
        _chips(ui, &status_chips(key, now));
    });
}

/// Renders the key actions: save public key, export secret, change
/// passphrase, delete.
fn _actions(ui: &mut egui::Ui, state: &AppState, key: &GpgKey, gates: Gates) -> Option<Action> {
    let mut action = None;
    let open = |dialog: GpgDialog| Some(Action::Open(DialogKind::Gpg(dialog)));
    ui.horizontal(|ui| {
        if secondary_button(ui, "Save public key...", gpg_blocked(state)) {
            action = open(GpgDialog::save_public(key));
        }
        if secondary_button(ui, "Export secret key...", export_blocked(state, key)) {
            action = open(GpgDialog::export_secret(key));
        }
        if secondary_button(
            ui,
            "Change passphrase...",
            change_blocked(state, key, gates),
        ) {
            action = open(GpgDialog::change_passphrase(key));
        }
        if danger_button(ui, "Delete...", delete_blocked(state, key, gates)) {
            action = open(GpgDialog::delete(key));
        }
    });
    action
}

/// Renders the notes: revoked or expired key, unusable or missing secret.
fn _notes(ui: &mut egui::Ui, key: &GpgKey, now: u64) {
    if is_revoked(key) {
        note(ui, theme::ERROR, MSG_REVOKED_NOTE, theme::ERROR);
    } else if is_expired(key, now) {
        note(ui, theme::TERTIARY, MSG_EXPIRED_NOTE, theme::TERTIARY);
    }
    if key.secret && !key.primary_secret {
        note(ui, theme::TERTIARY, MSG_STUB_NOTE, theme::TERTIARY);
    }
    if !key.secret {
        note(ui, theme::SECONDARY, MSG_PUBLIC_NOTE, theme::MUTED);
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

/// Renders the details card of the primary key.
fn _details(ui: &mut egui::Ui, key: &GpgKey, now: u64) {
    let offset = local_time::offset();
    card(ui, |ui| {
        ui.spacing_mut().item_spacing.y = 8.0;
        _row(
            ui,
            "Fingerprint",
            &grouped_fingerprint(&key.fingerprint),
            true,
        );
        _row(ui, "Key ID", &key.key_id, true);
        _row(ui, "Type", &type_line(key), false);
        _row(ui, "Usage", &usage_label(&key.capabilities), false);
        _row(ui, "Created", &date_text(key.created, offset), false);
        _row(ui, "Expires", &expiry_text(key.expires, now, offset), false);
        _row(ui, "Owner trust", trust_label(key.trust), false);
    });
}

/// Renders the user ids with their validity.
fn _uids(ui: &mut egui::Ui, key: &GpgKey) {
    card(ui, |ui| {
        field_label(ui, "User IDs");
        for uid in &key.uids {
            ui.horizontal(|ui| {
                let text = RichText::new(&uid.uid).color(theme::TEXT).size(13.5);
                ui.add(egui::Label::new(text).truncate());
                let flag = match uid.validity {
                    'r' => Some(KeyChip::Revoked),
                    'e' => Some(KeyChip::Expired),
                    other => validity_label(other).map(KeyChip::Validity),
                };
                if let Some(c) = flag {
                    chip(ui, c.label(), c.color());
                }
            });
        }
        if key.uids.is_empty() {
            muted(ui, "No user id");
        }
    });
}

/// Renders one subkey table cell of `width`.
fn _cell(ui: &mut egui::Ui, width: f32, text: RichText) {
    ui.allocate_ui(egui::vec2(width, 18.0), |ui| {
        ui.set_min_width(width);
        ui.add(egui::Label::new(text).truncate());
    });
}

/// Renders the subkeys table: key id, type, created, expires, usage.
fn _subkeys(ui: &mut egui::Ui, key: &GpgKey, now: u64) {
    if key.subkeys.is_empty() {
        return;
    }
    let offset = local_time::offset();
    let [id_w, type_w, created_w, expires_w] = SUBKEY_COLUMNS;
    card(ui, |ui| {
        field_label(ui, "Subkeys");
        ui.horizontal(|ui| {
            for (title, width) in [
                ("Key ID", id_w),
                ("Type", type_w),
                ("Created", created_w),
                ("Expires", expires_w),
            ] {
                _cell(
                    ui,
                    width,
                    RichText::new(title).color(theme::LABEL).size(11.5),
                );
            }
            ui.label(RichText::new("Usage").color(theme::LABEL).size(11.5));
        });
        for sub in &key.subkeys {
            let id_start = sub.fingerprint.len().saturating_sub(16);
            let id = sub.fingerprint.get(id_start..).unwrap_or_default();
            let value = |text: String| RichText::new(text).color(theme::TEXT).size(12.5);
            ui.horizontal(|ui| {
                let mono = RichText::new(id).monospace().size(12.0).color(theme::TEXT);
                _cell(ui, id_w, mono);
                _cell(ui, type_w, value(algorithm_label(&sub.algorithm, sub.bits)));
                _cell(ui, created_w, value(date_text(sub.created, offset)));
                _cell(ui, expires_w, value(expiry_text(sub.expires, now, offset)));
                ui.label(value(usage_label(&sub.capabilities)));
            });
        }
    });
}

/// Renders the public key box with its Copy button; returns the info
/// action after a copy.
fn _public_key(ui: &mut egui::Ui, state: &AppState, key: &GpgKey) -> Option<Action> {
    let mut action = None;
    let text = public_key(state, key);
    card(ui, |ui| {
        ui.horizontal(|ui| {
            field_label(ui, "Public key");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let blocked = text.is_none().then_some(MSG_READING);
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
            let Some(text) = text else {
                return muted(ui, MSG_READING);
            };
            egui::ScrollArea::vertical()
                .id_salt("kring-gpg-public")
                .max_height(PUBLIC_MAX_HEIGHT)
                .show(ui, |ui| {
                    let label = RichText::new(text)
                        .monospace()
                        .size(11.5)
                        .color(theme::TEXT);
                    ui.add(egui::Label::new(label).wrap());
                });
        });
    });
    action
}

/// Renders the empty state shown when no key is selected.
pub fn empty_state(ui: &mut egui::Ui) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        glyph_tile(ui, Ico::Shield, 64.0);
        ui.add_space(8.0);
        heading(ui, "Select a key");
        muted(
            ui,
            "Keys of your GnuPG keyring: create and import keys, export them, change their \
             passphrase or delete them (after a backup).",
        );
    });
}

/// Renders the notice of an unusable gpg, then the selected key (or the
/// empty state).
pub fn show(ui: &mut egui::Ui, state: &AppState, gates: Gates) -> Option<Action> {
    unavailable_card(ui, state);
    let Some(key) = selected_key(state) else {
        empty_state(ui);
        return None;
    };
    let now = now_secs();
    let mut action = None;
    egui::ScrollArea::vertical()
        .id_salt("kring-gpg-detail")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            _header(ui, key, now);
            ui.add_space(6.0);
            action = _actions(ui, state, key, gates);
            ui.add_space(8.0);
            _notes(ui, key, now);
            ui.add_space(4.0);
            _details(ui, key, now);
            ui.add_space(8.0);
            _uids(ui, key);
            ui.add_space(8.0);
            _subkeys(ui, key, now);
            ui.add_space(8.0);
            action = _public_key(ui, state, key).or(action.take());
        });
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::dialog_gpg::tests::{public_key as public_fixture, secret_key};
    use crate::worker::Event;

    /// v4 fingerprints are grouped by 4 with a wider middle gap; others by 4.
    #[test]
    fn fingerprint_groups() {
        let fpr = "F304378CE8CEEF63BB59F93CEF2CA8C2F6A348DC";
        assert_eq!(
            grouped_fingerprint(fpr),
            "F304 378C E8CE EF63 BB59  F93C EF2C A8C2 F6A3 48DC"
        );
        assert_eq!(grouped_fingerprint("ABCDEF"), "ABCD EF");
        assert_eq!(grouped_fingerprint(""), "");
    }

    /// Usage, trust, type and expiry texts.
    #[test]
    fn detail_texts() {
        assert_eq!(usage_label("scESC"), "sign, certify");
        assert_eq!(usage_label("e"), "encrypt");
        assert_eq!(usage_label(""), "-");
        assert_eq!(trust_label('u'), "ultimate");
        assert_eq!(trust_label('-'), "unknown");
        assert_eq!(type_line(&secret_key()), "EdDSA ed25519, 255 bits");
        let utc = time::UtcOffset::UTC;
        assert_eq!(expiry_text(None, 0, utc), "never");
        assert_eq!(expiry_text(Some(86_400), 0, utc), "1970-01-02");
        assert_eq!(
            expiry_text(Some(86_400), 86_400, utc),
            "1970-01-02 (expired)"
        );
        assert_eq!(date_text(0, utc), "-");
    }

    /// Secret actions need a secret primary key on disk; delete is refused
    /// only for stubs; all are blocked while gpg is unusable or busy.
    #[test]
    fn action_gating() {
        let free = Gates::from_provider(None);
        let mut s = AppState::default();
        let secret = secret_key();
        let public = public_fixture();
        assert_eq!(change_blocked(&s, &secret, free), None);
        assert_eq!(delete_blocked(&s, &secret, free), None);
        assert_eq!(export_blocked(&s, &public), Some(MSG_PUBLIC_ONLY));
        assert_eq!(delete_blocked(&s, &public, free), None);
        let mut stub = secret.clone();
        stub.primary_secret = false;
        assert_eq!(
            change_blocked(&s, &stub, free),
            Some(MSG_PRIMARY_SECRET_UNAVAILABLE)
        );
        assert_eq!(
            delete_blocked(&s, &stub, free),
            Some(MSG_PRIMARY_SECRET_UNAVAILABLE)
        );
        let busy = free.with_operation(true);
        assert!(change_blocked(&s, &secret, busy).is_some());
        assert!(delete_blocked(&s, &public, busy).is_some());
        s.apply(Event::GpgUnavailable {
            reason: "x".into(),
            scan: false,
        });
        assert!(delete_blocked(&s, &public, free).is_some());
        assert!(export_blocked(&s, &secret).is_some());
    }

    /// The public key is read on selection; only the selected key's text is shown.
    #[test]
    fn public_key_reading() {
        let key = secret_key();
        assert!(matches!(
            select_command(&key),
            Command::ExportGpgPublic { fpr } if fpr == key.fingerprint
        ));
        let mut s = AppState::default();
        s.apply(Event::GpgKeys(vec![key.clone(), public_fixture()]));
        s.select_gpg_key(key.fingerprint.clone());
        assert_eq!(selected_key(&s), Some(&key));
        assert!(public_key(&s, &key).is_none());
        s.apply(Event::GpgPublicKey {
            fpr: key.fingerprint.clone(),
            text: "armored".into(),
        });
        assert_eq!(public_key(&s, &key), Some("armored"));
        assert!(public_key(&s, &public_fixture()).is_none());
    }
}
