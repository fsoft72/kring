//! The selected KWallet wallet: header, notes, Open / Import and its entries.

use eframe::egui::{self, RichText};
use kring_core::model::CollectionInfo;
use kring_core::provider::ProviderInfo;

use crate::app_state::AppState;
use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;
use crate::ui::widgets::{accent_card, glyph_tile, heading, muted, note, primary_button, semibold};
use crate::views::collection::{format_date, shown_name};
use crate::views::dialogs::DialogKind;
use crate::views::file_detail::{default_import_target, import_report};
use crate::views::files_list::format_size;
use crate::views::wallet_items::{self, WalletView};
use crate::views::wallets_list::{chips, is_readable};
use crate::views::{Action, Gates, MSG_NO_PROVIDER};
use crate::worker::{WalletInfo, kwallet_competitors};

/// Tooltip of Import before the wallet is opened.
const MSG_OPEN_FIRST: &str = "Open the wallet first";
/// Tooltip of Import on a wallet kring cannot read.
const MSG_UNREADABLE: &str = "This wallet format cannot be read";
/// Tooltip of Import on an open wallet without entries.
const MSG_NO_ENTRIES: &str = "No entries to import";
/// Tooltip of Import when no keyring can receive the entries.
const MSG_NO_TARGET: &str = "Unlock a keyring first";
/// Body of the card of a wallet not opened yet.
const MSG_ENCRYPTED: &str = "Encrypted wallet. Enter its password to see the entries.";
/// Note of every wallet: it is only read.
const MSG_READ_ONLY: &str = "Read from disk without KWallet: the wallet files are never changed";
/// Note of a file that is not a KWallet wallet.
const MSG_NOT_WALLET: &str = "Not a KWallet wallet file";
/// Note of a wallet in a format kring cannot read.
const MSG_UNSUPPORTED: &str =
    "Unsupported wallet format: only Blowfish CBC wallets with PBKDF2-SHA512 keys can be read";
/// Title of the card shown while KWallet daemons are on the bus.
const MSG_COMPETITOR_TITLE: &str = "KWallet is still running";
/// Advice of the card shown while KWallet daemons are on the bus.
const MSG_COMPETITOR_ADVICE: &str = "After migrating, disable KWallet's Secret Service \
     integration (System Settings > KDE Wallet: uncheck \"Use KWallet for the Secret Service \
     interface\") and log in again, so gnome-keyring keeps org.freedesktop.secrets.";

/// Returns the info line about the keyring KWallet apps look for.
pub fn wallet_keyring_info(name: &str) -> String {
    format!(
        "Apps using KWallet look for a keyring named '{name}'. Importing into login keeps the \
         secrets but those apps will not find them."
    )
}

/// Returns the import dialog option creating the keyring of wallet `name`.
pub fn create_option_label(name: &str) -> String {
    format!("Create keyring '{name}'")
}

/// Returns the muted subline, e.g. `20.8 KB - modified 2025-10-02 - has app attributes`.
pub fn wallet_subline(info: &WalletInfo) -> String {
    let mut text = format!(
        "{} - modified {}",
        format_size(info.size),
        format_date(info.modified)
    );
    if info.has_attributes {
        text.push_str(" - has app attributes");
    }
    text
}

/// Returns the keyring labelled like wallet `info`: its suggested target
/// when still listed, else any current collection with that label (so a
/// keyring created since the last scan is never offered again).
pub fn wallet_keyring<'a>(
    info: &WalletInfo,
    collections: &'a [CollectionInfo],
) -> Option<&'a CollectionInfo> {
    let suggested = info.suggested_target.as_ref();
    collections
        .iter()
        .find(|c| Some(&c.id) == suggested)
        .or_else(|| collections.iter().find(|c| c.label == info.name))
}

/// Returns why Import is disabled for `info`, or `None` when allowed:
/// a provider, a readable and open wallet with entries, and a keyring to
/// receive them (the one labelled like the wallet when unlocked, a new one
/// when it can be created, or any unlocked one). When the wallet keyring is
/// locked and nothing else is unlocked the reason is `Unlock '<name>' first`.
pub fn import_blocked(state: &AppState, info: &WalletInfo, gates: Gates) -> Option<String> {
    let fixed = |m: &str| Some(m.to_string());
    if state.provider.is_none() {
        return fixed(MSG_NO_PROVIDER);
    }
    if !is_readable(info) {
        return fixed(MSG_UNREADABLE);
    }
    if !state.wallet_opened || state.wallet_password().is_none() {
        return fixed(MSG_OPEN_FIRST);
    }
    if state.wallet_items.is_empty() {
        return fixed(MSG_NO_ENTRIES);
    }
    let unlocked = default_import_target(&state.collections).is_some();
    match wallet_keyring(info, &state.collections) {
        Some(c) if c.locked && !unlocked => Some(format!(
            "Unlock '{}' first",
            shown_name(&state.collections, c)
        )),
        Some(_) => None,
        None if gates.master.is_none() || unlocked => None,
        None => fixed(MSG_NO_TARGET),
    }
}

/// Returns the import dialog of the open wallet `info` (needs its password).
pub fn import_dialog(state: &AppState, info: &WalletInfo, gates: Gates) -> Option<DialogKind> {
    let password = state.wallet_password()?.clone();
    Some(DialogKind::import_wallet(
        info.name.clone(),
        password,
        &state.collections,
        wallet_keyring(info, &state.collections),
        gates.master,
    ))
}

/// Returns the target note: where imports go by default (asking to unlock
/// it when locked), or the info line when no keyring is labelled like the
/// wallet (`true` = warning tint).
pub fn target_note(info: &WalletInfo, collections: &[CollectionInfo]) -> (String, bool) {
    let Some(c) = wallet_keyring(info, collections) else {
        return (wallet_keyring_info(&info.name), true);
    };
    let mut text = format!(
        "Imports go to the keyring '{}', labelled like this wallet: apps using KWallet find \
         the entries there.",
        shown_name(collections, c)
    );
    if c.locked {
        text.push_str(" Unlock it first.");
    }
    (text, c.locked)
}

/// Returns the KWallet bus names of the competitor card, empty when none.
pub fn competitor_names(provider: Option<&ProviderInfo>) -> Vec<&str> {
    provider.map(kwallet_competitors).unwrap_or_default()
}

/// Renders name, chips, Import, path and subline.
fn _header(ui: &mut egui::Ui, state: &AppState, info: &WalletInfo, gates: Gates) -> Option<Action> {
    let mut action = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.add(egui::Label::new(semibold(&info.name, 22.0)).truncate());
        chips(ui, info);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let blocked = import_blocked(state, info, gates);
            if primary_button(ui, "Import into...", blocked.as_deref()) {
                action = import_dialog(state, info, gates).map(Action::Open);
            }
        });
    });
    ui.label(
        RichText::new(info.path.display().to_string())
            .monospace()
            .size(12.0)
            .color(theme::MUTED),
    );
    muted(ui, &wallet_subline(info));
    action
}

/// Renders the notes: format problems, read only, target and the KWallet
/// competitor card.
fn _notes(ui: &mut egui::Ui, state: &AppState, info: &WalletInfo) {
    ui.add_space(4.0);
    match &info.header {
        None => note(ui, theme::ERROR, MSG_NOT_WALLET, theme::ERROR),
        Some(h) if !h.is_supported() => note(ui, theme::ERROR, MSG_UNSUPPORTED, theme::ERROR),
        Some(_) => {}
    }
    note(ui, theme::SECONDARY, MSG_READ_ONLY, theme::MUTED);
    if is_readable(info) {
        let (text, warn) = target_note(info, &state.collections);
        let (accent, color) = if warn {
            (theme::TERTIARY, theme::TERTIARY)
        } else {
            (theme::SECONDARY, theme::MUTED)
        };
        note(ui, accent, &text, color);
    }
    let names = competitor_names(state.provider.as_ref());
    if names.is_empty() {
        return;
    }
    accent_card(ui, theme::TERTIARY, |ui| {
        let title = format!("{MSG_COMPETITOR_TITLE} ({})", names.join(", "));
        ui.label(RichText::new(title).color(theme::TERTIARY).size(12.5));
        ui.label(
            RichText::new(MSG_COMPETITOR_ADVICE)
                .color(theme::MUTED)
                .size(12.0),
        );
    });
}

/// Renders the card of a wallet whose entries are not read yet.
fn _encrypted_card(ui: &mut egui::Ui, info: &WalletInfo) -> Option<Action> {
    let mut action = None;
    accent_card(ui, theme::SECONDARY, |ui| {
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
            glyphs::paint(ui.painter(), r, Ico::Lock, theme::LABEL);
            ui.label(RichText::new(MSG_ENCRYPTED).color(theme::MUTED));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if primary_button(ui, "Open", None) {
                    let kind = DialogKind::wallet_password(info.name.clone());
                    action = Some(Action::Open(kind));
                }
            });
        });
    });
    action
}

/// Renders the empty state shown when no wallet is selected.
pub fn empty_state(ui: &mut egui::Ui, state: &AppState) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        glyph_tile(ui, Ico::Wallet, 64.0);
        ui.add_space(8.0);
        heading(ui, "Select a wallet");
        muted(
            ui,
            "KWallet wallets are read from disk, without KWallet, and imported into keyrings.",
        );
        let dir = state.wallets.first().and_then(|w| w.path.parent());
        let Some(dir) = dir else {
            return;
        };
        ui.add_space(12.0);
        ui.label(
            RichText::new(dir.display().to_string())
                .monospace()
                .size(12.0)
                .color(theme::MUTED),
        );
    });
}

/// Renders the selected wallet with its entries.
pub fn show(
    ui: &mut egui::Ui,
    state: &AppState,
    view: &mut WalletView,
    gates: Gates,
) -> Option<Action> {
    view.sync(state);
    let Some(info) = state
        .selected_wallet
        .as_ref()
        .and_then(|name| state.wallets.iter().find(|w| &w.name == name))
    else {
        empty_state(ui, state);
        return None;
    };
    let action = _header(ui, state, info, gates);
    _notes(ui, state, info);
    import_report(ui, state);
    ui.add_space(10.0);
    if !is_readable(info) {
        return action;
    }
    if !state.wallet_opened {
        return _encrypted_card(ui, info).or(action);
    }
    wallet_items::show(ui, state, view).or(action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::dialogs::WalletTarget;
    use crate::worker::{Command, Event, OfflineItemView, WalletEntryKind};
    use kring_core::kwallet_file::WalletHeader;
    use kring_core::model::{CollectionId, LOGIN_COLLECTION_PATH, SecretValue};
    use kring_core::provider::ProviderKind;

    /// Builds a supported wallet named `name`, suggesting `target`.
    fn wallet(name: &str, target: Option<&str>) -> WalletInfo {
        WalletInfo {
            name: name.into(),
            path: format!("/k/{name}.kwl").into(),
            size: 896,
            modified: 1_759_363_200,
            header: Some(WalletHeader {
                major: 0,
                minor: 1,
                cipher: 3,
                hash: 2,
            }),
            has_attributes: true,
            suggested_target: target.map(|t| CollectionId(t.into())),
        }
    }

    /// Builds a collection.
    fn col(path: &str, label: &str, locked: bool) -> CollectionInfo {
        CollectionInfo {
            id: CollectionId(path.into()),
            label: label.into(),
            locked,
            item_count: 0,
            aliases: vec![],
            is_login: path == LOGIN_COLLECTION_PATH,
            created: 0,
            modified: 0,
        }
    }

    /// Builds a provider with the given competitors.
    fn provider(competitors: &[&str], master: bool) -> ProviderInfo {
        ProviderInfo {
            kind: ProviderKind::GnomeKeyring,
            pid: None,
            process_name: None,
            competitors: competitors.iter().map(|c| c.to_string()).collect(),
            has_master_password_iface: master,
        }
    }

    /// Builds a state with `wallet` selected (opened with `pw` when given).
    fn state(info: WalletInfo, cols: Vec<CollectionInfo>, pw: Option<&str>) -> AppState {
        let mut s = AppState::default();
        s.apply(Event::Provider(provider(&[], true)));
        s.apply(Event::Collections(cols));
        let name = info.name.clone();
        s.apply(Event::Wallets(vec![info]));
        s.select_wallet(name.clone());
        let Some(pw) = pw else {
            return s;
        };
        s.track_wallet_command(
            &Command::OpenWallet {
                name: name.clone(),
                password: SecretValue::from_text(pw),
            },
            0,
        );
        let item = OfflineItemView {
            label: "x".into(),
            attributes: Default::default(),
            folder: "f".into(),
            key: "x".into(),
            kind: WalletEntryKind::Password,
            app_entry: true,
            modified: 0,
            secret: SecretValue::from_text("s"),
        };
        s.apply(Event::WalletItems {
            name,
            items: vec![item],
        });
        s
    }

    /// Gates of gnome-keyring with or without the master password interface.
    fn gates(master: bool) -> Gates {
        Gates::from_provider(Some(&provider(&[], master)))
    }

    /// The info line and the create option name the wallet.
    #[test]
    fn info_texts() {
        assert_eq!(
            wallet_keyring_info("kdewallet"),
            "Apps using KWallet look for a keyring named 'kdewallet'. Importing into login \
             keeps the secrets but those apps will not find them."
        );
        assert_eq!(
            create_option_label("kdewallet"),
            "Create keyring 'kdewallet'"
        );
        assert_eq!(
            wallet_subline(&wallet("w", None)),
            "896 B - modified 2025-10-02 - has app attributes"
        );
    }

    /// Import needs a provider, an open readable wallet with entries and a target.
    #[test]
    fn import_gates() {
        let login = col(LOGIN_COLLECTION_PATH, "Login", false);
        let closed = state(wallet("w", None), vec![login.clone()], None);
        let info = closed.wallets[0].clone();
        assert_eq!(
            import_blocked(&closed, &info, gates(true)),
            Some(MSG_OPEN_FIRST.to_string())
        );
        assert!(import_dialog(&closed, &info, gates(true)).is_none());
        let open = state(wallet("w", None), vec![login.clone()], Some("pw"));
        assert_eq!(import_blocked(&open, &info, gates(true)), None);
        let mut legacy = info.clone();
        legacy.header = legacy.header.map(|h| WalletHeader { cipher: 0, ..h });
        assert_eq!(
            import_blocked(&open, &legacy, gates(true)),
            Some(MSG_UNREADABLE.to_string())
        );
        let locked = state(
            wallet("w", None),
            vec![col(LOGIN_COLLECTION_PATH, "Login", true)],
            Some("pw"),
        );
        assert_eq!(import_blocked(&locked, &info, gates(true)), None, "create");
        assert_eq!(
            import_blocked(&locked, &info, gates(false)),
            Some(MSG_NO_TARGET.to_string())
        );
        let mut none = AppState::default();
        none.apply(Event::Wallets(vec![info.clone()]));
        assert_eq!(
            import_blocked(&none, &info, gates(true)),
            Some(MSG_NO_PROVIDER.to_string())
        );
    }

    /// The dialog preselects the keyring labelled like the wallet; without
    /// one it offers and preselects Create, or the default target when
    /// creation is blocked. It carries the wallet password.
    #[test]
    fn dialog_targets() {
        let login = col(LOGIN_COLLECTION_PATH, "Login", false);
        let kde = col("/c/kdewallet", "kdewallet", false);
        let s = state(
            wallet("kdewallet", Some("/c/kdewallet")),
            vec![login.clone(), kde],
            Some("pw"),
        );
        let info = s.wallets[0].clone();
        let Some(DialogKind::ImportWallet {
            password,
            target,
            offer_create,
            targets,
            ..
        }) = import_dialog(&s, &info, gates(true))
        else {
            panic!("expected the wallet import dialog");
        };
        assert_eq!(password.as_text(), Some("pw"));
        assert_eq!(
            target,
            Some(WalletTarget::Keyring(CollectionId("/c/kdewallet".into())))
        );
        assert!(!offer_create);
        assert_eq!(targets.len(), 2);

        let s = state(wallet("kdewallet", None), vec![login.clone()], Some("pw"));
        let info = s.wallets[0].clone();
        let Some(DialogKind::ImportWallet {
            target,
            offer_create,
            ..
        }) = import_dialog(&s, &info, gates(true))
        else {
            panic!("expected the wallet import dialog");
        };
        assert_eq!(target, Some(WalletTarget::Create));
        assert!(offer_create);
        let Some(DialogKind::ImportWallet {
            target,
            create_blocked,
            ..
        }) = import_dialog(&s, &info, gates(false))
        else {
            panic!("expected the wallet import dialog");
        };
        assert_eq!(target, Some(WalletTarget::Keyring(login.id.clone())));
        assert!(create_blocked.is_some());

        // A keyring labelled like the wallet but created after the scan
        // (no suggestion yet) is used: Create is not offered again.
        let kde = col("/c/kdewallet", "kdewallet", false);
        let s = state(
            wallet("kdewallet", None),
            vec![login.clone(), kde],
            Some("pw"),
        );
        let Some(DialogKind::ImportWallet {
            target,
            offer_create,
            ..
        }) = import_dialog(&s, &s.wallets[0], gates(true))
        else {
            panic!("expected the wallet import dialog");
        };
        assert!(!offer_create);
        assert_eq!(
            target,
            Some(WalletTarget::Keyring(CollectionId("/c/kdewallet".into())))
        );
    }

    /// A locked wallet keyring is not preselected: the first unlocked
    /// keyring is; without any, Import asks to unlock it.
    #[test]
    fn locked_wallet_keyring() {
        let login = col(LOGIN_COLLECTION_PATH, "Login", false);
        let kde = col("/c/kdewallet", "kdewallet", true);
        let info = wallet("kdewallet", Some("/c/kdewallet"));
        let s = state(info.clone(), vec![login.clone(), kde.clone()], Some("pw"));
        assert_eq!(import_blocked(&s, &info, gates(true)), None);
        let Some(DialogKind::ImportWallet {
            target,
            offer_create,
            ..
        }) = import_dialog(&s, &info, gates(true))
        else {
            panic!("expected the wallet import dialog");
        };
        assert!(!offer_create);
        assert_eq!(target, Some(WalletTarget::Keyring(login.id.clone())));
        let s = state(info.clone(), vec![kde], Some("pw"));
        assert_eq!(
            import_blocked(&s, &info, gates(true)).as_deref(),
            Some("Unlock 'kdewallet' first")
        );
    }

    /// The target note names the suggested keyring, or warns with the info line.
    #[test]
    fn target_notes() {
        let kde = col("/c/kdewallet", "kdewallet", false);
        let (text, warn) = target_note(
            &wallet("kdewallet", Some("/c/kdewallet")),
            std::slice::from_ref(&kde),
        );
        assert!(!warn && text.contains("'kdewallet'"));
        let locked = CollectionInfo {
            locked: true,
            ..kde
        };
        let (text, warn) = target_note(&wallet("kdewallet", Some("/c/kdewallet")), &[locked]);
        assert!(warn && text.ends_with("Unlock it first."));
        let (text, warn) = target_note(&wallet("kdewallet", Some("/c/gone")), &[]);
        assert!(warn);
        assert_eq!(text, wallet_keyring_info("kdewallet"));
    }

    /// Only KWallet daemons show the competitor card.
    #[test]
    fn competitor_card_names() {
        assert!(competitor_names(None).is_empty());
        let p = provider(&["org.keepassxc.KeePassXC.MainWindow"], true);
        assert!(competitor_names(Some(&p)).is_empty());
        let p = provider(
            &[
                "org.kde.ksecretd",
                "org.keepassxc.KeePassXC.MainWindow",
                "org.kde.kwalletd6",
            ],
            true,
        );
        assert_eq!(
            competitor_names(Some(&p)),
            ["org.kde.ksecretd", "org.kde.kwalletd6"]
        );
    }
}
