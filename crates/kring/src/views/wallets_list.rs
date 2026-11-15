//! List panel "KWallet wallets": rescan button, search box, summary and rows.

use eframe::egui::{self, Align, Color32, Layout, RichText, Sense, Ui, UiBuilder};

use crate::app_state::{AppState, count_noun};
use crate::ui::glyphs::Ico;
use crate::ui::theme;
use crate::ui::widgets::{chip, ico_button, muted, muted_text, search_box, semibold};
use crate::views::Action;
use crate::views::files_list::format_size;
use crate::views::sidebar::row_background;
use crate::worker::{Command, WalletInfo};

/// Height of a wallet row (name and subline).
const ROW_HEIGHT: f32 = 52.0;
/// Horizontal padding inside a row.
const ROW_PADDING: f32 = 12.0;
/// Subline part of a wallet with an attributes file.
const MSG_HAS_ATTRIBUTES: &str = "app attributes";

/// A status chip of a wallet file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletChip {
    /// Blowfish CBC cipher (the supported one).
    BlowfishCbc,
    /// PBKDF2-SHA512 key derivation (the supported one).
    Pbkdf2,
    /// A KWallet wallet in a format kring cannot read.
    Unsupported,
    /// Not a KWallet wallet file.
    Unknown,
}

impl WalletChip {
    /// Chip text (painted uppercase).
    pub fn label(self) -> &'static str {
        match self {
            Self::BlowfishCbc => "blowfish cbc",
            Self::Pbkdf2 => "pbkdf2",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
        }
    }

    /// Tint of the chip text and border.
    pub fn color(self) -> Color32 {
        match self {
            Self::BlowfishCbc | Self::Pbkdf2 => theme::SECONDARY,
            Self::Unsupported | Self::Unknown => theme::ERROR,
        }
    }
}

/// Returns the chips of a wallet, in display order.
pub fn wallet_chips(info: &WalletInfo) -> Vec<WalletChip> {
    match &info.header {
        None => vec![WalletChip::Unknown],
        Some(h) if h.is_supported() => vec![WalletChip::BlowfishCbc, WalletChip::Pbkdf2],
        Some(_) => vec![WalletChip::Unsupported],
    }
}

/// Returns true when the wallet can be opened (a supported KWallet header).
pub fn is_readable(info: &WalletInfo) -> bool {
    info.header.as_ref().is_some_and(|h| h.is_supported())
}

/// Returns the row subline, e.g. `20.8 KB - app attributes`.
pub fn row_subline(info: &WalletInfo) -> String {
    let size = format_size(info.size);
    if !info.has_attributes {
        return size;
    }
    format!("{size} - {MSG_HAS_ATTRIBUTES}")
}

/// Returns the muted summary line, e.g. `2 wallets - 1 with app attributes`.
pub fn wallets_summary(wallets: &[WalletInfo]) -> String {
    let with = wallets.iter().filter(|w| w.has_attributes).count();
    format!(
        "{} - {with} with app attributes",
        count_noun(wallets.len(), "wallet")
    )
}

/// Returns true when the wallet name contains `filter` (case-insensitive).
pub fn wallet_matches(info: &WalletInfo, filter: &str) -> bool {
    let needle = filter.trim().to_lowercase();
    needle.is_empty() || info.name.to_lowercase().contains(&needle)
}

/// Renders the chips of a wallet.
pub fn chips(ui: &mut Ui, info: &WalletInfo) {
    for c in wallet_chips(info) {
        chip(ui, c.label(), c.color());
    }
}

/// Renders one wallet row; returns true when clicked.
fn _row(ui: &mut Ui, info: &WalletInfo, selected: bool) -> bool {
    let size = egui::vec2(ui.available_width(), ROW_HEIGHT);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    row_background(ui, rect, selected, resp.hovered());
    let inner = rect.shrink2(egui::vec2(ROW_PADDING, 0.0));
    // Right to left: the chips keep their room, the name truncates.
    let builder = UiBuilder::new()
        .max_rect(inner)
        .layout(Layout::right_to_left(Align::Center));
    ui.scope_builder(builder, |ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        for c in wallet_chips(info).into_iter().rev() {
            chip(ui, c.label(), c.color());
        }
        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                let name = RichText::new(&info.name)
                    .family(theme::medium())
                    .size(14.0)
                    .color(theme::TEXT);
                ui.add(egui::Label::new(name).truncate().selectable(false));
                let subline = muted_text(row_subline(info));
                ui.add(egui::Label::new(subline).truncate().selectable(false));
            });
        });
    });
    resp.clicked()
}

/// Renders the wallets list panel and returns the requested action.
pub fn show(ui: &mut Ui, state: &AppState, filter: &mut String) -> Option<Action> {
    let mut action = None;
    ui.horizontal(|ui| {
        ui.label(semibold("KWallet wallets", 18.0));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ico_button(ui, Ico::Refresh, "Rescan the KWallet folder", None, false) {
                action = Some(Action::Send(Command::ScanWallets));
            }
        });
    });
    ui.add_space(2.0);
    search_box(ui, filter, "Search wallets");
    muted(ui, &wallets_summary(&state.wallets));
    ui.add_space(2.0);
    egui::ScrollArea::vertical()
        .id_salt("kring-wallets")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for info in state.wallets.iter().filter(|w| wallet_matches(w, filter)) {
                let selected = state.selected_wallet.as_ref() == Some(&info.name);
                if _row(ui, info, selected) && !selected {
                    action = Some(Action::SelectWallet(info.name.clone()));
                }
            }
        });
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use kring_core::kwallet_file::WalletHeader;

    /// Builds a wallet with the given header and attributes flag.
    fn wallet(name: &str, header: Option<WalletHeader>, attrs: bool) -> WalletInfo {
        WalletInfo {
            name: name.into(),
            path: format!("/k/{name}.kwl").into(),
            size: 21_256,
            modified: 1_759_363_200,
            header,
            has_attributes: attrs,
            suggested_target: None,
        }
    }

    /// The header of the supported format (version 0.1, Blowfish CBC, PBKDF2).
    fn supported() -> WalletHeader {
        WalletHeader {
            major: 0,
            minor: 1,
            cipher: 3,
            hash: 2,
        }
    }

    /// Supported wallets show cipher and hash, others UNSUPPORTED or UNKNOWN.
    #[test]
    fn chips_by_header() {
        use WalletChip::*;
        let legacy = WalletHeader {
            cipher: 0,
            hash: 0,
            ..supported()
        };
        assert_eq!(
            wallet_chips(&wallet("k", Some(supported()), true)),
            [BlowfishCbc, Pbkdf2]
        );
        assert_eq!(
            wallet_chips(&wallet("l", Some(legacy), false)),
            [Unsupported]
        );
        assert_eq!(wallet_chips(&wallet("j", None, false)), [Unknown]);
        assert!(is_readable(&wallet("k", Some(supported()), true)));
        assert!(!is_readable(&wallet("l", Some(legacy), true)));
        assert!(!is_readable(&wallet("j", None, true)));
        assert_eq!(Unsupported.color(), theme::ERROR);
        assert_eq!(Pbkdf2.label(), "pbkdf2");
    }

    /// The subline shows the size and the attributes file; the summary counts both.
    #[test]
    fn subline_and_summary() {
        let a = wallet("kdewallet", Some(supported()), true);
        let b = wallet("other", None, false);
        assert_eq!(row_subline(&a), "20.8 KB - app attributes");
        assert_eq!(row_subline(&b), "20.8 KB");
        assert_eq!(
            wallets_summary(&[a.clone(), b]),
            "2 wallets - 1 with app attributes"
        );
        assert_eq!(wallets_summary(&[a]), "1 wallet - 1 with app attributes");
        assert_eq!(wallets_summary(&[]), "0 wallets - 0 with app attributes");
    }

    /// The filter matches the name case-insensitively; blank matches all.
    #[test]
    fn filter_by_name() {
        let w = wallet("kdewallet", None, false);
        assert!(wallet_matches(&w, " "));
        assert!(wallet_matches(&w, "KDE"));
        assert!(!wallet_matches(&w, "login"));
    }
}
