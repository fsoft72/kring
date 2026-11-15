//! Locked keyrings skipped by the consolidation preview: one row per
//! keyring (lock glyph, shown name, Unlock), naturally sorted, the first
//! rows only until expanded, and "Unlock all" with one password.

use std::cmp::Ordering;
use std::collections::HashMap;

use eframe::egui::{self, Align, Layout, RichText, Sense, Ui};
use kring_core::model::{CollectionId, SecretValue};
use kring_core::transfer::consolidate::SkipReason;

use crate::app_state::count_noun;
use crate::ui::glyphs::{self, Ico};
use crate::ui::theme;
use crate::ui::widgets::{accent_card, compact_button, muted_text, semibold};
use crate::views::consolidate::name_in;
use crate::views::dialogs::DialogKind;
use crate::views::sidebar::row_background;
use crate::views::{Action, Gates};
use crate::worker::{Command, ConsolidationSummary};

/// Rows shown before "Show all".
pub const VISIBLE_ROWS: usize = 8;
/// Height of a keyring row.
const ROW_HEIGHT: f32 = 34.0;
/// Horizontal padding inside a row.
const ROW_PADDING: f32 = 8.0;
/// Side of the lock glyph box.
const GLYPH_SIZE: f32 = 18.0;
/// Most height of the expanded list before it scrolls.
const LIST_MAX_HEIGHT: f32 = 260.0;
/// Height of the card header row.
const HEADER_HEIGHT: f32 = 28.0;
/// Muted line under the card header.
pub const MSG_UNLOCK_TO_INCLUDE: &str = "Unlock them to include them in the consolidation.";
/// Text of the button unlocking every listed keyring.
const UNLOCK_ALL_TEXT: &str = "Unlock all";
/// Text collapsing the expanded list.
const SHOW_FEWER_TEXT: &str = "Show fewer";

/// Compares `a` and `b` for display: case-insensitive, with runs of digits
/// compared by value (`Default_keyring_3` before `Default_keyring_10`); a
/// tie falls back to the plain text order.
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (mut x, mut y) = (a, b);
    while let (Some(cx), Some(cy)) = (x.chars().next(), y.chars().next()) {
        let order = if cx.is_ascii_digit() && cy.is_ascii_digit() {
            let (nx, rx) = _split_digits(x);
            let (ny, ry) = _split_digits(y);
            (x, y) = (rx, ry);
            _cmp_digits(nx, ny)
        } else {
            x = &x[cx.len_utf8()..];
            y = &y[cy.len_utf8()..];
            cx.to_lowercase().cmp(cy.to_lowercase())
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    x.len().cmp(&y.len()).then_with(|| a.cmp(b))
}

/// Splits `s` into its leading run of ASCII digits and the rest.
fn _split_digits(s: &str) -> (&str, &str) {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    s.split_at(end)
}

/// Compares two runs of digits by value (any length, leading zeros ignored).
fn _cmp_digits(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Returns the locked keyrings skipped by `summary` with their shown
/// names (see [`name_in`]), naturally sorted by name.
pub fn locked_entries(
    summary: &ConsolidationSummary,
    names: &HashMap<CollectionId, String>,
) -> Vec<(CollectionId, String)> {
    let mut out: Vec<(CollectionId, String)> = summary
        .skipped
        .iter()
        .filter(|(_, _, reason)| *reason == SkipReason::Locked)
        .map(|(id, label, _)| (id.clone(), name_in(names, id, label)))
        .collect();
    out.sort_by(|(_, a), (_, b)| natural_cmp(a, b));
    out
}

/// What "Unlock all" does.
pub enum UnlockAll {
    /// Send the unlock with the remembered passphrase and show the toast text.
    Send(Command, String),
    /// Ask the password in this dialog.
    Ask(DialogKind),
}

/// Returns what "Unlock all" of `collections` does: tried right away with
/// the `remembered` passphrase, otherwise the password dialog.
pub fn unlock_all(remembered: Option<&SecretValue>, collections: Vec<CollectionId>) -> UnlockAll {
    let Some(password) = remembered.cloned() else {
        return UnlockAll::Ask(DialogKind::unlock_many(collections));
    };
    let text = format!(
        "Trying the remembered passphrase on {}",
        count_noun(collections.len(), "keyring")
    );
    UnlockAll::Send(
        Command::UnlockMany {
            collections,
            password,
        },
        text,
    )
}

/// Returns the text of the toggle under a list of `total` rows.
pub fn toggle_text(total: usize, show_all: bool) -> String {
    if show_all {
        return SHOW_FEWER_TEXT.to_string();
    }
    format!("Show all {total}")
}

/// Renders one locked keyring row; returns true when Unlock was clicked.
fn _row(ui: &mut Ui, name: &str, gates: Gates) -> bool {
    let size = egui::vec2(ui.available_width(), ROW_HEIGHT);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    row_background(ui, rect, false, ui.rect_contains_pointer(rect));
    let inner = rect.shrink2(egui::vec2(ROW_PADDING, 0.0));
    let mut clicked = false;
    ui.scope_builder(
        egui::UiBuilder::new()
            .max_rect(inner)
            .layout(Layout::right_to_left(Align::Center)),
        |ui| {
            clicked = compact_button(ui, "Unlock", gates.master);
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                let (glyph, _) =
                    ui.allocate_exact_size(egui::vec2(GLYPH_SIZE, GLYPH_SIZE), Sense::hover());
                glyphs::paint(ui.painter(), glyph, Ico::Lock, theme::TERTIARY);
                ui.add_space(4.0);
                let text = RichText::new(name).color(theme::TEXT).size(13.0);
                ui.add(egui::Label::new(text).truncate());
            });
        },
    );
    clicked
}

/// Renders the rows of `entries`; returns the Unlock dialog of a clicked one.
fn _rows(ui: &mut Ui, entries: &[(CollectionId, String)], gates: Gates) -> Option<Action> {
    let mut action = None;
    ui.spacing_mut().item_spacing.y = 2.0;
    for (id, name) in entries {
        if _row(ui, name, gates) {
            action = Some(Action::Open(DialogKind::unlock(id.clone(), name.clone())));
        }
    }
    action
}

/// Renders the card of the locked keyrings titled `title`: header with
/// "Unlock all", the first [`VISIBLE_ROWS`] rows (all of them, scrolled,
/// when `show_all`) and the toggle; returns the requested action.
pub fn card(
    ui: &mut Ui,
    title: &str,
    entries: &[(CollectionId, String)],
    show_all: &mut bool,
    gates: Gates,
) -> Option<Action> {
    let mut action = None;
    accent_card(ui, theme::TERTIARY, |ui| {
        let header = egui::vec2(ui.available_width(), HEADER_HEIGHT);
        ui.allocate_ui_with_layout(header, Layout::left_to_right(Align::Center), |ui| {
            ui.label(semibold(title, 14.0));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if compact_button(ui, UNLOCK_ALL_TEXT, gates.master) {
                    let ids = entries.iter().map(|(id, _)| id.clone()).collect();
                    action = Some(Action::UnlockMany(ids));
                }
            });
        });
        ui.label(muted_text(MSG_UNLOCK_TO_INCLUDE));
        ui.add_space(6.0);
        let long = entries.len() > VISIBLE_ROWS;
        let found = if long && *show_all {
            egui::ScrollArea::vertical()
                .id_salt("kring-consolidate-locked")
                .max_height(LIST_MAX_HEIGHT)
                .auto_shrink([false, true])
                .show(ui, |ui| _rows(ui, entries, gates))
                .inner
        } else {
            _rows(ui, &entries[..entries.len().min(VISIBLE_ROWS)], gates)
        };
        action = found.or(action.take());
        if long {
            ui.add_space(4.0);
            if compact_button(ui, &toggle_text(entries.len(), *show_all), None) {
                *show_all = !*show_all;
            }
        }
    });
    action
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Digit runs compare by value, text case-insensitively.
    #[test]
    fn natural_order() {
        let mut names = vec![
            "Default keyring · Default_keyring_10",
            "StripeCLI",
            "Default keyring · Default_keyring_3",
            "default keyring · Default_keyring_2",
            "Default keyring · Default_keyring_28",
            "Default keyring · Default_keyring",
        ];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            names,
            [
                "Default keyring · Default_keyring",
                "default keyring · Default_keyring_2",
                "Default keyring · Default_keyring_3",
                "Default keyring · Default_keyring_10",
                "Default keyring · Default_keyring_28",
                "StripeCLI",
            ]
        );
        assert_eq!(natural_cmp("a2", "a10"), Ordering::Less);
        assert_eq!(natural_cmp("a010", "a9"), Ordering::Greater);
        assert_eq!(natural_cmp("a", "a"), Ordering::Equal);
        assert_eq!(natural_cmp("a", "a1"), Ordering::Less);
        assert_ne!(natural_cmp("A", "a"), Ordering::Equal, "total order");
        assert_eq!(natural_cmp("a07", "a7").reverse(), natural_cmp("a7", "a07"));
    }

    /// Builds a summary skipping `locked` keyrings (`(path, label)`) and a protected one.
    fn summary(locked: &[(&str, &str)]) -> ConsolidationSummary {
        let mut skipped: Vec<_> = locked
            .iter()
            .map(|(p, l)| (CollectionId((*p).into()), l.to_string(), SkipReason::Locked))
            .collect();
        skipped.push((
            CollectionId("/c/session".into()),
            String::new(),
            SkipReason::Protected("session"),
        ));
        ConsolidationSummary {
            target: CollectionId("/c/login".into()),
            steps: vec![],
            delete_empty: vec![],
            skipped,
            locked_count: locked.len(),
            set_default: false,
            conflict_count: 0,
            orphan_files: vec![],
            backup_needs_passphrase: false,
        }
    }

    /// Only locked keyrings, with their shown names, naturally sorted.
    #[test]
    fn locked_entries_sorted_by_shown_name() {
        let s = summary(&[("/c/d10", "Dk"), ("/c/zeta", "Zeta"), ("/c/d9", "Dk")]);
        let mut names = HashMap::new();
        names.insert(CollectionId("/c/d10".into()), "Dk · d10".to_string());
        names.insert(CollectionId("/c/d9".into()), "Dk · d9".to_string());
        let got: Vec<_> = locked_entries(&s, &names)
            .into_iter()
            .map(|(id, name)| (id.0, name))
            .collect();
        assert_eq!(
            got,
            [
                ("/c/d9".to_string(), "Dk · d9".to_string()),
                ("/c/d10".to_string(), "Dk · d10".to_string()),
                ("/c/zeta".to_string(), "Zeta".to_string()),
            ]
        );
    }

    /// With a remembered passphrase the unlock is sent at once (with the
    /// toast text); without one the dialog asks for the password.
    #[test]
    fn unlock_all_uses_remembered_or_asks() {
        let ids = vec![CollectionId("/c/a".into()), CollectionId("/c/b".into())];
        let secret = SecretValue::from_text("kept");
        let UnlockAll::Send(cmd, text) = unlock_all(Some(&secret), ids.clone()) else {
            panic!("expected a direct send");
        };
        assert_eq!(text, "Trying the remembered passphrase on 2 keyrings");
        let Command::UnlockMany {
            collections,
            password,
        } = cmd
        else {
            panic!("expected UnlockMany");
        };
        assert_eq!(collections, ids);
        assert_eq!(password.as_text(), Some("kept"));
        let UnlockAll::Ask(DialogKind::UnlockMany { collections, .. }) =
            unlock_all(None, ids.clone())
        else {
            panic!("expected the dialog");
        };
        assert_eq!(collections, ids);
    }

    /// The toggle names the total until expanded.
    #[test]
    fn toggle_texts() {
        assert_eq!(toggle_text(26, false), "Show all 26");
        assert_eq!(toggle_text(26, true), "Show fewer");
    }
}
