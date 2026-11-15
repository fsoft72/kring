//! Screenshot presets for the isolated dev session (debug builds only).
//!
//! The preset can select a keyring, expand an item, reveal its secret and
//! open a dialog without clicks. It is honoured only when the environment
//! passes `kring_core::dev_guard::violation_from` (private runtime dir and a
//! bus that is not the real user bus), so a leftover export in a normal
//! session cannot reveal a secret from the real keyring.

use kring_core::dev_guard::{IT_RUNTIME_VAR, violation_from};
use kring_core::model::CollectionId;

use crate::app_state::AppState;
use crate::views::Action;
use crate::views::collection::display_name;
use crate::views::dialogs::DialogKind;
use crate::views::item_list::displayed_items;
use crate::worker::Command;

/// Keyring (display name) to select first.
const VAR_SELECT: &str = "KRING_DEV_SELECT";
/// Index of the card (in displayed order) to expand.
const VAR_EXPAND: &str = "KRING_DEV_EXPAND";
/// Any non-empty value reveals the expanded item's secret.
const VAR_REVEAL: &str = "KRING_DEV_REVEAL";
/// Dialog to open: `new-keyring` or `unlock`.
const VAR_DIALOG: &str = "KRING_DEV_DIALOG";

/// Initial state requested for screenshots.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DevPreset {
    /// Display name of the keyring to select first.
    pub select: Option<String>,
    /// Index of the card to expand (displayed, sorted order) once items are loaded.
    pub expand: Option<usize>,
    /// Reveal the expanded item's secret.
    pub reveal: bool,
    /// Dialog to open at start: `new-keyring` or `unlock`.
    pub dialog: Option<String>,
}

/// Builds the preset from the given environment values; empty unless they
/// describe the isolated session. `get_var` reads the preset variables.
pub fn preset_from(
    it_runtime: Option<&str>,
    runtime_dir: Option<&str>,
    bus_addr: Option<&str>,
    get_var: impl Fn(&str) -> Option<String>,
) -> DevPreset {
    if violation_from(it_runtime, runtime_dir, bus_addr).is_some() {
        return DevPreset::default();
    }
    let var = |name: &str| get_var(name).filter(|v| !v.is_empty());
    DevPreset {
        select: var(VAR_SELECT),
        expand: var(VAR_EXPAND).and_then(|v| v.parse().ok()),
        reveal: var(VAR_REVEAL).is_some(),
        dialog: var(VAR_DIALOG),
    }
}

/// Reads the preset from the process environment.
pub fn from_env() -> DevPreset {
    let get = |name: &str| std::env::var(name).ok();
    let it_runtime = get(IT_RUNTIME_VAR);
    let runtime_dir = get("XDG_RUNTIME_DIR");
    let bus_addr = get("DBUS_SESSION_BUS_ADDRESS");
    preset_from(
        it_runtime.as_deref(),
        runtime_dir.as_deref(),
        bus_addr.as_deref(),
        get,
    )
}

impl DevPreset {
    /// Keyring to select first, when the preset names an existing one.
    pub fn preferred_collection(&self, state: &AppState) -> Option<CollectionId> {
        let wanted = self.select.as_deref()?;
        state
            .collections
            .iter()
            .find(|c| display_name(c) == wanted)
            .map(|c| c.id.clone())
    }

    /// Actions due now (expand, reveal, dialog); each fires once when its data exists.
    pub fn take_actions(&mut self, state: &AppState, filter: &str) -> Vec<Action> {
        let mut out = Vec::new();
        let card = self.expand.and_then(|i| {
            displayed_items(state, filter)
                .get(i)
                .map(|item| item.id.clone())
        });
        if let Some(id) = card {
            self.expand = None;
            out.push(Action::SelectItem(id.clone()));
            if self.reveal {
                out.push(Action::Send(Command::RevealSecret(id)));
            }
        }
        let locked = state.collections.iter().find(|c| c.locked);
        let kind = match (self.dialog.as_deref(), locked) {
            (Some("new-keyring"), _) => Some(DialogKind::create_collection()),
            (Some("unlock"), Some(c)) => Some(DialogKind::unlock(c.id.clone(), display_name(c))),
            _ => None,
        };
        if let Some(kind) = kind {
            self.dialog = None;
            out.push(Action::Open(kind));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::Event;
    use kring_core::model::{CollectionInfo, ItemId, ItemInfo};

    /// Private runtime dir of the isolated session.
    const RUN: &str = "/tmp/kring-dev.abc/run";
    /// Private bus address.
    const PRIVATE_BUS: &str = "unix:path=/tmp/dbus-XyZ,guid=0123";
    /// The user's real session bus.
    const REAL_BUS: &str = "unix:path=/run/user/1000/bus";

    /// Preset variables as a fake environment.
    fn vars(name: &str) -> Option<String> {
        match name {
            VAR_SELECT => Some("login".into()),
            VAR_EXPAND => Some("1".into()),
            VAR_REVEAL => Some("1".into()),
            VAR_DIALOG => Some("unlock".into()),
            _ => None,
        }
    }

    /// Inside the isolated session the variables are parsed.
    #[test]
    fn parsed_in_isolated_session() {
        let p = preset_from(Some(RUN), Some(RUN), Some(PRIVATE_BUS), vars);
        assert_eq!(
            p,
            DevPreset {
                select: Some("login".into()),
                expand: Some(1),
                reveal: true,
                dialog: Some("unlock".into()),
            }
        );
    }

    /// Mismatched or empty runtime dirs and the real bus give the empty preset.
    #[test]
    fn empty_outside_isolated_session() {
        let empty = DevPreset::default();
        let other = Some("/run/user/1000");
        assert_eq!(
            preset_from(Some(RUN), other, Some(PRIVATE_BUS), vars),
            empty
        );
        assert_eq!(
            preset_from(Some(""), Some(""), Some(PRIVATE_BUS), vars),
            empty
        );
        assert_eq!(preset_from(None, Some(RUN), Some(PRIVATE_BUS), vars), empty);
        assert_eq!(
            preset_from(Some(RUN), Some(RUN), Some(REAL_BUS), vars),
            empty
        );
        assert_eq!(preset_from(Some(RUN), Some(RUN), None, vars), empty);
    }

    /// The expand index follows the displayed (label-sorted) order, once.
    #[test]
    fn expand_uses_displayed_order() {
        let coll = CollectionId("/c/a".into());
        let mut s = AppState::default();
        s.apply(Event::Collections(vec![CollectionInfo {
            id: coll.clone(),
            label: "a".into(),
            locked: false,
            item_count: 2,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        }]));
        s.select_collection(coll.clone());
        let item = |id: &str, label: &str| ItemInfo {
            id: ItemId(id.into()),
            collection: coll.clone(),
            label: label.into(),
            attributes: Default::default(),
            locked: false,
            created: 0,
            modified: 0,
        };
        s.apply(Event::Items(
            coll.clone(),
            vec![item("/i/z", "Zeta"), item("/i/a", "alpha")],
        ));
        let mut p = DevPreset {
            expand: Some(1),
            ..DevPreset::default()
        };
        let actions = p.take_actions(&s, "");
        assert!(matches!(&actions[..], [Action::SelectItem(id)] if id.0 == "/i/z"));
        assert!(p.take_actions(&s, "").is_empty());
    }
}
