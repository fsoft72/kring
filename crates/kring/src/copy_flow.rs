//! Copying the selected secret, revealing it first when it is hidden.

use std::time::Instant;

use kring_core::model::{ItemId, SecretValue};

use crate::app_state::AppState;
use crate::clipboard::{CLIPBOARD_CLEAR_AFTER, ClipboardBackend, ClipboardGuard};
use crate::secret_display::{SecretView, secret_display};
use crate::worker::{Command, Event};

/// Error shown when copying a binary secret.
const MSG_BINARY: &str = "Binary secrets cannot be copied";

/// Clipboard copies of secrets with automatic clearing.
pub struct SecretCopier<C: ClipboardBackend> {
    clipboard: ClipboardGuard<C>,
    /// Item whose secret is copied (and hidden again) as soon as it is revealed.
    pending: Option<ItemId>,
}

impl<C: ClipboardBackend> SecretCopier<C> {
    /// Wraps a clipboard backend.
    pub fn new(backend: C) -> Self {
        Self {
            clipboard: ClipboardGuard::new(backend),
            pending: None,
        }
    }

    /// Copies the selected secret; returns the reveal command to send when it is hidden.
    pub fn request(&mut self, state: &mut AppState) -> Option<Command> {
        let id = state.selected_item.clone()?;
        if state.revealed.as_ref().is_some_and(|(r, _)| *r == id) {
            self._copy_revealed(state);
            return None;
        }
        self.pending = Some(id.clone());
        Some(Command::RevealSecret(id))
    }

    /// Forgets a copy waiting for its secret (selection changed or an error arrived).
    pub fn cancel(&mut self) {
        self.pending = None;
    }

    /// Copies a secret requested while hidden once it is revealed, then hides it again.
    pub fn finish(&mut self, state: &mut AppState) {
        let Some(id) = &self.pending else {
            return;
        };
        if !state.revealed.as_ref().is_some_and(|(r, _)| r == id) {
            return;
        }
        self.pending = None;
        self._copy_revealed(state);
        state.hide_secret();
    }

    /// Copies a secret already in memory (offline file items) and reports the outcome.
    pub fn copy_value(&mut self, secret: &SecretValue, state: &mut AppState) {
        let SecretView::Text(text) = secret_display(secret) else {
            return state.apply(Event::Error(MSG_BINARY.into()));
        };
        match self.clipboard.copy(&text, Instant::now()) {
            Ok(()) => {
                let secs = CLIPBOARD_CLEAR_AFTER.as_secs();
                state.status = format!("Copied, clipboard clears in {secs} s");
            }
            Err(e) => state.apply(Event::Error(e)),
        }
    }

    /// Clears the clipboard when due; returns true while a clear is still pending.
    pub fn tick(&mut self, now: Instant) -> bool {
        self.clipboard.tick(now);
        self.clipboard.has_pending()
    }

    /// Copies the revealed secret (text only) and reports the outcome in the state.
    fn _copy_revealed(&mut self, state: &mut AppState) {
        let Some((id, secret)) = state.revealed.take() else {
            return;
        };
        self.copy_value(&secret, state);
        state.revealed = Some((id, secret));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kring_core::model::{CollectionId, ItemInfo, SecretValue};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// In-memory clipboard sharing its content with the test.
    #[derive(Clone, Default)]
    struct Fake {
        text: Rc<RefCell<Option<String>>>,
    }

    impl ClipboardBackend for Fake {
        fn set_text(&mut self, text: &str) -> Result<(), String> {
            *self.text.borrow_mut() = Some(text.to_string());
            Ok(())
        }
        fn get_text(&mut self) -> Result<String, String> {
            self.text.borrow().clone().ok_or_else(|| "empty".into())
        }
        fn clear(&mut self) -> Result<(), String> {
            *self.text.borrow_mut() = None;
            Ok(())
        }
    }

    /// State with one selected item.
    fn state() -> AppState {
        let id = CollectionId("/c/a".into());
        let mut s = AppState::default();
        s.select_collection(id.clone());
        s.apply(Event::Items(
            id.clone(),
            vec![ItemInfo {
                id: ItemId("/c/a/1".into()),
                collection: id,
                label: "x".into(),
                attributes: Default::default(),
                locked: false,
                created: 0,
                modified: 0,
            }],
        ));
        s.select_item(ItemId("/c/a/1".into()));
        s
    }

    /// A revealed text secret is copied right away.
    #[test]
    fn copies_revealed_secret() {
        let fake = Fake::default();
        let mut c = SecretCopier::new(fake.clone());
        let mut s = state();
        s.apply(Event::Secret(
            ItemId("/c/a/1".into()),
            SecretValue::from_text("pw"),
        ));
        assert!(c.request(&mut s).is_none());
        assert_eq!(fake.text.borrow().as_deref(), Some("pw"));
        assert!(c.tick(Instant::now()));
    }

    /// A hidden secret is revealed, copied on arrival and hidden again.
    #[test]
    fn reveals_then_copies_and_hides() {
        let fake = Fake::default();
        let mut c = SecretCopier::new(fake.clone());
        let mut s = state();
        let cmd = c.request(&mut s);
        assert!(matches!(cmd, Some(Command::RevealSecret(_))));
        c.finish(&mut s);
        assert_eq!(*fake.text.borrow(), None);
        s.apply(Event::Secret(
            ItemId("/c/a/1".into()),
            SecretValue::from_text("pw"),
        ));
        c.finish(&mut s);
        assert_eq!(fake.text.borrow().as_deref(), Some("pw"));
        assert!(s.revealed.is_none());
    }

    /// An in-memory secret is copied directly; binary ones are refused.
    #[test]
    fn copies_value_directly() {
        let fake = Fake::default();
        let mut c = SecretCopier::new(fake.clone());
        let mut s = AppState::default();
        c.copy_value(&SecretValue::from_text("offline"), &mut s);
        assert_eq!(fake.text.borrow().as_deref(), Some("offline"));
        assert!(s.status.starts_with("Copied"));
        c.copy_value(&SecretValue::new(vec![0xff], "x"), &mut s);
        assert_eq!(fake.text.borrow().as_deref(), Some("offline"));
        assert_eq!(s.errors.last().map(String::as_str), Some(MSG_BINARY));
    }

    /// Binary secrets are not copied and report an error.
    #[test]
    fn binary_not_copied() {
        let fake = Fake::default();
        let mut c = SecretCopier::new(fake.clone());
        let mut s = state();
        s.apply(Event::Secret(
            ItemId("/c/a/1".into()),
            SecretValue::new(vec![0xff], "application/octet-stream"),
        ));
        assert!(c.request(&mut s).is_none());
        assert_eq!(*fake.text.borrow(), None);
        assert_eq!(s.errors.last().map(String::as_str), Some(MSG_BINARY));
    }
}
