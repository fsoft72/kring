//! Clipboard access with automatic clearing of copied secrets.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// Delay after which a copied secret is removed from the clipboard.
pub const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

/// Minimal clipboard operations needed by the guard.
pub trait ClipboardBackend {
    /// Replaces the clipboard text.
    fn set_text(&mut self, text: &str) -> Result<(), String>;
    /// Reads the clipboard text.
    fn get_text(&mut self) -> Result<String, String>;
    /// Empties the clipboard.
    fn clear(&mut self) -> Result<(), String>;
}

/// System clipboard backed by `arboard`, created on first use.
#[derive(Default)]
pub struct ArboardClipboard {
    inner: Option<arboard::Clipboard>,
}

impl ArboardClipboard {
    /// Creates an unconnected clipboard handle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the connection, creating it when missing (fails without a display).
    fn _conn(&mut self) -> Result<&mut arboard::Clipboard, String> {
        if self.inner.is_none() {
            let cb =
                arboard::Clipboard::new().map_err(|e| format!("clipboard unavailable: {e}"))?;
            self.inner = Some(cb);
        }
        self.inner
            .as_mut()
            .ok_or_else(|| "clipboard unavailable".to_string())
    }
}

impl ClipboardBackend for ArboardClipboard {
    /// Sets the clipboard text.
    fn set_text(&mut self, text: &str) -> Result<(), String> {
        self._conn()?.set_text(text).map_err(|e| e.to_string())
    }

    /// Reads the clipboard text.
    fn get_text(&mut self) -> Result<String, String> {
        self._conn()?.get_text().map_err(|e| e.to_string())
    }

    /// Clears the clipboard.
    fn clear(&mut self) -> Result<(), String> {
        self._conn()?.clear().map_err(|e| e.to_string())
    }
}

/// Copies text and clears it after a delay, unless the user copied something else.
pub struct ClipboardGuard<C> {
    backend: C,
    pending: Option<(Zeroizing<String>, Instant)>,
}

impl<C: ClipboardBackend> ClipboardGuard<C> {
    /// Wraps a clipboard backend.
    pub fn new(backend: C) -> Self {
        Self {
            backend,
            pending: None,
        }
    }

    /// Copies `text` and schedules its removal at `now + CLIPBOARD_CLEAR_AFTER`.
    pub fn copy(&mut self, text: &str, now: Instant) -> Result<(), String> {
        self.backend.set_text(text)?;
        self.pending = Some((Zeroizing::new(text.to_string()), now));
        Ok(())
    }

    /// Clears the clipboard when the delay elapsed and it still holds the copied text.
    pub fn tick(&mut self, now: Instant) {
        let Some((_, copied_at)) = &self.pending else {
            return;
        };
        if now.saturating_duration_since(*copied_at) < CLIPBOARD_CLEAR_AFTER {
            return;
        }
        let Some((text, _)) = self.pending.take() else {
            return;
        };
        if let Ok(current) = self.backend.get_text().map(Zeroizing::new)
            && *current == *text
        {
            // Nothing useful to do if clearing fails; the text stays until overwritten.
            let _ = self.backend.clear();
        }
    }

    /// Returns true while a copied text is waiting to be cleared.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// In-memory clipboard sharing its content with the test.
    #[derive(Clone, Default)]
    struct Fake {
        text: Rc<RefCell<Option<String>>>,
        fail_get: bool,
    }

    impl ClipboardBackend for Fake {
        fn set_text(&mut self, text: &str) -> Result<(), String> {
            *self.text.borrow_mut() = Some(text.to_string());
            Ok(())
        }
        fn get_text(&mut self) -> Result<String, String> {
            if self.fail_get {
                return Err("boom".into());
            }
            self.text.borrow().clone().ok_or_else(|| "empty".into())
        }
        fn clear(&mut self) -> Result<(), String> {
            *self.text.borrow_mut() = None;
            Ok(())
        }
    }

    /// The clipboard is cleared exactly at 30 seconds.
    #[test]
    fn clears_after_30s() {
        let fake = Fake::default();
        let mut g = ClipboardGuard::new(fake.clone());
        let t0 = Instant::now();
        g.copy("secret", t0).unwrap();
        g.tick(t0 + Duration::from_secs(29));
        assert_eq!(fake.text.borrow().as_deref(), Some("secret"));
        assert!(g.has_pending());
        g.tick(t0 + Duration::from_secs(30));
        assert_eq!(*fake.text.borrow(), None);
        assert!(!g.has_pending());
    }

    /// A clipboard changed by the user is left alone.
    #[test]
    fn does_not_clear_if_user_copied_something_else() {
        let fake = Fake::default();
        let mut g = ClipboardGuard::new(fake.clone());
        let t0 = Instant::now();
        g.copy("secret", t0).unwrap();
        *fake.text.borrow_mut() = Some("other".into());
        g.tick(t0 + Duration::from_secs(31));
        assert_eq!(fake.text.borrow().as_deref(), Some("other"));
        assert!(!g.has_pending());
    }

    /// A read failure drops the pending text without clearing.
    #[test]
    fn get_error_drops_pending() {
        let fake = Fake {
            fail_get: true,
            ..Fake::default()
        };
        let mut g = ClipboardGuard::new(fake.clone());
        let t0 = Instant::now();
        g.copy("secret", t0).unwrap();
        g.tick(t0 + Duration::from_secs(40));
        assert_eq!(fake.text.borrow().as_deref(), Some("secret"));
        assert!(!g.has_pending());
    }
}
