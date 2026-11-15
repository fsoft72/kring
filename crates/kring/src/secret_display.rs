//! Decides how a secret is shown in the UI.

use kring_core::model::SecretValue;

/// How a secret is rendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretView {
    /// Printable UTF-8 text.
    Text(String),
    /// Non-text bytes, shown as lowercase hex.
    Binary { len: usize, hex: String },
}

/// Returns true for control characters that make text unfit for display.
fn _is_junk(c: char) -> bool {
    c.is_control() && !matches!(c, '\n' | '\r' | '\t')
}

/// Builds the view of a secret: text when valid UTF-8 without junk, hex otherwise.
pub fn secret_display(s: &SecretValue) -> SecretView {
    if let Some(text) = s.as_text().filter(|t| !t.chars().any(_is_junk)) {
        return SecretView::Text(text.to_string());
    }
    let hex = s.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    SecretView::Binary { len: s.len(), hex }
}

/// Returns true when the view can be copied to the clipboard.
pub fn can_copy(view: &SecretView) -> bool {
    matches!(view, SecretView::Text(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Non-UTF-8 bytes become hex and cannot be copied.
    #[test]
    fn binary_secret_shown_as_hex() {
        let v = secret_display(&SecretValue::new(
            vec![0xff, 0x00],
            "application/octet-stream",
        ));
        assert_eq!(
            v,
            SecretView::Binary {
                len: 2,
                hex: "ff00".into()
            }
        );
        assert!(!can_copy(&v));
    }

    /// Valid UTF-8 is text and copyable.
    #[test]
    fn utf8_secret_is_text() {
        let v = secret_display(&SecretValue::from_text("pass\nword\t"));
        assert_eq!(v, SecretView::Text("pass\nword\t".into()));
        assert!(can_copy(&v));
    }

    /// UTF-8 with control characters is treated as binary.
    #[test]
    fn control_chars_are_binary() {
        let v = secret_display(&SecretValue::new(vec![b'a', 0x00, b'b'], "text/plain"));
        assert_eq!(
            v,
            SecretView::Binary {
                len: 3,
                hex: "610062".into()
            }
        );
    }
}
