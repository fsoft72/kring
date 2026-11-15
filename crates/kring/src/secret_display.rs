//! Decides how a secret is shown in the UI.

use std::fmt;

use kring_core::model::SecretValue;
use zeroize::Zeroizing;

/// Lowercase hex digits.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// How a secret is rendered. Contents are zeroized on drop and redacted in `Debug`.
pub enum SecretView {
    /// Printable UTF-8 text.
    Text(Zeroizing<String>),
    /// Non-text bytes, shown as lowercase hex.
    Binary { len: usize, hex: Zeroizing<String> },
}

impl fmt::Debug for SecretView {
    /// Prints only the length, never the content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(t) => write!(f, "Text(<redacted, {} bytes>)", t.len()),
            Self::Binary { len, .. } => {
                write!(f, "Binary {{ len: {len}, hex: <redacted> }}")
            }
        }
    }
}

/// Returns true for control characters that make text unfit for display.
fn _is_junk(c: char) -> bool {
    c.is_control() && !matches!(c, '\n' | '\r' | '\t')
}

/// Builds the view of a secret: text when valid UTF-8 without junk, hex otherwise.
pub fn secret_display(s: &SecretValue) -> SecretView {
    if let Some(text) = s.as_text().filter(|t| !t.chars().any(_is_junk)) {
        return SecretView::Text(Zeroizing::new(String::from(text)));
    }
    let mut hex = Zeroizing::new(String::with_capacity(s.len() * 2));
    for b in s.as_bytes() {
        hex.push(HEX_DIGITS[usize::from(b >> 4)] as char);
        hex.push(HEX_DIGITS[usize::from(b & 0x0f)] as char);
    }
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
        assert!(matches!(&v, SecretView::Binary { len: 2, hex } if hex.as_str() == "ff00"));
        assert!(!can_copy(&v));
    }

    /// Valid UTF-8 is text and copyable.
    #[test]
    fn utf8_secret_is_text() {
        let v = secret_display(&SecretValue::from_text("pass\nword\t"));
        assert!(matches!(&v, SecretView::Text(t) if t.as_str() == "pass\nword\t"));
        assert!(can_copy(&v));
    }

    /// UTF-8 with control characters is treated as binary.
    #[test]
    fn control_chars_are_binary() {
        let v = secret_display(&SecretValue::new(vec![b'a', 0x00, b'b'], "text/plain"));
        assert!(matches!(&v, SecretView::Binary { len: 3, hex } if hex.as_str() == "610062"));
    }

    /// Debug output contains neither the secret nor its hex.
    #[test]
    fn secret_view_debug_is_redacted() {
        let text = secret_display(&SecretValue::from_text("hunter2"));
        let out = format!("{text:?}");
        assert!(!out.contains("hunter2") && !out.contains("68756e74657232"));
        let bin = secret_display(&SecretValue::new(vec![0xde, 0xad], "x"));
        let out = format!("{bin:?}");
        assert!(!out.contains("dead"));
    }
}
