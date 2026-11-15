//! Input validation for user-edited values.

use crate::error::{KringError, Result};
use crate::model::{Attributes, SecretValue};

/// Checks that a collection label is not blank.
pub fn collection_label(label: &str) -> Result<()> {
    if label.trim().is_empty() {
        return Err(KringError::InvalidInput("label must not be empty".into()));
    }
    Ok(())
}

/// Builds attributes from edited rows: keys are trimmed, must be non-empty and unique.
/// Values are kept as-is.
pub fn attributes(rows: &[(String, String)]) -> Result<Attributes> {
    let mut out = Attributes::new();
    for (key, value) in rows {
        let key = key.trim();
        if key.is_empty() {
            return Err(KringError::InvalidInput(
                "attribute key must not be empty".into(),
            ));
        }
        if out.insert(key.to_string(), value.clone()).is_some() {
            return Err(KringError::InvalidInput(format!(
                "duplicate attribute key: {key}"
            )));
        }
    }
    Ok(out)
}

/// Checks a new password and its confirmation: non-empty and equal.
pub fn new_password(new: &SecretValue, confirm: &SecretValue) -> Result<()> {
    if new.is_empty() {
        return Err(KringError::InvalidInput(
            "password must not be empty".into(),
        ));
    }
    if new.as_bytes() != confirm.as_bytes() {
        return Err(KringError::InvalidInput(
            "password and confirmation do not match".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Blank labels are rejected.
    #[test]
    fn rejects_empty_label() {
        assert!(matches!(
            collection_label("  "),
            Err(KringError::InvalidInput(_))
        ));
        assert!(collection_label(" ok ").is_ok());
    }

    /// Empty and duplicate keys are rejected; keys are trimmed.
    #[test]
    fn rejects_empty_and_duplicate_attribute_keys() {
        assert!(attributes(&[("".into(), "x".into())]).is_err());
        assert!(attributes(&[("a".into(), "1".into()), ("a".into(), "2".into())]).is_err());
        assert!(attributes(&[("a".into(), "1".into()), (" a ".into(), "2".into())]).is_err());
        let ok = attributes(&[(" a ".into(), " 1".into())]).unwrap();
        assert_eq!(ok.get("a").unwrap(), " 1");
    }

    /// Mismatched and empty passwords are rejected.
    #[test]
    fn rejects_password_mismatch_and_empty() {
        assert!(new_password(&SecretValue::from_text("a"), &SecretValue::from_text("b")).is_err());
        assert!(new_password(&SecretValue::from_text(""), &SecretValue::from_text("")).is_err());
        assert!(new_password(&SecretValue::from_text("a"), &SecretValue::from_text("a")).is_ok());
    }
}
