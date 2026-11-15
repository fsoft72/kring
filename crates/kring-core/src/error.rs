//! Error type shared by all kring-core operations.

use std::path::PathBuf;

/// Errors returned by kring-core.
#[derive(Debug, thiserror::Error)]
pub enum KringError {
    /// A D-Bus call failed.
    #[error("D-Bus error while {context}: {message}")]
    Dbus { context: String, message: String },
    /// The collection or item is locked.
    #[error("locked: {0}")]
    Locked(String),
    /// The requested object does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The operation is not supported by the current provider.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// User input failed validation.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// A filesystem operation failed.
    #[error("I/O error on {}: {message}", path.display())]
    Io { path: PathBuf, message: String },
    /// A passphrase is needed to continue.
    #[error("a passphrase is required")]
    PassphraseRequired,
    /// No Secret Service provider is available.
    #[error("no Secret Service provider available")]
    NoProvider,
}

/// Result alias using [`KringError`].
pub type Result<T> = std::result::Result<T, KringError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Error messages include their context.
    #[test]
    fn display_includes_context() {
        let e = KringError::Dbus { context: "listing".into(), message: "boom".into() };
        assert_eq!(e.to_string(), "D-Bus error while listing: boom");
        let e = KringError::Io { path: "/x/y".into(), message: "denied".into() };
        assert_eq!(e.to_string(), "I/O error on /x/y: denied");
    }
}
