//! Filesystem locations used by kring and gnome-keyring.

use std::path::PathBuf;

/// Directory of the KWallet wallets inside the data home (`ksecretd`, `kwalletd`).
const KWALLET_DIR_NAME: &str = "kwalletd";

/// Resolves the XDG data home from explicit values (pure, testable).
///
/// Empty values are treated as unset, as the XDG spec requires.
pub fn data_home_from(xdg: Option<&str>, home: Option<&str>) -> PathBuf {
    if let Some(xdg) = xdg.filter(|v| !v.is_empty()) {
        return PathBuf::from(xdg);
    }
    PathBuf::from(home.filter(|v| !v.is_empty()).unwrap_or("/")).join(".local/share")
}

/// Returns `XDG_DATA_HOME` or `$HOME/.local/share`.
pub fn data_home() -> PathBuf {
    data_home_from(
        std::env::var("XDG_DATA_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// Returns the gnome-keyring keyrings directory.
pub fn keyrings_dir() -> PathBuf {
    data_home().join("keyrings")
}

/// Resolves the KWallet wallets directory from explicit values (pure, testable).
pub fn kwallet_dir_from(xdg: Option<&str>, home: Option<&str>) -> PathBuf {
    data_home_from(xdg, home).join(KWALLET_DIR_NAME)
}

/// Returns the KWallet wallets directory, `$XDG_DATA_HOME/kwalletd`.
pub fn kwallet_dir() -> PathBuf {
    data_home().join(KWALLET_DIR_NAME)
}

/// Returns the kring backups root directory.
pub fn backups_dir() -> PathBuf {
    data_home().join("kring").join("backups")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// XDG_DATA_HOME wins over HOME.
    #[test]
    fn xdg_takes_precedence() {
        assert_eq!(
            data_home_from(Some("/x/data"), Some("/home/u")),
            PathBuf::from("/x/data")
        );
    }

    /// The KWallet directory is `kwalletd` inside the data home, with the same fallbacks.
    #[test]
    fn kwallet_dir_in_data_home() {
        assert_eq!(
            kwallet_dir_from(Some("/x/data"), Some("/home/u")),
            PathBuf::from("/x/data/kwalletd")
        );
        assert_eq!(
            kwallet_dir_from(Some(""), Some("/home/u")),
            PathBuf::from("/home/u/.local/share/kwalletd")
        );
    }

    /// Falls back to HOME/.local/share, also for empty XDG.
    #[test]
    fn falls_back_to_home() {
        let expected = PathBuf::from("/home/u/.local/share");
        assert_eq!(data_home_from(None, Some("/home/u")), expected);
        assert_eq!(data_home_from(Some(""), Some("/home/u")), expected);
    }
}
