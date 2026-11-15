//! Filesystem locations used by kring and gnome-keyring.

use std::ffi::OsString;
use std::path::PathBuf;

/// Environment variable naming the ssh-agent socket.
const SSH_AUTH_SOCK_VAR: &str = "SSH_AUTH_SOCK";
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

/// Resolves the SSH key directory `$HOME/.ssh` from an explicit HOME (pure,
/// testable); `None` when HOME is unset or empty (no directory to scan).
pub fn ssh_dir_from(home: Option<&str>) -> Option<PathBuf> {
    let home = home.filter(|v| !v.is_empty())?;
    Some(PathBuf::from(home).join(".ssh"))
}

/// Returns the user's SSH key directory, `$HOME/.ssh`; `None` without HOME.
pub fn ssh_dir() -> Option<PathBuf> {
    ssh_dir_from(std::env::var("HOME").ok().as_deref())
}

/// Resolves the ssh-agent socket from an `SSH_AUTH_SOCK` value; empty means unset.
pub fn agent_sock_from(value: Option<OsString>) -> Option<PathBuf> {
    value.filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Returns the ssh-agent socket named by `SSH_AUTH_SOCK`, if set.
///
/// Read once at startup by the application; library code never calls it.
pub fn agent_sock() -> Option<PathBuf> {
    agent_sock_from(std::env::var_os(SSH_AUTH_SOCK_VAR))
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

    /// The SSH directory is `$HOME/.ssh`; an unset or empty HOME gives none.
    #[test]
    fn ssh_dir_in_home() {
        assert_eq!(
            ssh_dir_from(Some("/home/u")),
            Some(PathBuf::from("/home/u/.ssh"))
        );
        assert_eq!(ssh_dir_from(Some("")), None, "empty HOME: no SSH dir");
        assert_eq!(ssh_dir_from(None), None, "unset HOME: no SSH dir");
    }

    /// The agent socket is taken from a non-empty `SSH_AUTH_SOCK` value only.
    #[test]
    fn agent_sock_from_env_value() {
        assert_eq!(
            agent_sock_from(Some("/run/agent.sock".into())),
            Some(PathBuf::from("/run/agent.sock"))
        );
        assert_eq!(agent_sock_from(Some("".into())), None);
        assert_eq!(agent_sock_from(None), None);
    }

    /// Falls back to HOME/.local/share, also for empty XDG.
    #[test]
    fn falls_back_to_home() {
        let expected = PathBuf::from("/home/u/.local/share");
        assert_eq!(data_home_from(None, Some("/home/u")), expected);
        assert_eq!(data_home_from(Some(""), Some("/home/u")), expected);
    }
}
