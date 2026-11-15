//! Detection of the Secret Service provider that owns `org.freedesktop.secrets`.

use oo7::zbus;

use crate::error::{KringError, Result};
use crate::secret_service::errors::map_zbus;

/// Well-known name of the Secret Service.
const SECRETS_NAME: &str = "org.freedesktop.secrets";
/// Object path of the Secret Service.
const SECRETS_PATH: &str = "/org/freedesktop/secrets";
/// gnome-keyring private interface used for master password operations.
const PRIVATE_IFACE: &str = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface";

/// Bus names of other secret managers that may compete with the Secret Service owner.
pub const COMPETITOR_NAMES: [&str; 4] = [
    "org.kde.kwalletd6",
    "org.kde.kwalletd5",
    "org.kde.secretservicecompat",
    "org.keepassxc.KeePassXC.MainWindow",
];

/// Kind of Secret Service provider.
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderKind {
    /// gnome-keyring-daemon.
    GnomeKeyring,
    /// KDE wallet (kwalletd or ksecretd).
    KWallet,
    /// KeePassXC.
    KeePassXC,
    /// The oo7 daemon.
    Oo7Daemon,
    /// Anything else, carrying the process name.
    Other(String),
}

/// Information about the running provider.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderInfo {
    /// Detected kind.
    pub kind: ProviderKind,
    /// Process id of the bus name owner.
    pub pid: Option<u32>,
    /// Process name (`/proc/<pid>/comm`), when readable.
    pub process_name: Option<String>,
    /// Competitor bus names that currently have an owner.
    pub competitors: Vec<String>,
    /// True when the gnome-keyring private master password interface is available.
    pub has_master_password_iface: bool,
}

impl ProviderInfo {
    /// Write and destructive operations are only allowed with gnome-keyring.
    pub fn allows_writes(&self) -> bool {
        self.kind == ProviderKind::GnomeKeyring
    }
}

/// Classifies a process name (prefix match, since `comm` is truncated to 15 chars).
pub fn classify(process_name: &str) -> ProviderKind {
    if process_name.starts_with("gnome-keyring-d") {
        return ProviderKind::GnomeKeyring;
    }
    if process_name.starts_with("kwalletd") || process_name.starts_with("ksecretd") {
        return ProviderKind::KWallet;
    }
    if process_name.starts_with("keepassxc") {
        return ProviderKind::KeePassXC;
    }
    if process_name.starts_with("oo7-daemon") {
        return ProviderKind::Oo7Daemon;
    }
    ProviderKind::Other(process_name.to_string())
}

/// Detects the provider owning `org.freedesktop.secrets` (read-only bus queries).
///
/// Returns `NoProvider` when nobody owns the name.
pub async fn detect(conn: &zbus::Connection) -> Result<ProviderInfo> {
    let dbus = zbus::Proxy::new(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    .map_err(|e| map_zbus("creating the bus proxy", e))?;
    let pid: u32 = dbus
        .call("GetConnectionUnixProcessID", &SECRETS_NAME)
        .await
        .map_err(|e| map_zbus("finding the Secret Service owner", e))?;
    let process_name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string());
    let kind = match &process_name {
        Some(name) => classify(name),
        None => ProviderKind::Other("unknown".to_string()),
    };
    let mut competitors = Vec::new();
    for name in COMPETITOR_NAMES {
        let has_owner: bool = dbus
            .call("NameHasOwner", &name)
            .await
            .map_err(|e| map_zbus("checking competing providers", e))?;
        if has_owner {
            competitors.push(name.to_string());
        }
    }
    let has_master_password_iface = match introspect(conn).await {
        Ok(xml) => xml.contains(PRIVATE_IFACE),
        Err(KringError::NoProvider) => return Err(KringError::NoProvider),
        Err(_) => kind == ProviderKind::GnomeKeyring,
    };
    Ok(ProviderInfo {
        kind,
        pid: Some(pid),
        process_name,
        competitors,
        has_master_password_iface,
    })
}

/// Introspects the Secret Service root object and returns the XML.
async fn introspect(conn: &zbus::Connection) -> Result<String> {
    let proxy = zbus::Proxy::new(
        conn,
        SECRETS_NAME,
        SECRETS_PATH,
        "org.freedesktop.DBus.Introspectable",
    )
    .await
    .map_err(|e| map_zbus("creating the introspection proxy", e))?;
    proxy
        .call("Introspect", &())
        .await
        .map_err(|e| map_zbus("introspecting the Secret Service", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a ProviderInfo of the given kind.
    fn info(kind: ProviderKind) -> ProviderInfo {
        ProviderInfo {
            kind,
            pid: None,
            process_name: None,
            competitors: vec![],
            has_master_password_iface: false,
        }
    }

    /// Known process names map to their kind, including truncated ones.
    #[test]
    fn classify_known_names() {
        assert_eq!(classify("gnome-keyring-d"), ProviderKind::GnomeKeyring);
        assert_eq!(classify("gnome-keyring-daemon"), ProviderKind::GnomeKeyring);
        assert_eq!(classify("kwalletd6"), ProviderKind::KWallet);
        assert_eq!(classify("ksecretd"), ProviderKind::KWallet);
        assert_eq!(classify("keepassxc"), ProviderKind::KeePassXC);
        assert_eq!(classify("oo7-daemon"), ProviderKind::Oo7Daemon);
    }

    /// Unknown names become `Other`.
    #[test]
    fn classify_unknown() {
        assert_eq!(classify("foo"), ProviderKind::Other("foo".into()));
    }

    /// Only gnome-keyring allows writes.
    #[test]
    fn writes_only_for_gnome_keyring() {
        assert!(info(ProviderKind::GnomeKeyring).allows_writes());
        assert!(!info(ProviderKind::KWallet).allows_writes());
        assert!(!info(ProviderKind::Other("x".into())).allows_writes());
    }
}
