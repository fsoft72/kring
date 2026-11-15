//! Worker handlers for KWallet wallets (`*.kwl` files read offline).
//!
//! Wallets are addressed by name only (`<name>.kwl` with `<name>.salt` and
//! the optional `<name>_attributes.json` inside [`WorkerConfig::kwallet_dir`]);
//! the path always comes from a fresh scan, never from the UI. The wallet
//! password is only used to decrypt and is never echoed in an event: a wrong
//! one is a plain [`Event::Error`] (`Wrong wallet password`).
//!
//! Secrets leave the worker only in [`Event::WalletItems`]. Imports reuse the
//! Plan 3 path ([`worker_transfer::plan_wallet_import`]): applied directly
//! without conflicts, previewed otherwise, with the offline side of a
//! conflict backed by the wallet items (`offline_index` is the position in
//! [`Event::WalletItems`]).

use std::path::{Path, PathBuf};

use kring_core::kwallet_file::{
    EntryValue, WalletHeader, open_wallet, read_attributes, read_header, to_incoming,
};
use kring_core::model::{Attributes, CollectionId, CollectionInfo, SCHEMA_ATTRIBUTE, SecretValue};
use kring_core::provider::ProviderInfo;
use kring_core::transfer::plan::{Incoming, TransferSource};
use kring_core::{KringError, MasterPasswordStore, Result, SecretStore};

use crate::worker::{Command, Emitter, Event, MSG_NO_PROVIDER, WorkerConfig, gate, refresh};
use crate::worker_transfer::{self, PlanState};

/// Notice after a migration while a KWallet daemon still owns its bus names.
pub(crate) const MSG_KWALLET_COMPETITOR: &str = "KWallet is still running and may claim org.freedesktop.secrets; disable KWallet's Secret Service integration after migrating";
/// Message for a wallet name that could escape the KWallet directory.
const MSG_BAD_NAME: &str = "Invalid wallet name";
/// Extension of wallet files.
const WALLET_EXTENSION: &str = "kwl";
/// Extension of the PBKDF2 salt file next to a wallet.
const SALT_EXTENSION: &str = "salt";
/// Suffix of the compat layer metadata file (`<name>_attributes.json`).
const ATTRIBUTES_SUFFIX: &str = "_attributes.json";
/// Bytes read to recognise a wallet header (magic + 4 version bytes).
const HEADER_READ_LEN: u64 = 16;
/// Parts of competitor bus names that belong to KWallet.
const KWALLET_COMPETITOR_PARTS: [&str; 2] = ["kwalletd", "secretservicecompat"];
/// Schema the mapping gives native entries.
const NATIVE_SCHEMA: &str = "org.kde.KWallet.Entry";
/// Attribute with the wallet folder of a native entry.
const ATTR_FOLDER: &str = "kwallet-folder";
/// Attribute with the wallet key of a native entry.
const ATTR_KEY: &str = "kwallet-key";

/// A wallet file of the KWallet directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletInfo {
    /// Wallet name (`<name>.kwl`).
    pub name: String,
    /// Path of the `.kwl` file.
    pub path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// Modification time, unix seconds (0 when unknown).
    pub modified: u64,
    /// Header, `None` when the file is not a KWallet wallet.
    pub header: Option<WalletHeader>,
    /// True when `<name>_attributes.json` (app attributes) exists.
    pub has_attributes: bool,
    /// Collection labelled like the wallet (where the kwalletd6 shim looks
    /// for it), the suggested import target; `None` when there is none.
    pub suggested_target: Option<CollectionId>,
}

/// Type of a wallet entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletEntryKind {
    /// A password (text).
    Password,
    /// A string map (shown as JSON text).
    Map,
    /// Raw bytes.
    Stream,
}

/// One wallet entry as shown to the UI, with its secret (display only).
#[derive(Clone, Debug)]
pub struct OfflineItemView {
    /// Label the import gives the item.
    pub label: String,
    /// Attributes the import gives the item.
    pub attributes: Attributes,
    /// Wallet folder.
    pub folder: String,
    /// Entry key inside the folder.
    pub key: String,
    /// Entry type.
    pub kind: WalletEntryKind,
    /// True when the attributes came from the Secret Service compat layer
    /// (an app entry), false for a native KWallet entry.
    pub app_entry: bool,
    /// Modification time, unix seconds (0 when unknown).
    pub modified: u64,
    /// The secret: password text, map as JSON text, or stream bytes.
    pub secret: SecretValue,
}

/// A decrypted wallet: the transfer items and their views, in the same order
/// (one view per item, so a plan's incoming index is a view index).
pub(crate) struct OpenedWallet {
    /// Items for the transfer planner.
    pub(crate) incoming: Vec<Incoming>,
    /// The same items for the UI.
    pub(crate) views: Vec<OfflineItemView>,
}

/// Returns true for commands handled by this module.
pub(crate) fn is_wallet(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::ScanWallets
            | Command::OpenWallet { .. }
            | Command::PlanWalletImport { .. }
            | Command::CreateWalletCollection { .. }
    )
}

/// Handles one wallet command, reporting failures as [`Event::Error`].
pub(crate) async fn handle<S, N>(
    out: &Emitter<N>,
    store: Option<&S>,
    provider: Option<&ProviderInfo>,
    config: &WorkerConfig,
    plans: &mut PlanState,
    cmd: Command,
) where
    S: SecretStore + MasterPasswordStore,
    N: Fn(),
{
    match cmd {
        Command::ScanWallets => {
            if let Err(e) = emit_wallets(out, store, config).await {
                out.error(message(&e));
            }
        }
        Command::OpenWallet { name, password } => match read_wallet(config, &name, &password) {
            Ok(wallet) => out.emit(Event::WalletItems {
                name,
                items: wallet.views,
            }),
            Err(e) => out.error(message(&e)),
        },
        Command::PlanWalletImport {
            name,
            password,
            target,
        } => {
            plans.clear();
            let Some(store) = store else {
                return out.error(MSG_NO_PROVIDER);
            };
            let wallet = match read_wallet(config, &name, &password) {
                Ok(wallet) => wallet,
                Err(e) => return out.error(message(&e)),
            };
            worker_transfer::plan_wallet_import(
                out,
                store,
                provider,
                config,
                plans,
                &target,
                wallet.incoming,
            )
            .await;
        }
        Command::CreateWalletCollection { .. } => {
            if !gate(out, provider, &cmd) {
                return;
            }
            let Some(store) = store else {
                return out.error(MSG_NO_PROVIDER);
            };
            let Command::CreateWalletCollection { name, password } = &cmd else {
                return;
            };
            if let Err(e) = create_collection(out, store, config, name, password).await {
                out.error(message(&e));
            }
        }
        _ => out.error("Command sent to the wallet path"),
    }
}

/// Returns the text of a wallet error: `InvalidInput` messages as they are
/// (e.g. `Wrong wallet password`), anything else with its kind.
fn message(e: &KringError) -> String {
    match e {
        KringError::InvalidInput(m) => m.clone(),
        other => other.to_string(),
    }
}

/// Builds an `InvalidInput` error.
fn invalid(message: impl Into<String>) -> KringError {
    KringError::InvalidInput(message.into())
}

/// Emits [`Event::Notice`] with [`MSG_KWALLET_COMPETITOR`] when a KWallet
/// daemon is among the provider's competitors.
pub(crate) fn competitor_notice<N: Fn()>(out: &Emitter<N>, provider: Option<&ProviderInfo>) {
    let Some(provider) = provider else {
        return;
    };
    let kwallet = provider
        .competitors
        .iter()
        .any(|c| KWALLET_COMPETITOR_PARTS.iter().any(|part| c.contains(part)));
    if !kwallet {
        return;
    }
    out.emit(Event::Notice(MSG_KWALLET_COMPETITOR.to_string()));
}

/// Scans the wallets, adds the suggested targets and emits [`Event::Wallets`].
///
/// Without a store there are no suggestions; a store that cannot list its
/// collections is reported as an error after the list (the scan still counts).
async fn emit_wallets<S: SecretStore, N: Fn()>(
    out: &Emitter<N>,
    store: Option<&S>,
    config: &WorkerConfig,
) -> Result<()> {
    let mut wallets = scan_wallets(&config.kwallet_dir)?;
    let collections = match store {
        Some(store) => store.list_collections().await,
        None => Ok(Vec::new()),
    };
    if let Ok(list) = &collections {
        for wallet in &mut wallets {
            wallet.suggested_target = suggested_target(list, &wallet.name);
        }
    }
    out.emit(Event::Wallets(wallets));
    if let Err(e) = collections {
        out.error(format!("Cannot suggest import targets: {e}"));
    }
    Ok(())
}

/// Returns the first collection labelled exactly `name`.
fn suggested_target(collections: &[CollectionInfo], name: &str) -> Option<CollectionId> {
    collections
        .iter()
        .find(|c| c.label == name)
        .map(|c| c.id.clone())
}

/// Lists the regular `*.kwl` files of `dir`, sorted by name; a missing
/// directory is an empty list.
pub(crate) fn scan_wallets(dir: &Path) -> Result<Vec<WalletInfo>> {
    let io = |e: std::io::Error| KringError::Io {
        path: dir.to_path_buf(),
        message: e.to_string(),
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io(e)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.map_err(io)?.path();
        if path.extension().and_then(|e| e.to_str()) != Some(WALLET_EXTENSION) {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_file() {
            continue;
        }
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        out.push(WalletInfo {
            name: name.to_string(),
            header: _read_file_header(&path),
            has_attributes: dir.join(format!("{name}{ATTRIBUTES_SUFFIX}")).is_file(),
            path,
            size: meta.len(),
            modified,
            suggested_target: None,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Reads the header of a wallet file; `None` when unreadable or not a wallet.
fn _read_file_header(path: &Path) -> Option<WalletHeader> {
    use std::io::Read;
    let mut head = Vec::new();
    let file = std::fs::File::open(path).ok()?;
    file.take(HEADER_READ_LEN).read_to_end(&mut head).ok()?;
    read_header(&head).ok()
}

/// Resolves a wallet name to its scanned entry in the KWallet directory.
///
/// The name must be non-empty, contain no `/` and not be `.` or `..`; the
/// entry must be the regular (non-symlink) file `<kwallet_dir>/<name>.kwl`.
pub(crate) fn resolve_wallet(config: &WorkerConfig, name: &str) -> Result<WalletInfo> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(invalid(MSG_BAD_NAME));
    }
    let path = config
        .kwallet_dir
        .join(format!("{name}.{WALLET_EXTENSION}"));
    scan_wallets(&config.kwallet_dir)?
        .into_iter()
        .find(|w| w.name == name && w.path == path)
        .ok_or_else(|| invalid(format!("No wallet named '{name}'")))
}

/// Reads a file next to a wallet; a missing file is empty when `optional`.
fn _read_beside(path: &Path, optional: bool) -> Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(e) if optional && e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(KringError::Io {
            path: path.to_path_buf(),
            message: e.to_string(),
        }),
    }
}

/// Resolves and decrypts wallet `name` and maps its entries.
///
/// A wrong password is `InvalidInput("Wrong wallet password")`, an
/// unsupported format `InvalidInput` naming it; nothing is returned then.
pub(crate) fn read_wallet(
    config: &WorkerConfig,
    name: &str,
    password: &SecretValue,
) -> Result<OpenedWallet> {
    let info = resolve_wallet(config, name)?;
    let dir = &config.kwallet_dir;
    let kwl = _read_beside(&info.path, false)?;
    let salt = _read_beside(&dir.join(format!("{name}.{SALT_EXTENSION}")), true)?;
    let json = _read_beside(&dir.join(format!("{name}{ATTRIBUTES_SUFFIX}")), true)?;
    let entries = open_wallet(&kwl, &salt, password)?;
    let meta = read_attributes(&json)?;
    let incoming = to_incoming(&entries, &meta);
    let mut views = Vec::with_capacity(incoming.len());
    for item in &incoming {
        let TransferSource::Offline(index) = item.source else {
            return Err(invalid("Wallet item without an entry"));
        };
        let entry = entries.get(index);
        let Some((entry, kind)) = entry.and_then(|e| Some((e, _kind(&e.value)?))) else {
            return Err(invalid("Wallet item without an entry"));
        };
        views.push(OfflineItemView {
            label: item.label.clone(),
            attributes: item.attributes.clone(),
            folder: entry.folder.clone(),
            key: entry.key.clone(),
            kind,
            app_entry: !_is_native(&item.attributes, &entry.folder, &entry.key),
            modified: item.modified,
            secret: item.secret.clone(),
        });
    }
    Ok(OpenedWallet { incoming, views })
}

/// Returns the kind of a mapped value; `None` for unknown types (never mapped).
fn _kind(value: &EntryValue) -> Option<WalletEntryKind> {
    match value {
        EntryValue::Password(_) => Some(WalletEntryKind::Password),
        EntryValue::Map(_) => Some(WalletEntryKind::Map),
        EntryValue::Stream(_) => Some(WalletEntryKind::Stream),
        EntryValue::Unknown(_) => None,
    }
}

/// True when `attributes` are the native mapping of `<folder>/<key>`.
fn _is_native(attributes: &Attributes, folder: &str, key: &str) -> bool {
    attributes.get(SCHEMA_ATTRIBUTE).map(String::as_str) == Some(NATIVE_SCHEMA)
        && attributes.get(ATTR_FOLDER).map(String::as_str) == Some(folder)
        && attributes.get(ATTR_KEY).map(String::as_str) == Some(key)
}

/// Creates the keyring labelled like wallet `name`, re-lists collections and
/// wallets and reports `Done`.
async fn create_collection<S, N>(
    out: &Emitter<N>,
    store: &S,
    config: &WorkerConfig,
    name: &str,
    password: &SecretValue,
) -> Result<()>
where
    S: SecretStore + MasterPasswordStore,
    N: Fn(),
{
    let info = resolve_wallet(config, name)?;
    let collections = store.list_collections().await?;
    if collections.iter().any(|c| c.label == info.name) {
        return Err(invalid(format!(
            "A keyring named '{}' already exists",
            info.name
        )));
    }
    store.create_with_password(&info.name, password).await?;
    refresh(out, store).await;
    emit_wallets(out, Some(store), config).await?;
    out.emit(Event::Done(format!("Keyring '{}' created", info.name)));
    Ok(())
}

#[cfg(test)]
mod tests;
