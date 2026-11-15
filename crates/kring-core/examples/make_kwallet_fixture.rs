//! Generates the KWallet test fixtures with a real KWallet daemon.
//!
//! Dev only: run through `scripts/kwallet-session.sh`, which starts a private
//! `ksecretd` (the daemon that owns `.kwl` files in KDE Frameworks 6) on a
//! private bus with a temp `XDG_DATA_HOME`. It refuses to run outside that
//! session (`kring_core::dev_guard`), so the user's real wallet and daemon are
//! never touched.
//!
//! Steps (see `tests/fixtures/kwallet/README.md`):
//! 1. write a random 56-byte `fixture.salt` and derive the wallet key like
//!    `pam_kwallet` / `KWallet::Backend::setPassword` do
//!    (PBKDF2-HMAC-SHA512, 50000 iterations, 56 bytes);
//! 2. `pamOpen` creates the wallet `fixture` with that key, without any dialog;
//! 3. native entries through the `org.kde.KWallet` API (`writePassword`,
//!    `writeMap`, `writeEntry`);
//! 4. items with attributes through the daemon's Secret Service compat layer,
//!    which records them in `fixture_attributes.json`;
//! 5. close the wallet (forces a save) and copy the 3 files into
//!    `tests/fixtures/kwallet`.

use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use kring_core::dev_guard::{IT_RUNTIME_VAR, data_home_violation, private_session_violation};
use kring_core::model::{Attributes, CollectionId, NewItem, SecretValue};
use kring_core::secret_service::SecretServiceBackend;
use kring_core::{KringError, SecretStore, paths};
use oo7::zbus;
use sha2::Sha512;
use zeroize::Zeroizing;

/// Name of the generated wallet (file stem of the fixtures).
const WALLET: &str = "fixture";
/// Password of the generated wallet.
const PASSWORD: &str = "fixture-pw";
/// Application id passed to the KWallet API.
const APP_ID: &str = "kring-fixture";
/// Bus name of the private KWallet daemon.
const KSECRETD_NAME: &str = "org.kde.ksecretd";
/// Object path of the KWallet API on `ksecretd`.
const KSECRETD_PATH: &str = "/ksecretd";
/// KWallet D-Bus interface (src/api/KWallet/org.kde.KWallet.xml).
const KWALLET_IFACE: &str = "org.kde.KWallet";
/// Secret Service collection the compat layer exposes for the wallet.
const COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/fixture";
/// PBKDF2 iterations (`PBKDF2_SHA512_ITERATIONS` in kwalletbackend.h).
const PBKDF2_ITERATIONS: u32 = 50_000;
/// Derived key length (`PBKDF2_SHA512_KEYSIZE` in kwalletbackend.h).
const KEY_LEN: usize = 56;
/// Salt length (`PBKDF2_SHA512_SALTSIZE` in kwalletbackend.h).
const SALT_LEN: usize = 56;
/// `KWallet::Wallet::EntryType::Stream`.
const ENTRY_TYPE_STREAM: i32 = 2;
/// Folder written by the compat layer for labels without a `/`.
const COMPAT_DEFAULT_FOLDER: &str = "Secret Service";
/// Native password entry: folder, key, value.
const NATIVE_PASSWORD: (&str, &str, &str) = ("Passwords", "site", "fixture-secret-1");
/// Native map entry: folder and key.
const NATIVE_MAP: (&str, &str) = ("Maps", "form");
/// Native map entry content.
const NATIVE_MAP_VALUE: [(&str, &str); 2] = [("user", "alice"), ("pass", "fixture-secret-2")];
/// Native stream entry: folder and key.
const NATIVE_STREAM: (&str, &str) = ("Streams", "blob");
/// Native stream entry content.
const NATIVE_STREAM_VALUE: [u8; 3] = [0x00, 0xff, 0x10];
/// Compat map item: label and content (written by Qt's `QDataStream`).
const COMPAT_MAP: (&str, [(&str, &str); 2]) = (
    "Fixture map",
    [("user", "dave"), ("pass", "fixture-secret-6")],
);
/// Source of the random salt.
const RANDOM_SOURCE: &str = "/dev/urandom";
/// How long to wait for the daemon to open or close the wallet.
const STATE_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for the whole run.
const RUN_TIMEOUT: Duration = Duration::from_secs(120);

/// A Secret Service item created through the compat layer.
struct CompatItem {
    /// fdo label (`<folder>/<key>` selects a folder).
    label: &'static str,
    /// fdo attributes.
    attributes: &'static [(&'static str, &'static str)],
    /// Text secret.
    secret: String,
}

/// Builds the compat items: a plain label, a duplicate label (the daemon
/// appends `__0_` to the entry key), a label with a folder and a map.
fn _compat_items() -> Vec<CompatItem> {
    let map_json =
        serde_json::to_string(&_sorted(&COMPAT_MAP.1)).expect("a string map always serializes");
    vec![
        CompatItem {
            label: "Fixture bob",
            attributes: &[("service", "fixture"), ("user", "bob")],
            secret: "fixture-secret-3".into(),
        },
        CompatItem {
            label: "Fixture bob",
            attributes: &[("service", "fixture"), ("user", "bob-alt")],
            secret: "fixture-secret-5".into(),
        },
        CompatItem {
            label: "Apps/Fixture carol",
            attributes: &[("service", "fixture"), ("user", "carol")],
            secret: "fixture-secret-4".into(),
        },
        CompatItem {
            label: COMPAT_MAP.0,
            attributes: &[("service", "fixture"), ("user", "dave"), ("type", "map")],
            secret: map_json,
        },
    ]
}

/// Returns the pairs as a key-sorted map.
fn _sorted(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Encodes a `QString` like `QDataStream` (quint32 byte length, UTF-16BE).
fn _qt_string(out: &mut Vec<u8>, text: &str) {
    let units: Vec<u16> = text.encode_utf16().collect();
    out.extend_from_slice(&((units.len() * 2) as u32).to_be_bytes());
    for unit in units {
        out.extend_from_slice(&unit.to_be_bytes());
    }
}

/// Encodes a `QMap<QString, QString>` like Qt 6 `QDataStream`: quint32 count,
/// then key/value pairs in ascending key order. This is what
/// `KWallet::Wallet::writeMap` sends over D-Bus.
fn _qt_map(pairs: &[(&str, &str)]) -> Vec<u8> {
    let sorted = _sorted(pairs);
    let mut out = Vec::new();
    out.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for (key, value) in &sorted {
        _qt_string(&mut out, key);
        _qt_string(&mut out, value);
    }
    out
}

/// Maps a D-Bus error into a kring error with context.
fn _dbus(context: &str, e: zbus::Error) -> KringError {
    KringError::InvalidInput(format!("{context}: {e}"))
}

/// Maps an I/O error on `path` into a kring error.
fn _io(path: &Path, e: std::io::Error) -> KringError {
    KringError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    }
}

/// Fails unless a KWallet call returned 0.
fn _expect_zero(context: &str, rc: i32) -> kring_core::Result<()> {
    if rc == 0 {
        return Ok(());
    }
    Err(KringError::InvalidInput(format!("{context} returned {rc}")))
}

/// Writes a fresh random salt file (mode 0600) and returns the salt.
fn _write_salt(path: &Path) -> kring_core::Result<Zeroizing<Vec<u8>>> {
    use std::io::{Read, Write};
    let random = Path::new(RANDOM_SOURCE);
    let mut salt = Zeroizing::new(vec![0u8; SALT_LEN]);
    std::fs::File::open(random)
        .and_then(|mut f| f.read_exact(&mut salt))
        .map_err(|e| _io(random, e))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(&salt))
        .map_err(|e| _io(path, e))?;
    Ok(salt)
}

/// Derives the wallet key as `KWallet::Backend::password2PBKDF2_SHA512` does.
fn _derive_key(salt: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
    pbkdf2::pbkdf2_hmac::<Sha512>(PASSWORD.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Polls `isOpen(wallet)` until it equals `open` or the timeout expires.
async fn _wait_open_state(proxy: &zbus::Proxy<'_>, open: bool) -> kring_core::Result<()> {
    let deadline = tokio::time::Instant::now() + STATE_TIMEOUT;
    loop {
        let state: bool = proxy
            .call("isOpen", &(WALLET,))
            .await
            .map_err(|e| _dbus("isOpen", e))?;
        if state == open {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(KringError::InvalidInput(format!(
                "wallet {WALLET} did not become {}",
                if open { "open" } else { "closed" }
            )));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Writes the native entries through the KWallet API.
async fn _write_native(proxy: &zbus::Proxy<'_>, handle: i32) -> kring_core::Result<()> {
    for folder in [NATIVE_PASSWORD.0, NATIVE_MAP.0, NATIVE_STREAM.0] {
        let created: bool = proxy
            .call("createFolder", &(handle, folder, APP_ID))
            .await
            .map_err(|e| _dbus("createFolder", e))?;
        if !created {
            return Err(KringError::InvalidInput(format!(
                "createFolder {folder} failed"
            )));
        }
    }
    let (folder, key, value) = NATIVE_PASSWORD;
    let rc: i32 = proxy
        .call("writePassword", &(handle, folder, key, value, APP_ID))
        .await
        .map_err(|e| _dbus("writePassword", e))?;
    _expect_zero("writePassword", rc)?;
    let map = Zeroizing::new(_qt_map(&NATIVE_MAP_VALUE));
    let rc: i32 = proxy
        .call(
            "writeMap",
            &(handle, NATIVE_MAP.0, NATIVE_MAP.1, map.as_slice(), APP_ID),
        )
        .await
        .map_err(|e| _dbus("writeMap", e))?;
    _expect_zero("writeMap", rc)?;
    let stream = NATIVE_STREAM_VALUE.as_slice();
    let rc: i32 = proxy
        .call(
            "writeEntry",
            &(
                handle,
                NATIVE_STREAM.0,
                NATIVE_STREAM.1,
                stream,
                ENTRY_TYPE_STREAM,
                APP_ID,
            ),
        )
        .await
        .map_err(|e| _dbus("writeEntry", e))?;
    _expect_zero("writeEntry", rc)
}

/// Unlocks the wallet's compat collection: the open wallet is not exposed
/// as unlocked until a Secret Service `Unlock` prompt runs, which completes
/// without a dialog because the wallet is already open.
async fn _unlock_compat(connection: &zbus::Connection) -> kring_core::Result<()> {
    let context = |e: oo7::dbus::Error| KringError::InvalidInput(format!("unlocking: {e}"));
    let service = oo7::dbus::Service::plain_with_connection(connection)
        .await
        .map_err(context)?;
    for collection in service.collections().await.map_err(context)? {
        if collection.path().as_str() == COLLECTION_PATH {
            return collection.unlock(None).await.map_err(context);
        }
    }
    Err(KringError::NotFound(COLLECTION_PATH.into()))
}

/// Creates the compat items through the daemon's Secret Service interface.
async fn _write_compat(connection: &zbus::Connection) -> kring_core::Result<()> {
    _unlock_compat(connection).await?;
    let backend = SecretServiceBackend::connect().await?;
    let collection = CollectionId(COLLECTION_PATH.into());
    for item in _compat_items() {
        let attributes: Attributes = item
            .attributes
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let new = NewItem {
            label: item.label.into(),
            attributes,
            secret: SecretValue::from_text(&item.secret),
            replace: false,
        };
        backend.create_item(&collection, new).await?;
    }
    Ok(())
}

/// Checks that the map Qt encoded for the compat map item equals what
/// [`_qt_map`] sends for the native one, so both are genuine Qt bytes.
async fn _check_map_encoding(proxy: &zbus::Proxy<'_>, handle: i32) -> kring_core::Result<()> {
    let stored: Vec<u8> = proxy
        .call(
            "readEntry",
            &(handle, COMPAT_DEFAULT_FOLDER, COMPAT_MAP.0, APP_ID),
        )
        .await
        .map_err(|e| _dbus("readEntry", e))?;
    let stored = Zeroizing::new(stored);
    let ours = Zeroizing::new(_qt_map(&COMPAT_MAP.1));
    if *stored != *ours {
        return Err(KringError::InvalidInput(
            "QMap encoding differs from the daemon's QDataStream output".into(),
        ));
    }
    Ok(())
}

/// Creates, fills and closes the wallet; returns the wallet dir.
async fn _generate() -> kring_core::Result<PathBuf> {
    let wallet_dir = paths::data_home().join("kwalletd");
    std::fs::create_dir_all(&wallet_dir).map_err(|e| _io(&wallet_dir, e))?;
    if wallet_dir.join(format!("{WALLET}.kwl")).exists() {
        return Err(KringError::InvalidInput(format!(
            "wallet {WALLET} already exists in {}",
            wallet_dir.display()
        )));
    }
    let salt = _write_salt(&wallet_dir.join(format!("{WALLET}.salt")))?;
    let key = _derive_key(&salt);
    let connection = zbus::Connection::session()
        .await
        .map_err(|e| _dbus("connecting to the session bus", e))?;
    let proxy = zbus::Proxy::new(&connection, KSECRETD_NAME, KSECRETD_PATH, KWALLET_IFACE)
        .await
        .map_err(|e| _dbus("creating the KWallet proxy", e))?;
    proxy
        .call_noreply("pamOpen", &(WALLET, key.as_slice(), 0i32))
        .await
        .map_err(|e| _dbus("pamOpen", e))?;
    _wait_open_state(&proxy, true).await?;
    let handle: i32 = proxy
        .call("open", &(WALLET, 0i64, APP_ID))
        .await
        .map_err(|e| _dbus("open", e))?;
    if handle < 0 {
        return Err(KringError::InvalidInput(format!("open returned {handle}")));
    }
    _write_native(&proxy, handle).await?;
    _write_compat(&connection).await?;
    _check_map_encoding(&proxy, handle).await?;
    let rc: i32 = proxy
        .call("close", &(handle, true, APP_ID))
        .await
        .map_err(|e| _dbus("close", e))?;
    _expect_zero("close", rc)?;
    _wait_open_state(&proxy, false).await?;
    Ok(wallet_dir)
}

/// Copies the wallet, salt and attributes files into the fixtures dir.
fn _copy_fixtures(wallet_dir: &Path) -> kring_core::Result<PathBuf> {
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kwallet");
    std::fs::create_dir_all(&target).map_err(|e| _io(&target, e))?;
    for suffix in [".kwl", ".salt", "_attributes.json"] {
        let name = format!("{WALLET}{suffix}");
        let source = wallet_dir.join(&name);
        std::fs::copy(&source, target.join(&name)).map_err(|e| _io(&source, e))?;
    }
    Ok(target)
}

/// Generates the fixtures after checking the environment.
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    if let Some(reason) = private_session_violation() {
        eprintln!("make_kwallet_fixture: refusing to run outside a private session: {reason}");
        return ExitCode::FAILURE;
    }
    let runtime = std::env::var_os(IT_RUNTIME_VAR).map(PathBuf::from);
    if let Some(reason) = data_home_violation(&paths::data_home(), runtime.as_deref()) {
        eprintln!("make_kwallet_fixture: refusing to write wallets: {reason}");
        return ExitCode::FAILURE;
    }
    let result = match tokio::time::timeout(RUN_TIMEOUT, _generate()).await {
        Ok(result) => result.and_then(|dir| _copy_fixtures(&dir)),
        Err(_) => Err(KringError::InvalidInput("timed out".into())),
    };
    match result {
        Ok(target) => {
            println!(
                "make_kwallet_fixture: wallet {WALLET:?} (password {PASSWORD:?}) written to {}",
                target.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("make_kwallet_fixture: {e}");
            ExitCode::FAILURE
        }
    }
}
