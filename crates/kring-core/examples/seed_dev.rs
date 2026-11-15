//! Seeds a throwaway gnome-keyring with sample data for manual UI testing.
//!
//! Dev only: run through `scripts/dev-session.sh`. It refuses to run outside the
//! private session (`kring_core::dev_guard`), so the user's real keyring is never touched.
//! It also writes two sample backups of the (temp) keyring fixtures, only when
//! the data home lies inside the session's temp root.

use std::path::PathBuf;
use std::process::ExitCode;

use kring_core::backup::{BACKUP_KEEP, BackupManager};
use kring_core::dev_guard::{IT_RUNTIME_VAR, data_home_violation, private_session_violation};
use kring_core::model::{Attributes, CollectionId, LOGIN_COLLECTION_PATH, NewItem, SecretValue};
use kring_core::paths;
use kring_core::secret_service::SecretServiceBackend;
use kring_core::{MasterPasswordStore, SecretStore};

/// Label and password of the collection that is left locked.
const WORK: (&str, &str) = ("Work", "work");
/// Label and password of the collection that is left empty.
const DEFAULT_1: (&str, &str) = ("Default_1", "d1");
/// Label and password of the orphan holding a duplicate of a login item.
const DEFAULT_2: (&str, &str) = ("Default_2", "d2");
/// Label and password of the second empty orphan.
const DEFAULT_3: (&str, &str) = ("Default_3", "d3");
/// Passphrase of the sample backup holding a plaintext keyring.
const BACKUP_PASSPHRASE: &str = "backup";
/// Binary fixture backed up by both sample backups.
const BINARY_FIXTURE: &str = "binary_two_items.keyring";
/// Plaintext fixture backed up (encrypted) by the newest sample backup.
const TEXTUAL_FIXTURE: &str = "textual_two_items.keyring";
/// Content type of the binary sample secret.
const BINARY_CONTENT_TYPE: &str = "application/octet-stream";
/// Preset variable of the app; with [`DIALOG_TRANSFER_PREVIEW`] `Work` stays unlocked.
const VAR_DIALOG: &str = "KRING_DEV_DIALOG";
/// Preset value that previews a transfer between `login` and `Work`.
const DIALOG_TRANSFER_PREVIEW: &str = "transfer-preview";
/// Preset value that previews a consolidation into `login`: `Work` stays
/// unlocked (a conflict) and `Default_1` is locked (a skipped keyring).
const DIALOG_CONSOLIDATE_PREVIEW: &str = "consolidate-preview";
/// Any non-empty value relabels `Default_1` and `Default_3` as [`SHARED_LABEL`],
/// like the orphans gnome-keyring creates (same label, different ids).
const VAR_SHARED_LABELS: &str = "KRING_DEV_SHARED_LABELS";
/// Label given to the orphans by [`VAR_SHARED_LABELS`].
const SHARED_LABEL: &str = "Default";
/// With value `1`, [`MANY_LOCKED_COUNT`] more locked keyrings labelled
/// [`MANY_LOCKED_LABEL`] are created (the daemon names them
/// `Default_keyring`, `Default_keyring_1`...), for the locked list of the
/// consolidation preview.
const VAR_MANY_LOCKED: &str = "KRING_DEV_MANY_LOCKED";
/// Label of the keyrings added by [`VAR_MANY_LOCKED`].
const MANY_LOCKED_LABEL: &str = "Default keyring";
/// Number of keyrings added by [`VAR_MANY_LOCKED`].
const MANY_LOCKED_COUNT: usize = 12;
/// Password of the keyrings added by [`VAR_MANY_LOCKED`], except the last
/// one: the app's remembered dev passphrase (`KRING_DEV_REMEMBER`), so a
/// remembered "Unlock all" opens them.
const MANY_LOCKED_PASSWORD: &str = "backup";
/// Password of the last keyring added by [`VAR_MANY_LOCKED`] (so "Unlock
/// all" with [`MANY_LOCKED_PASSWORD`] leaves one locked).
const MANY_LOCKED_ODD_PASSWORD: &str = "odd";
/// Attributes of the item `login` and `Work` share with different secrets.
const GITHUB_ATTRS: [(&str, &str); 2] = [("service", "gh"), ("user", "dev")];
/// Attributes of the item `login` and `Work` share with the same secret.
const MAIL_ATTRS: [(&str, &str); 2] = [("service", "imap"), ("user", "dev@example.com")];
/// Pause before the shared `Work` items, so their modification time is
/// newer (gnome-keyring stores whole seconds).
const NEWER_PAUSE: std::time::Duration = std::time::Duration::from_millis(1100);

/// Builds attributes from key/value pairs.
fn _attrs(pairs: &[(&str, &str)]) -> Attributes {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Builds a text item.
fn _item(label: &str, pairs: &[(&str, &str)], secret: &str) -> NewItem {
    NewItem {
        label: label.into(),
        attributes: _attrs(pairs),
        secret: SecretValue::from_text(secret),
        replace: false,
    }
}

/// Creates the sample collections and items, then locks `Work` (unless a
/// preview preset needs it unlocked); the consolidation preset locks
/// `Default_1` instead.
async fn _seed() -> kring_core::Result<()> {
    let backend = SecretServiceBackend::connect().await?;
    let login = CollectionId(LOGIN_COLLECTION_PATH.into());
    let login_items = [
        _item("GitHub token", &GITHUB_ATTRS, "ghp_sample"),
        _item("Mail account", &MAIL_ATTRS, "mail-pw"),
        NewItem {
            label: "Binary blob".into(),
            attributes: _attrs(&[("kind", "binary")]),
            secret: SecretValue::new(vec![0xde, 0xad, 0x00, 0xbe, 0xef], BINARY_CONTENT_TYPE),
            replace: false,
        },
    ];
    for item in login_items {
        backend.create_item(&login, item).await?;
    }
    let work = backend
        .create_with_password(WORK.0, &SecretValue::from_text(WORK.1))
        .await?;
    backend
        .create_item(&work, _item("VPN", &[("service", "vpn")], "vpn-pw"))
        .await?;
    backend
        .create_item(
            &work,
            _item("Jira API", &[("service", "jira")], "jira-token"),
        )
        .await?;
    // Same identity as in login: a newer, different secret (conflict) and
    // an identical copy (duplicate) for the Copy / Move preview.
    std::thread::sleep(NEWER_PAUSE);
    backend
        .create_item(&work, _item("GitHub token", &GITHUB_ATTRS, "ghp_rotated"))
        .await?;
    backend
        .create_item(&work, _item("Mail account", &MAIL_ATTRS, "mail-pw"))
        .await?;
    let default_1 = backend
        .create_with_password(DEFAULT_1.0, &SecretValue::from_text(DEFAULT_1.1))
        .await?;
    // Orphans for the consolidation: one holding a copy of a login item
    // (same identity and secret: a duplicate), one empty.
    let default_2 = backend
        .create_with_password(DEFAULT_2.0, &SecretValue::from_text(DEFAULT_2.1))
        .await?;
    backend
        .create_item(&default_2, _item("Mail account", &MAIL_ATTRS, "mail-pw"))
        .await?;
    let default_3 = backend
        .create_with_password(DEFAULT_3.0, &SecretValue::from_text(DEFAULT_3.1))
        .await?;
    if _shared_labels() {
        for orphan in [&default_1, &default_3] {
            backend.rename_collection(orphan, SHARED_LABEL).await?;
        }
    }
    if !_keep_work_unlocked() {
        backend.lock(&work).await?;
    }
    if _preset_is(DIALOG_CONSOLIDATE_PREVIEW) {
        backend.lock(&default_1).await?;
    }
    if _many_locked() {
        _seed_many_locked(&backend).await?;
    }
    Ok(())
}

/// Creates the [`MANY_LOCKED_COUNT`] locked keyrings of [`VAR_MANY_LOCKED`].
async fn _seed_many_locked(backend: &SecretServiceBackend) -> kring_core::Result<()> {
    for index in 0..MANY_LOCKED_COUNT {
        let password = if index + 1 == MANY_LOCKED_COUNT {
            MANY_LOCKED_ODD_PASSWORD
        } else {
            MANY_LOCKED_PASSWORD
        };
        let id = backend
            .create_with_password(MANY_LOCKED_LABEL, &SecretValue::from_text(password))
            .await?;
        backend.lock(&id).await?;
    }
    Ok(())
}

/// Returns true when the many locked keyrings are wanted (see [`VAR_MANY_LOCKED`]).
fn _many_locked() -> bool {
    std::env::var(VAR_MANY_LOCKED).is_ok_and(|v| v == "1")
}

/// Returns true when the orphans must share one label (see [`VAR_SHARED_LABELS`]).
fn _shared_labels() -> bool {
    std::env::var_os(VAR_SHARED_LABELS).is_some_and(|v| !v.is_empty())
}

/// Returns true when the app preset variable equals `value`.
fn _preset_is(value: &str) -> bool {
    std::env::var(VAR_DIALOG).is_ok_and(|v| v == value)
}

/// Returns true when the app preset previews a transfer into `Work` or a
/// consolidation of it, which needs it unlocked.
fn _keep_work_unlocked() -> bool {
    _preset_is(DIALOG_TRANSFER_PREVIEW) || _preset_is(DIALOG_CONSOLIDATE_PREVIEW)
}

/// Creates the sample backups: an older binary one (reason
/// `delete-collection`) and a newer one with an encrypted plaintext keyring
/// (reason `delete-item`, passphrase [`BACKUP_PASSPHRASE`]).
fn _seed_backups() -> kring_core::Result<()> {
    let data_home = paths::data_home();
    let runtime = std::env::var_os(IT_RUNTIME_VAR).map(PathBuf::from);
    if let Some(reason) = data_home_violation(&data_home, runtime.as_deref()) {
        return Err(kring_core::KringError::InvalidInput(format!(
            "refusing to write backups: {reason}"
        )));
    }
    let keyrings = paths::keyrings_dir();
    let manager = BackupManager {
        root: paths::backups_dir(),
        keep: BACKUP_KEEP,
    };
    let binary = keyrings.join(BINARY_FIXTURE);
    manager.create("delete-collection", std::slice::from_ref(&binary), None)?;
    let pass = SecretValue::from_text(BACKUP_PASSPHRASE);
    let both = [binary, keyrings.join(TEXTUAL_FIXTURE)];
    manager.create("delete-item", &both, Some(&pass))?;
    Ok(())
}

/// Seeds the keyring after checking the environment.
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    if let Some(reason) = private_session_violation() {
        eprintln!("seed_dev: refusing to run outside a private session: {reason}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = _seed_backups() {
        eprintln!("seed_dev: {e}");
        return ExitCode::FAILURE;
    }
    match _seed().await {
        Ok(()) => {
            println!(
                "seed_dev: seeded login (3 items), {} (4 items, 2 shared with login, {}, password {:?}), {} (empty, password {:?}), {} (1 duplicate of login, password {:?}), {} (empty, password {:?}), 2 backups (passphrase {:?})",
                WORK.0,
                if _keep_work_unlocked() {
                    "unlocked"
                } else {
                    "locked"
                },
                WORK.1,
                DEFAULT_1.0,
                DEFAULT_1.1,
                DEFAULT_2.0,
                DEFAULT_2.1,
                DEFAULT_3.0,
                DEFAULT_3.1,
                BACKUP_PASSPHRASE
            );
            if _many_locked() {
                println!(
                    "seed_dev: added {MANY_LOCKED_COUNT} locked {MANY_LOCKED_LABEL:?} keyrings (password {MANY_LOCKED_PASSWORD:?}, the last one {MANY_LOCKED_ODD_PASSWORD:?})"
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("seed_dev: {e}");
            ExitCode::FAILURE
        }
    }
}
