//! Seeds a throwaway gnome-keyring with sample data for manual UI testing.
//!
//! Dev only: run through `scripts/dev-session.sh`. It refuses to run outside the
//! private session (`kring_core::dev_guard`), so the user's real keyring is never touched.

use std::process::ExitCode;

use kring_core::dev_guard::private_session_violation;
use kring_core::model::{Attributes, CollectionId, LOGIN_COLLECTION_PATH, NewItem, SecretValue};
use kring_core::secret_service::SecretServiceBackend;
use kring_core::{MasterPasswordStore, SecretStore};

/// Label and password of the collection that is left locked.
const WORK: (&str, &str) = ("Work", "work");
/// Label and password of the collection that is left empty.
const DEFAULT_1: (&str, &str) = ("Default_1", "d1");
/// Content type of the binary sample secret.
const BINARY_CONTENT_TYPE: &str = "application/octet-stream";

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

/// Creates the sample collections and items, then locks `Work`.
async fn _seed() -> kring_core::Result<()> {
    let backend = SecretServiceBackend::connect().await?;
    let login = CollectionId(LOGIN_COLLECTION_PATH.into());
    let login_items = [
        _item(
            "GitHub token",
            &[("service", "gh"), ("user", "dev")],
            "ghp_sample",
        ),
        _item(
            "Mail account",
            &[("service", "imap"), ("user", "dev@example.com")],
            "mail-pw",
        ),
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
    backend
        .create_with_password(DEFAULT_1.0, &SecretValue::from_text(DEFAULT_1.1))
        .await?;
    backend.lock(&work).await?;
    Ok(())
}

/// Seeds the keyring after checking the environment.
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    if let Some(reason) = private_session_violation() {
        eprintln!("seed_dev: refusing to run outside a private session: {reason}");
        return ExitCode::FAILURE;
    }
    match _seed().await {
        Ok(()) => {
            println!(
                "seed_dev: seeded login (3 items), {} (2 items, locked, password {:?}), {} (empty, password {:?})",
                WORK.0, WORK.1, DEFAULT_1.0, DEFAULT_1.1
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("seed_dev: {e}");
            ExitCode::FAILURE
        }
    }
}
