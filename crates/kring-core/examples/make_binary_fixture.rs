//! Generates the binary v0 keyring test fixture with a throwaway gnome-keyring.
//!
//! Dev only: run through `scripts/it-session.sh`:
//! `bash scripts/it-session.sh cargo run -q -p kring-core --example make_binary_fixture`.
//! It refuses to run outside the private session (`kring_core::dev_guard`) and writes
//! only `tests/fixtures/keyrings/binary_two_items.keyring`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use kring_core::dev_guard::private_session_violation;
use kring_core::error::KringError;
use kring_core::model::{Attributes, NewItem, SecretValue};
use kring_core::secret_service::SecretServiceBackend;
use kring_core::{MasterPasswordStore, SecretStore};

/// Label of the fixture collection (file stem in the keyrings directory).
const COLLECTION_LABEL: &str = "fixture";
/// Password of the fixture collection.
const PASSWORD: &str = "fixture-pw";
/// How long to wait for the daemon to write the collection file.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Fixture file name inside `tests/fixtures/keyrings`.
const FIXTURE_NAME: &str = "binary_two_items.keyring";

/// Builds a fixture item.
fn _item(label: &str, user: &str, secret: &str) -> NewItem {
    let attributes: Attributes = [("service", "fixture"), ("user", user)]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    NewItem {
        label: label.into(),
        attributes,
        secret: SecretValue::from_text(secret),
        replace: false,
    }
}

/// Returns the daemon's keyrings directory inside the private session.
fn _keyrings_dir() -> Result<PathBuf, String> {
    let data = std::env::var("XDG_DATA_HOME").map_err(|_| "XDG_DATA_HOME is unset".to_string())?;
    Ok(Path::new(&data).join("keyrings"))
}

/// Polls until the file exists and is non-empty.
async fn _wait_for_file(path: &Path) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < WRITE_TIMEOUT {
        if std::fs::metadata(path)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("{} was not written in time", path.display()))
}

/// Creates the collection and items, locks it to force a write, then copies the file.
async fn _generate() -> Result<(), String> {
    let e = |e: KringError| e.to_string();
    let backend = SecretServiceBackend::connect().await.map_err(e)?;
    let id = backend
        .create_with_password(COLLECTION_LABEL, &SecretValue::from_text(PASSWORD))
        .await
        .map_err(e)?;
    backend
        .create_item(&id, _item("Fixture One", "one", "fixture-secret-1"))
        .await
        .map_err(e)?;
    backend
        .create_item(&id, _item("Fixture Two", "two", "fixture-secret-2"))
        .await
        .map_err(e)?;
    backend.lock(&id).await.map_err(e)?;

    let source = _keyrings_dir()?.join(format!("{COLLECTION_LABEL}.keyring"));
    _wait_for_file(&source).await?;
    let target = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/keyrings")
        .join(FIXTURE_NAME);
    std::fs::copy(&source, &target).map_err(|err| err.to_string())?;
    println!("make_binary_fixture: wrote {}", target.display());
    Ok(())
}

/// Generates the fixture after checking the environment.
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    if let Some(reason) = private_session_violation() {
        eprintln!("make_binary_fixture: refusing to run outside a private session: {reason}");
        return ExitCode::FAILURE;
    }
    match _generate().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("make_binary_fixture: {e}");
            ExitCode::FAILURE
        }
    }
}
