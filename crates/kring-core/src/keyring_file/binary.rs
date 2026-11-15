//! Reader for binary v0 gnome-keyring files (`GnomeKeyring\n\r\0\n`), via oo7.
//!
//! The file is decrypted in memory only. oo7 requires a target path for the
//! migrated v1 keyring; it is a path inside a fresh temporary directory that is
//! never written to.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use oo7::file::{Error as Oo7Error, UnlockedKeyring};

use super::scan::BINARY_MAGIC;
use super::textual::OfflineItem;
use crate::error::{KringError, Result};
use crate::model::{Attributes, SecretValue};

/// Reads and decrypts every item of a binary v0 keyring file.
///
/// A file that does not start with the binary magic yields
/// `InvalidInput("Not a binary keyring")`; a wrong password yields
/// `InvalidInput("Wrong password for <file name>")`. Nothing is written to disk
/// and no partial item list is returned on error.
pub async fn read_binary(path: &Path, password: &SecretValue) -> Result<Vec<OfflineItem>> {
    let name = _display_name(path);
    if !_has_binary_magic(path)? {
        return Err(KringError::InvalidInput("Not a binary keyring".into()));
    }
    _read_with_target(path, password, &_scratch_target(), &name).await
}

/// Returns true when the first bytes of `path` are the binary magic (only they are read).
///
/// A file shorter than the magic is not binary; an open failure is an Io error.
fn _has_binary_magic(path: &Path) -> Result<bool> {
    let io = |e: std::io::Error| KringError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    };
    let mut file = std::fs::File::open(path).map_err(io)?;
    let mut head = [0u8; BINARY_MAGIC.len()];
    match file.read_exact(&mut head) {
        Ok(()) => Ok(head == BINARY_MAGIC),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(io(e)),
    }
}

/// Builds a unique path under the temp dir that is only a placeholder for oo7 and never created.
fn _scratch_target() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "kring-binary-read-{}-{nanos}.keyring",
        std::process::id()
    ))
}

/// Loads the file through oo7 with the given (never written) target path.
async fn _read_with_target(
    path: &Path,
    password: &SecretValue,
    target: &Path,
    name: &str,
) -> Result<Vec<OfflineItem>> {
    let secret = oo7::Secret::blob(password.as_bytes());
    let keyring = UnlockedKeyring::load_from_v0(path, target, Some(secret))
        .await
        .map_err(|e| _map_error(name, e))?;
    let items = keyring.items().await.map_err(|e| _map_error(name, e))?;
    Ok(items.iter().map(_convert_item).collect())
}

/// Returns the file name used in error messages.
fn _display_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Maps an oo7 error to a kring error without leaking secrets (oo7 messages carry none).
fn _map_error(name: &str, error: Oo7Error) -> KringError {
    match error {
        Oo7Error::ChecksumMismatch | Oo7Error::MacError | Oo7Error::IncorrectSecret => {
            KringError::InvalidInput(format!("Wrong password for {name}"))
        }
        other => KringError::InvalidInput(format!("Cannot read {name}: {other}")),
    }
}

/// Converts an oo7 item into an [`OfflineItem`].
fn _convert_item(item: &oo7::file::UnlockedItem) -> OfflineItem {
    let secret = item.secret();
    let attributes: Attributes = item
        .attributes()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    OfflineItem {
        label: item.label().to_string(),
        attributes,
        secret: SecretValue::new(secret.as_bytes().to_vec(), secret.content_type().as_str()),
        created: item.created().as_secs(),
        modified: item.modified().as_secs(),
        secret_missing: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Password of the generated fixture.
    const FIXTURE_PASSWORD: &str = "fixture-pw";

    /// Returns the path of a keyring fixture.
    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/keyrings")
            .join(name)
    }

    /// The two fixture items are read with labels, attributes and secrets.
    #[tokio::test]
    async fn reads_binary_fixture() {
        let path = fixture("binary_two_items.keyring");
        let items = read_binary(&path, &SecretValue::from_text(FIXTURE_PASSWORD))
            .await
            .unwrap();
        assert_eq!(items.len(), 2);
        for (label, user, secret) in [
            ("Fixture One", "one", "fixture-secret-1"),
            ("Fixture Two", "two", "fixture-secret-2"),
        ] {
            let item = items.iter().find(|i| i.label == label).unwrap();
            assert_eq!(item.attributes.get("service").unwrap(), "fixture");
            assert_eq!(item.attributes.get("user").unwrap(), user);
            assert_eq!(item.secret.as_text(), Some(secret));
            assert!(item.created > 0 && item.modified >= item.created);
            assert!(!item.secret_missing);
        }
    }

    /// A wrong password is a clean error naming the file, with no items.
    #[tokio::test]
    async fn wrong_password_is_clean_error() {
        let path = fixture("binary_two_items.keyring");
        let err = read_binary(&path, &SecretValue::from_text("nope"))
            .await
            .unwrap_err();
        match err {
            KringError::InvalidInput(msg) => {
                assert_eq!(msg, "Wrong password for binary_two_items.keyring")
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// Textual files are rejected before oo7 sees them.
    #[tokio::test]
    async fn textual_file_is_rejected() {
        let path = fixture("textual_two_items.keyring");
        let err = read_binary(&path, &SecretValue::from_text("x"))
            .await
            .unwrap_err();
        assert!(matches!(&err, KringError::InvalidInput(m) if m == "Not a binary keyring"));
    }

    /// A file shorter than the magic, or a missing one, never reaches oo7.
    #[tokio::test]
    async fn short_file_is_not_binary() {
        let dir = tempfile::tempdir().unwrap();
        let short = dir.path().join("short.keyring");
        std::fs::write(&short, &BINARY_MAGIC[..5]).unwrap();
        let err = read_binary(&short, &SecretValue::from_text("x"))
            .await
            .unwrap_err();
        assert!(matches!(&err, KringError::InvalidInput(m) if m == "Not a binary keyring"));
        let missing = dir.path().join("missing.keyring");
        let err = read_binary(&missing, &SecretValue::from_text("x"))
            .await
            .unwrap_err();
        assert!(matches!(err, KringError::Io { .. }), "{err:?}");
    }

    /// Reading never creates the scratch target (nothing is written).
    #[tokio::test]
    async fn read_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("scratch.keyring");
        let path = fixture("binary_two_items.keyring");
        let items = _read_with_target(
            &path,
            &SecretValue::from_text(FIXTURE_PASSWORD),
            &target,
            "x",
        )
        .await
        .unwrap();
        assert_eq!(items.len(), 2);
        assert!(!target.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
