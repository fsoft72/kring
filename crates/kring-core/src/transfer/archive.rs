//! Encrypted export and import of items (age scrypt passphrase archive).
//!
//! The archive is an age file whose plaintext is JSON:
//! `{"format":"kring-items","version":1,"items":[{"collection","label",
//! "attributes","secret_b64","content_type","created","modified"}]}`.
//!
//! Plaintext JSON buffers are held in `Zeroizing`. Known residuals: the age
//! library's internal buffers, the `Vec` growth while reading the decrypted
//! stream, and the base64 text of a secret while it is encoded (that one is
//! zeroized after use) are not under this module's control.

use std::borrow::Cow;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::backup::{encrypt_age, io_err};
use crate::error::{KringError, Result};
use crate::keyring_file::textual::OfflineItem;
use crate::model::{Attributes, SecretValue};

/// Value of the `format` tag of an item archive.
pub const EXPORT_FORMAT: &str = "kring-items";
/// Current archive format version.
pub const EXPORT_VERSION: u32 = 1;

/// Message used for any failure to decrypt the archive.
const DECRYPT_FAILED: &str = "Wrong passphrase or corrupted archive";

/// One item of an archive together with the collection it came from.
#[derive(Clone, Debug)]
pub struct ExportedItem {
    /// Label of the source collection.
    pub collection: String,
    /// The item itself.
    pub item: OfflineItem,
}

/// Serialization view of an item (secret already base64 encoded).
#[derive(Serialize)]
struct ItemOut<'a> {
    collection: &'a str,
    label: &'a str,
    attributes: &'a Attributes,
    secret_b64: &'a str,
    content_type: &'a str,
    created: u64,
    modified: u64,
}

/// Serialization view of the whole archive.
#[derive(Serialize)]
struct ArchiveOut<'a> {
    format: &'static str,
    version: u32,
    items: Vec<ItemOut<'a>>,
}

/// Header used to check the tag and version before reading the items.
#[derive(Deserialize)]
struct ArchiveHeader {
    format: String,
    version: u32,
}

/// Deserialized archive (the secret text is borrowed from the decrypted buffer).
#[derive(Deserialize)]
struct ArchiveIn<'a> {
    #[serde(borrow)]
    items: Vec<ItemIn<'a>>,
}

/// Deserialized item.
#[derive(Deserialize)]
struct ItemIn<'a> {
    collection: String,
    label: String,
    attributes: Attributes,
    #[serde(borrow)]
    secret_b64: Cow<'a, str>,
    content_type: String,
    created: u64,
    modified: u64,
}

/// A `Write` that only counts bytes, to size the JSON buffer exactly.
struct CountingWriter(usize);

impl std::io::Write for CountingWriter {
    /// Counts the bytes and discards them.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    /// Nothing to flush.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Turns the passphrase into an age secret (non-empty UTF-8 only).
fn passphrase_secret(passphrase: &SecretValue) -> Result<SecretString> {
    let text = passphrase
        .as_text()
        .ok_or_else(|| KringError::InvalidInput("Passphrase must be valid UTF-8".into()))?;
    if text.is_empty() {
        return Err(KringError::InvalidInput(
            "Passphrase must not be empty".into(),
        ));
    }
    Ok(SecretString::from(text.to_string()))
}

/// Serializes the items into an exactly sized, zeroizing JSON buffer.
fn serialize_items(items: &[ExportedItem]) -> Result<Zeroizing<Vec<u8>>> {
    let encoded: Vec<Zeroizing<String>> = items
        .iter()
        .map(|e| Zeroizing::new(STANDARD.encode(e.item.secret.as_bytes())))
        .collect();
    let doc = ArchiveOut {
        format: EXPORT_FORMAT,
        version: EXPORT_VERSION,
        items: items
            .iter()
            .zip(&encoded)
            .map(|(e, b64)| ItemOut {
                collection: &e.collection,
                label: &e.item.label,
                attributes: &e.item.attributes,
                secret_b64: b64,
                content_type: &e.item.secret.content_type,
                created: e.item.created,
                modified: e.item.modified,
            })
            .collect(),
    };
    let json_err =
        |e: serde_json::Error| KringError::InvalidInput(format!("Cannot serialize items: {e}"));
    let mut counter = CountingWriter(0);
    serde_json::to_writer(&mut counter, &doc).map_err(json_err)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(counter.0));
    serde_json::to_writer(&mut *buf, &doc).map_err(json_err)?;
    Ok(buf)
}

/// Returns the temporary sibling path used while writing `path`.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Writes the items to an age archive protected by `passphrase`.
///
/// The file gets mode 0600 and is written via a temporary file; an existing
/// destination is never overwritten (`InvalidInput`).
pub fn write_archive(path: &Path, items: &[ExportedItem], passphrase: &SecretValue) -> Result<()> {
    let secret = passphrase_secret(passphrase)?;
    if path.exists() {
        return Err(KringError::InvalidInput(format!(
            "{} already exists",
            path.display()
        )));
    }
    let json = serialize_items(items)?;
    let encrypted = encrypt_age(&json, &secret, path)?;
    publish_file(path, &encrypted, |from, to| fs::hard_link(from, to))
}

/// Writes `bytes` to a new file `path` (mode 0600) without ever overwriting one.
///
/// See [`publish_file`]; an existing destination is `InvalidInput("... already exists")`.
pub(crate) fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    publish_file(path, bytes, |from, to| fs::hard_link(from, to))
}

/// Writes `bytes` to `path` without ever overwriting an existing file.
///
/// The data goes to a temporary sibling first and is hard linked into place.
/// If the link fails for a reason other than the destination existing (vfat,
/// exFAT, FUSE or network mounts), the bytes are written straight to `path`
/// with `create_new`. `link` is injectable for tests.
fn publish_file(
    path: &Path,
    bytes: &[u8],
    link: impl Fn(&Path, &Path) -> std::io::Result<()>,
) -> Result<()> {
    let exists = || KringError::InvalidInput(format!("{} already exists", path.display()));
    let tmp = temp_path(path);
    match create_private(&tmp, bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(KringError::InvalidInput(format!(
                "A previous export left {}; remove it and retry",
                tmp.display()
            )));
        }
        Err(e) => return Err(io_err(&tmp, e)),
    }
    let linked = link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(exists()),
        Err(_) => match create_private(path, bytes) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(exists()),
            Err(e) => Err(io_err(path, e)),
        },
    }
}

/// Creates `path` (mode 0600, must not exist) and writes `bytes`.
///
/// If the write fails after the file was created by this call, the file is
/// removed again. An already existing file is never touched.
fn create_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// Decrypts the archive file into a zeroizing buffer.
fn decrypt_archive(path: &Path, secret: SecretString) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = fs::read(path).map_err(|e| io_err(path, e))?;
    let bad = || KringError::InvalidInput(DECRYPT_FAILED.into());
    let decryptor = age::Decryptor::new(&bytes[..]).map_err(|_| bad())?;
    let identity = crate::backup::age_identity(secret);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| bad())?;
    let mut plain = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut plain).map_err(|_| bad())?;
    Ok(plain)
}

/// Reads and decrypts an item archive.
///
/// Nothing is returned unless the whole archive decrypts and validates.
pub fn read_archive(path: &Path, passphrase: &SecretValue) -> Result<Vec<ExportedItem>> {
    let secret = passphrase_secret(passphrase)?;
    let plain = decrypt_archive(path, secret)?;
    let not_archive = || KringError::InvalidInput("Not a kring items archive".into());
    let header: ArchiveHeader = serde_json::from_slice(&plain).map_err(|_| not_archive())?;
    if header.format != EXPORT_FORMAT {
        return Err(not_archive());
    }
    if header.version != EXPORT_VERSION {
        return Err(KringError::InvalidInput(format!(
            "Unsupported archive version {}",
            header.version
        )));
    }
    let doc: ArchiveIn = serde_json::from_slice(&plain).map_err(|e| {
        KringError::InvalidInput(format!(
            "Invalid archive contents (line {}, column {})",
            e.line(),
            e.column()
        ))
    })?;
    doc.items
        .into_iter()
        .map(|it| {
            let bytes = STANDARD.decode(it.secret_b64.as_bytes()).map_err(|_| {
                KringError::InvalidInput(format!(
                    "Invalid secret encoding in item \"{}\"",
                    it.label
                ))
            })?;
            Ok(ExportedItem {
                collection: it.collection,
                item: OfflineItem {
                    label: it.label,
                    attributes: it.attributes,
                    secret: SecretValue::new(bytes, &it.content_type),
                    created: it.created,
                    modified: it.modified,
                    secret_missing: false,
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Builds an item with the given secret bytes.
    fn item(label: &str, secret: Vec<u8>, ct: &str) -> ExportedItem {
        let mut attributes = Attributes::new();
        attributes.insert("service".into(), label.into());
        ExportedItem {
            collection: "login".into(),
            item: OfflineItem {
                label: label.into(),
                attributes,
                secret: SecretValue::new(secret, ct),
                created: 10,
                modified: 20,
                secret_missing: false,
            },
        }
    }

    /// Passphrase helper.
    fn pw(s: &str) -> SecretValue {
        SecretValue::from_text(s)
    }

    /// Encrypts arbitrary plaintext into an archive file for format tests.
    fn write_raw(path: &Path, plain: &[u8]) {
        let enc = encrypt_age(plain, &SecretString::from("pw".to_string()), path).unwrap();
        fs::write(path, enc).unwrap();
    }

    /// Text and binary secrets survive a round trip.
    #[test]
    fn roundtrip_text_and_binary_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.kring-items");
        let items = vec![
            item("one", b"text secret".to_vec(), "text/plain"),
            item("two", vec![0, 255, 1, 2, 128], "application/octet-stream"),
        ];
        write_archive(&path, &items, &pw("pw")).unwrap();
        let got = read_archive(&path, &pw("pw")).unwrap();
        assert_eq!(got.len(), 2);
        for (a, b) in items.iter().zip(&got) {
            assert_eq!(a.collection, b.collection);
            assert_eq!(a.item.label, b.item.label);
            assert_eq!(a.item.attributes, b.item.attributes);
            assert_eq!(a.item.secret.as_bytes(), b.item.secret.as_bytes());
            assert_eq!(a.item.secret.content_type, b.item.secret.content_type);
            assert_eq!(
                (a.item.created, a.item.modified),
                (b.item.created, b.item.modified)
            );
        }
    }

    /// The archive does not contain the secret in clear.
    #[test]
    fn archive_is_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.kring-items");
        write_archive(
            &path,
            &[item("one", b"visible-marker".to_vec(), "text/plain")],
            &pw("pw"),
        )
        .unwrap();
        let raw = fs::read(&path).unwrap();
        assert!(!raw.windows(14).any(|w| w == b"visible-marker"));
    }

    /// A wrong passphrase yields a clear error and nothing else.
    #[test]
    fn wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.kring-items");
        write_archive(
            &path,
            &[item("one", b"s".to_vec(), "text/plain")],
            &pw("pw"),
        )
        .unwrap();
        let err = read_archive(&path, &pw("other")).unwrap_err();
        assert!(
            matches!(&err, KringError::InvalidInput(m) if m == DECRYPT_FAILED),
            "{err}"
        );
    }

    /// Garbage and truncated files fail with the same message.
    #[test]
    fn corrupted_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let garbage = dir.path().join("g");
        fs::write(&garbage, b"this is not an age file").unwrap();
        let err = read_archive(&garbage, &pw("pw")).unwrap_err();
        assert!(
            matches!(&err, KringError::InvalidInput(m) if m == DECRYPT_FAILED),
            "{err}"
        );

        let path = dir.path().join("a.kring-items");
        write_archive(
            &path,
            &[item("one", b"s".to_vec(), "text/plain")],
            &pw("pw"),
        )
        .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
        let err = read_archive(&path, &pw("pw")).unwrap_err();
        assert!(
            matches!(&err, KringError::InvalidInput(m) if m == DECRYPT_FAILED),
            "{err}"
        );
    }

    /// Wrong format tag, bad JSON and future versions are rejected.
    #[test]
    fn wrong_format_tag_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x");
        write_raw(&path, br#"{"format":"other","version":1,"items":[]}"#);
        let err = read_archive(&path, &pw("pw")).unwrap_err();
        assert!(
            matches!(&err, KringError::InvalidInput(m) if m == "Not a kring items archive"),
            "{err}"
        );

        fs::remove_file(&path).unwrap();
        write_raw(&path, b"not json");
        let err = read_archive(&path, &pw("pw")).unwrap_err();
        assert!(
            matches!(&err, KringError::InvalidInput(m) if m == "Not a kring items archive"),
            "{err}"
        );

        fs::remove_file(&path).unwrap();
        write_raw(&path, br#"{"format":"kring-items","version":2,"items":[]}"#);
        let err = read_archive(&path, &pw("pw")).unwrap_err();
        assert!(
            matches!(&err, KringError::InvalidInput(m) if m == "Unsupported archive version 2"),
            "{err}"
        );
    }

    /// Version 0 is rejected too.
    #[test]
    fn version_zero_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x");
        write_raw(&path, br#"{"format":"kring-items","version":0,"items":[]}"#);
        let err = read_archive(&path, &pw("pw")).unwrap_err();
        assert!(
            matches!(&err, KringError::InvalidInput(m) if m == "Unsupported archive version 0"),
            "{err}"
        );
    }

    /// When hard links are unsupported the archive is still written, privately.
    #[test]
    fn link_failure_falls_back_to_direct_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.kring-items");
        let eperm = |_: &Path, _: &Path| Err(std::io::Error::from_raw_os_error(1));
        publish_file(&path, b"data", eperm).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"data");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        // The fallback never overwrites either.
        let again = publish_file(&path, b"new", eperm);
        assert!(matches!(again, Err(KringError::InvalidInput(_))));
        assert_eq!(fs::read(&path).unwrap(), b"data");
    }

    /// A leftover temp file is reported and left untouched.
    #[test]
    fn stale_temp_file_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.kring-items");
        let tmp = temp_path(&path);
        fs::write(&tmp, b"stale").unwrap();
        let err = write_archive(&path, &[], &pw("pw")).unwrap_err();
        assert!(
            matches!(&err, KringError::InvalidInput(m) if m.contains("A previous export left")),
            "{err}"
        );
        assert_eq!(fs::read(&tmp).unwrap(), b"stale");
        assert!(!path.exists());
    }

    /// An existing destination is never overwritten.
    #[test]
    fn refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.kring-items");
        fs::write(&path, b"precious").unwrap();
        let err = write_archive(&path, &[], &pw("pw")).unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
        assert_eq!(fs::read(&path).unwrap(), b"precious");
    }

    /// The archive is private and no temp file is left.
    #[test]
    fn file_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.kring-items");
        write_archive(&path, &[], &pw("pw")).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// Empty and non-UTF-8 passphrases are rejected.
    #[test]
    fn bad_passphrase_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.kring-items");
        let err = write_archive(&path, &[], &pw("")).unwrap_err();
        assert!(matches!(err, KringError::InvalidInput(_)));
        let bin = SecretValue::new(vec![0xff, 0xfe], "application/octet-stream");
        assert!(matches!(
            write_archive(&path, &[], &bin),
            Err(KringError::InvalidInput(_))
        ));
        assert!(!path.exists());
    }
}
