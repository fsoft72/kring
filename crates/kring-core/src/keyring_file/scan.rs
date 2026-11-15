//! Discovery and format detection of `*.keyring` files in a directory.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use zeroize::Zeroizing;

use super::textual::parse_textual;
use crate::error::{KringError, Result};

/// Magic bytes of the binary (encrypted) v0 keyring format.
pub const BINARY_MAGIC: &[u8] = b"GnomeKeyring\n\r\0\n";
/// Header line of a textual keyring.
const TEXTUAL_HEADER: &[u8] = b"[keyring]";
/// File extension of keyring files.
const KEYRING_EXTENSION: &str = "keyring";

/// On-disk format of a keyring file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyringFormat {
    /// Encrypted binary v0 file.
    BinaryV0,
    /// Plaintext GLib key file (secrets are readable on disk).
    Textual,
    /// Not recognized, or unreadable.
    Unknown,
}

/// Summary of one keyring file.
#[derive(Clone, Debug)]
pub struct KeyringFileInfo {
    /// Full path of the file.
    pub path: PathBuf,
    /// File name without extension.
    pub name: String,
    /// Detected format.
    pub format: KeyringFormat,
    /// File size in bytes.
    pub size: u64,
    /// File modification time, unix seconds.
    pub modified: u64,
    /// Keyring label (textual files only for now).
    pub display_name: Option<String>,
    /// Number of items (textual files only).
    pub item_count: Option<usize>,
    /// Whether gnome-keyring can read the file (textual files only).
    pub daemon_readable: Option<bool>,
    /// True when the file stores secrets in plaintext.
    pub plaintext: bool,
}

/// Detects the format of a keyring file from its content.
///
/// Binary v0 files start with [`BINARY_MAGIC`]. A file is textual when its
/// first non-empty line is `[keyring]`; anything else is `Unknown`.
pub fn detect_format(bytes: &[u8]) -> KeyringFormat {
    if bytes.starts_with(BINARY_MAGIC) {
        return KeyringFormat::BinaryV0;
    }
    let first = bytes
        .split(|b| *b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .map(|line| line.trim_ascii())
        .find(|line| !line.is_empty());
    match first {
        Some(line) if line == TEXTUAL_HEADER => KeyringFormat::Textual,
        _ => KeyringFormat::Unknown,
    }
}

/// Builds the info entry for one file; unreadable files become `Unknown`.
fn file_info(path: &Path) -> KeyringFileInfo {
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let meta = std::fs::metadata(path).ok();
    let mut info = KeyringFileInfo {
        path: path.to_path_buf(),
        name,
        format: KeyringFormat::Unknown,
        size: meta.as_ref().map_or(0, |m| m.len()),
        modified: meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs()),
        display_name: None,
        item_count: None,
        daemon_readable: None,
        plaintext: false,
    };
    let Ok(bytes) = std::fs::read(path).map(Zeroizing::new) else {
        return info;
    };
    info.format = detect_format(&bytes);
    if info.format != KeyringFormat::Textual {
        return info;
    }
    match parse_textual(&bytes) {
        Ok(parsed) => {
            info.display_name = parsed.display_name.clone();
            info.item_count = Some(parsed.items.len());
            info.daemon_readable = Some(parsed.daemon_readable);
            info.plaintext = true;
        }
        Err(_) => info.format = KeyringFormat::Unknown,
    }
    info
}

/// Lists the `*.keyring` files of `dir`, sorted by name.
///
/// A missing directory gives an empty list. A file that cannot be read is
/// listed with [`KeyringFormat::Unknown`].
pub fn scan_dir(dir: &Path) -> Result<Vec<KeyringFileInfo>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(KringError::Io {
                path: dir.to_path_buf(),
                message: e.to_string(),
            });
        }
    };
    let mut infos: Vec<KeyringFileInfo> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == KEYRING_EXTENSION))
        .map(|p| file_info(&p))
        .collect();
    infos.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(infos)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Directory with the synthetic fixtures.
    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keyrings")
    }

    /// The binary magic is recognized.
    #[test]
    fn detect_binary_magic() {
        let mut bytes = BINARY_MAGIC.to_vec();
        bytes.extend_from_slice(&[1, 2, 3]);
        assert_eq!(detect_format(&bytes), KeyringFormat::BinaryV0);
    }

    /// A leading `[keyring]` line (after blanks) means textual.
    #[test]
    fn detect_textual() {
        assert_eq!(detect_format(b"[keyring]\nx=y\n"), KeyringFormat::Textual);
        assert_eq!(detect_format(b"\n\n[keyring]\r\n"), KeyringFormat::Textual);
    }

    /// Anything else is unknown.
    #[test]
    fn detect_garbage_unknown() {
        assert_eq!(detect_format(b"hello\n"), KeyringFormat::Unknown);
        assert_eq!(detect_format(b""), KeyringFormat::Unknown);
        assert_eq!(detect_format(&[0xff, 0x00]), KeyringFormat::Unknown);
        assert_eq!(detect_format(b"[other]\n"), KeyringFormat::Unknown);
    }

    /// The fixture directory is scanned into sorted, classified entries.
    #[test]
    fn scan_fixture_dir() {
        let infos = scan_dir(&fixture_dir()).unwrap();
        let summary: Vec<_> = infos
            .iter()
            .map(|i| {
                (
                    i.name.as_str(),
                    i.format,
                    i.item_count,
                    i.daemon_readable,
                    i.plaintext,
                )
            })
            .collect();
        use KeyringFormat::{Textual, Unknown};
        assert_eq!(
            summary,
            vec![
                ("empty_textual", Textual, Some(0), Some(true), true),
                ("garbage", Unknown, None, None, false),
                ("textual_binary_secret", Textual, Some(1), Some(true), true),
                (
                    "textual_multiline_secret",
                    Textual,
                    Some(1),
                    Some(false),
                    true
                ),
                ("textual_two_items", Textual, Some(2), Some(true), true),
            ]
        );
        assert_eq!(infos[3].display_name.as_deref(), Some("Multiline"));
        assert!(infos[0].size > 0);
    }

    /// A missing directory is an empty list; non-keyring files are skipped.
    #[test]
    fn scan_missing_and_filtering() {
        let dir = tempfile::tempdir().unwrap();
        assert!(scan_dir(&dir.path().join("nope")).unwrap().is_empty());
        std::fs::write(dir.path().join("a.txt"), "[keyring]\n").unwrap();
        let mut bin = BINARY_MAGIC.to_vec();
        bin.push(0);
        std::fs::write(dir.path().join("b.keyring"), bin).unwrap();
        let infos = scan_dir(dir.path()).unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].format, KeyringFormat::BinaryV0);
        assert!(!infos[0].plaintext);
    }
}
