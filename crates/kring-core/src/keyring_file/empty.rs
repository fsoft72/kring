//! Removing an empty textual keyring file without a backup: it holds no
//! secrets, so there is nothing to back up.
//!
//! Emptiness is never taken from the caller: the bytes on disk are parsed
//! right before the unlink and any item (or a parse failure) refuses the
//! removal, so the caller falls back to its backup path.

use std::path::Path;

use zeroize::Zeroizing;

use super::retire::{RetireMode, check_location, check_unchanged, invalid, retire_mode};
use super::scan::{KeyringFileInfo, KeyringFormat, detect_format};
use super::textual::parse_textual;
use crate::backup::io_err;
use crate::error::Result;
use crate::model::CollectionInfo;

/// Refusal of an empty-file removal when the file holds items (or cannot be parsed).
pub const MSG_NOT_EMPTY: &str = "Keyring file is not empty, rescan first";
/// Refusal of an empty-file removal for a file the daemon serves.
const MSG_LIVE: &str = "Keyring is live in the daemon, delete the collection instead";

/// Returns true when `bytes` are a textual keyring that parses without any item.
///
/// A binary or unknown file, or a textual one that fails to parse, is never
/// empty (its content is unknown).
pub fn is_empty_textual(bytes: &[u8]) -> bool {
    if detect_format(bytes) != KeyringFormat::Textual {
        return false;
    }
    parse_textual(bytes).is_ok_and(|parsed| parsed.items.is_empty())
}

/// Returns true when the scan says `info` is an empty textual file (a hint
/// for choosing [`remove_empty_file`]; the bytes are re-checked there).
pub fn scanned_empty(info: &KeyringFileInfo) -> bool {
    info.format == KeyringFormat::Textual && info.item_count == Some(0) && info.error.is_none()
}

/// Removes the empty textual keyring file `info` without any backup.
///
/// Preconditions, each failing with `InvalidInput`: the daemon does not
/// serve the file (re-checked against `live`); the path is a regular
/// `*.keyring` file (not a symlink) directly inside `keyrings_dir`; the file
/// is unchanged since the scan; the bytes on disk, read right before the
/// unlink, are a textual keyring without items ([`MSG_NOT_EMPTY`] otherwise,
/// fail closed). The size and mtime are checked once more after that read.
pub fn remove_empty_file(
    info: &KeyringFileInfo,
    keyrings_dir: &Path,
    live: &[CollectionInfo],
) -> Result<()> {
    if retire_mode(info, live) != RetireMode::DeleteFile {
        return Err(invalid(MSG_LIVE));
    }
    check_location(info, keyrings_dir)?;
    check_unchanged(info)?;
    unlink_if_empty(info)
}

/// Re-reads `info`, unlinks it only when it still parses without items and
/// is unchanged since the scan.
pub(super) fn unlink_if_empty(info: &KeyringFileInfo) -> Result<()> {
    let bytes = Zeroizing::new(std::fs::read(&info.path).map_err(|e| io_err(&info.path, e))?);
    if !is_empty_textual(&bytes) {
        return Err(invalid(MSG_NOT_EMPTY));
    }
    check_unchanged(info)?;
    std::fs::remove_file(&info.path).map_err(|e| io_err(&info.path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KringError;
    use crate::keyring_file::scan_dir;
    use crate::model::CollectionId;

    /// Textual keyring without items.
    const EMPTY: &str = "[keyring]\ndisplay-name=Test\nlock-on-idle=false\nlock-after=false\n";
    /// Textual keyring with one item.
    const ONE_ITEM: &str = "[keyring]\ndisplay-name=Test\n\n[1]\ndisplay-name=a\nsecret=s\n\
                            item-type=0\nctime=0\nmtime=0\n";

    /// Writes `content` as `file` in a temp keyrings dir and scans it.
    fn fixture(file: &str, content: &[u8]) -> (tempfile::TempDir, KeyringFileInfo) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keyrings");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join(file), content).unwrap();
        let info = scan_dir(&dir).unwrap().remove(0);
        (tmp, info)
    }

    /// Removes with the keyrings dir taken from the file's parent.
    fn remove(info: &KeyringFileInfo, live: &[CollectionInfo]) -> Result<()> {
        let dir = info.path.parent().unwrap().to_path_buf();
        remove_empty_file(info, &dir, live)
    }

    /// Only a textual keyring that parses without items is empty.
    #[test]
    fn empty_detection() {
        assert!(is_empty_textual(EMPTY.as_bytes()));
        assert!(!is_empty_textual(ONE_ITEM.as_bytes()));
        let mut bin = crate::backup::KEYRING_MAGIC.to_vec();
        bin.extend_from_slice(b"payload");
        assert!(!is_empty_textual(&bin));
        assert!(!is_empty_textual(b"garbage"));
        assert!(!is_empty_textual(b"[keyring]\n\xff\xfe"));
    }

    /// The scan hint needs a textual file with zero items.
    #[test]
    fn scanned_empty_rules() {
        let (_t, info) = fixture("e.keyring", EMPTY.as_bytes());
        assert!(scanned_empty(&info));
        let (_t, info) = fixture("f.keyring", ONE_ITEM.as_bytes());
        assert!(!scanned_empty(&info));
        let (_t, info) = fixture("g.keyring", b"garbage");
        assert!(!scanned_empty(&info));
    }

    /// An empty file is removed and no backup directory is made.
    #[test]
    fn removes_empty_file() {
        let (tmp, info) = fixture("e.keyring", EMPTY.as_bytes());
        remove(&info, &[]).unwrap();
        assert!(!info.path.exists());
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
    }

    /// A file with items is kept, also when the info was faked as empty.
    #[test]
    fn refuses_file_with_items() {
        let (_t, mut info) = fixture("f.keyring", ONE_ITEM.as_bytes());
        info.item_count = Some(0);
        let r = remove(&info, &[]);
        assert!(matches!(&r, Err(KringError::InvalidInput(m)) if m == MSG_NOT_EMPTY));
        assert!(info.path.exists());
    }

    /// A file that got items after the scan is kept (never unlinked).
    #[test]
    fn refuses_file_changed_since_scan() {
        let (_t, info) = fixture("c.keyring", EMPTY.as_bytes());
        std::fs::write(&info.path, ONE_ITEM).unwrap();
        assert!(remove(&info, &[]).is_err());
        assert!(info.path.exists());
    }

    /// Binary files and files served by the daemon are refused.
    #[test]
    fn refuses_binary_and_live() {
        let mut bin = crate::backup::KEYRING_MAGIC.to_vec();
        bin.extend_from_slice(b"payload");
        let (_t, info) = fixture("b.keyring", &bin);
        assert!(remove(&info, &[]).is_err());
        assert!(info.path.exists());

        let (_t, info) = fixture("l.keyring", EMPTY.as_bytes());
        let live = [CollectionInfo {
            id: CollectionId("/org/freedesktop/secrets/collection/l".into()),
            label: "l".into(),
            locked: false,
            item_count: 0,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        }];
        let r = remove(&info, &live);
        assert!(matches!(&r, Err(KringError::InvalidInput(m)) if m == MSG_LIVE));
        assert!(info.path.exists());
    }

    /// Files outside the keyrings dir are refused.
    #[test]
    fn refuses_outside_dir() {
        let (tmp, info) = fixture("a.keyring", EMPTY.as_bytes());
        let other = tmp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        assert!(remove_empty_file(&info, &other, &[]).is_err());
        assert!(info.path.exists());
    }
}
