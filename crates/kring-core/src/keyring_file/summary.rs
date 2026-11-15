//! Privacy-safe per-file summaries of keyring files, for dry runs on real data.
//!
//! [`FileSummary`] has no field able to hold a label, attribute or secret: the
//! parse result is reduced to counts and dropped immediately.

use std::collections::BTreeMap;
use std::path::Path;

use zeroize::Zeroizing;

use super::scan::{KeyringFormat, detect_format};
use super::textual::parse_textual;
use crate::error::{KringError, Result};

/// File extension of keyring files.
const KEYRING_EXTENSION: &str = "keyring";

/// Counts-only summary of one keyring file (never any file content).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileSummary {
    /// File name (like `Default_keyring_3.keyring`).
    pub name: String,
    /// Detected format.
    pub format: KeyringFormat,
    /// File size in bytes.
    pub size: u64,
    /// Number of items (textual files only).
    pub item_count: Option<usize>,
    /// Whether gnome-keyring's strict parser accepts the file (textual files only).
    pub daemon_readable: Option<bool>,
    /// Warning counts by kind name.
    pub warnings: BTreeMap<String, usize>,
}

impl FileSummary {
    /// Renders the summary as one line with counts only.
    pub fn render(&self) -> String {
        let item_count = self
            .item_count
            .map_or_else(|| "-".to_string(), |n| n.to_string());
        let readable = self
            .daemon_readable
            .map_or_else(|| "-".to_string(), |b| b.to_string());
        let warnings = self
            .warnings
            .iter()
            .map(|(kind, n)| format!("{kind}={n}"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{} format={:?} size={} items={} daemon_readable={} warnings=[{}]",
            self.name, self.format, self.size, item_count, readable, warnings
        )
    }
}

/// Summarizes raw file bytes; the parsed items are dropped before returning.
pub fn summarize_bytes(name: &str, bytes: &[u8]) -> FileSummary {
    let format = detect_format(bytes);
    let mut summary = FileSummary {
        name: name.to_string(),
        format,
        size: bytes.len() as u64,
        item_count: None,
        daemon_readable: None,
        warnings: BTreeMap::new(),
    };
    if format != KeyringFormat::Textual {
        return summary;
    }
    let Ok(parsed) = parse_textual(bytes) else {
        summary.format = KeyringFormat::Unknown;
        return summary;
    };
    summary.item_count = Some(parsed.items.len());
    summary.daemon_readable = Some(parsed.daemon_readable);
    for warning in &parsed.warnings {
        *summary
            .warnings
            .entry(format!("{:?}", warning.kind))
            .or_default() += 1;
    }
    summary
}

/// Summarizes every `*.keyring` file of `dir` (read only), sorted by name.
///
/// A missing directory gives an empty list; an unreadable file is an error
/// naming the path.
pub fn summarize_dir(dir: &Path) -> Result<Vec<FileSummary>> {
    let io = |path: &Path, e: std::io::Error| KringError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io(dir, e)),
    };
    let mut summaries = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() || path.extension().is_none_or(|x| x != KEYRING_EXTENSION) {
            continue;
        }
        // The bytes hold plaintext secrets: wiped when dropped.
        let bytes = Zeroizing::new(std::fs::read(&path).map_err(|e| io(&path, e))?);
        let name = entry.file_name().to_string_lossy().into_owned();
        summaries.push(summarize_bytes(&name, &bytes));
    }
    summaries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(summaries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Directory with the synthetic fixtures.
    fn fixture_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keyrings")
    }

    /// The rendered summaries contain counts only, never fixture content.
    #[test]
    fn rendered_summary_has_no_content() {
        let summaries = summarize_dir(&fixture_dir()).unwrap();
        assert_eq!(summaries.len(), 6);
        let rendered = summaries
            .iter()
            .map(FileSummary::render)
            .collect::<Vec<_>>()
            .join("\n");
        let debug = format!("{summaries:?}");
        for needle in [
            "fixture-secret",
            "JSON secret",
            "Multiline",
            "token",
            "00ff10fe",
            "attribute",
            "display-name",
        ] {
            assert!(!rendered.contains(needle), "rendered leaks {needle}");
            assert!(!debug.contains(needle), "debug leaks {needle}");
        }
        assert!(rendered.contains("textual_multiline_secret.keyring format=Textual"));
        assert!(rendered.contains("items=1 daemon_readable=false warnings=[ContinuationLine="));
    }

    /// Binary and garbage files have no item counts.
    #[test]
    fn binary_and_garbage_have_no_counts() {
        let summaries = summarize_dir(&fixture_dir()).unwrap();
        let by_name = |n: &str| summaries.iter().find(|s| s.name == n).unwrap();
        assert_eq!(by_name("binary_two_items.keyring").item_count, None);
        assert_eq!(by_name("garbage.keyring").format, KeyringFormat::Unknown);
        assert_eq!(by_name("empty_textual.keyring").item_count, Some(0));
    }
}
