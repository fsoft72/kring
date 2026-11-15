//! Reader for the Secret Service compat layer metadata `<wallet>_attributes.json`.
//!
//! Written by `KWalletFreedesktopAttributes` in `src/runtime/ksecretd` of
//! <https://invent.kde.org/frameworks/kwallet>: a flat JSON object with the
//! wallet metadata (`$fdo_created`, `$fdo_modified`) and one key per entry,
//! `"<folder>/<key>"`, split at the first `/` (a folder never contains `/`,
//! a key may). Each entry object holds `$fdo_created`, `$fdo_modified`
//! (decimal strings, unix seconds), optionally `$fdo_mime_type`, and an
//! `attributes` string map (omitted when empty). Unknown fields are ignored.

use std::collections::HashMap;

use serde_json::Value;

use crate::error::{KringError, Result};
use crate::model::Attributes;

/// Prefix of the metadata fields of the JSON (`$fdo_created`, ...).
const FDO_FIELD_PREFIX: &str = "$fdo_";
/// Entry field holding the creation time.
const FIELD_CREATED: &str = "$fdo_created";
/// Entry field holding the modification time.
const FIELD_MODIFIED: &str = "$fdo_modified";
/// Entry field holding the content type of the secret.
const FIELD_MIME_TYPE: &str = "$fdo_mime_type";
/// Entry field holding the attribute map.
const FIELD_ATTRIBUTES: &str = "attributes";

/// Secret Service metadata the compat layer keeps for one wallet entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FdoMeta {
    /// Item attributes as stored by the compat layer.
    pub attributes: Attributes,
    /// Creation time, unix seconds (0 when missing).
    pub created: u64,
    /// Last modification time, unix seconds (0 when missing).
    pub modified: u64,
    /// Content type of the secret (`$fdo_mime_type`), when the record has one.
    pub mime_type: Option<String>,
}

/// Parses an attributes JSON into metadata keyed by `(folder, key)`.
///
/// Empty (or whitespace only) input, as for a wallet without the file, gives
/// an empty map. Top-level `$fdo_*` fields, keys without `/`, non-object
/// records and non-string attribute values are ignored. Invalid JSON or a
/// non-object root is `InvalidInput`.
pub fn read_attributes(json: &[u8]) -> Result<HashMap<(String, String), FdoMeta>> {
    let mut out = HashMap::new();
    if json.iter().all(u8::is_ascii_whitespace) {
        return Ok(out);
    }
    let root: Value = serde_json::from_slice(json)
        .map_err(|e| KringError::InvalidInput(format!("Invalid wallet attributes JSON: {e}")))?;
    let Value::Object(root) = root else {
        return Err(KringError::InvalidInput(
            "Invalid wallet attributes JSON: not an object".into(),
        ));
    };
    for (name, record) in &root {
        if name.starts_with(FDO_FIELD_PREFIX) {
            continue;
        }
        let (Some((folder, key)), Value::Object(record)) = (name.split_once('/'), record) else {
            continue;
        };
        let attributes = match record.get(FIELD_ATTRIBUTES) {
            Some(Value::Object(map)) => map
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect(),
            _ => Attributes::new(),
        };
        let meta = FdoMeta {
            attributes,
            created: _seconds(record.get(FIELD_CREATED)),
            modified: _seconds(record.get(FIELD_MODIFIED)),
            mime_type: record
                .get(FIELD_MIME_TYPE)
                .and_then(Value::as_str)
                .filter(|m| !m.is_empty())
                .map(str::to_string),
        };
        out.insert((folder.to_string(), key.to_string()), meta);
    }
    Ok(out)
}

/// Reads a unix time given as decimal string or number; anything else is 0.
fn _seconds(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Key of a map entry.
    fn _k(folder: &str, key: &str) -> (String, String) {
        (folder.to_string(), key.to_string())
    }

    /// The fixture JSON yields the five records with exact attributes and dates.
    #[test]
    fn fixture_attributes_are_read() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/kwallet/fixture_attributes.json");
        let meta = read_attributes(&std::fs::read(path).expect("read")).expect("parse");
        assert_eq!(meta.len(), 5);
        let bob = &meta[&_k("Secret Service", "Fixture bob")];
        assert_eq!(bob.created, 1794752450);
        assert_eq!(bob.modified, 1794752450);
        let want: Attributes = [("service", "fixture"), ("user", "bob")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(bob.attributes, want);
        assert_eq!(bob.mime_type.as_deref(), Some("text/plain"));
        assert!(meta.contains_key(&_k("Streams", "blob")));
        assert!(meta.contains_key(&_k("Secret Service", "Fixture bob__0_")));
    }

    /// Keys split at the first slash; odd records and fields are tolerated.
    #[test]
    fn tolerant_parsing() {
        let json = br#"{"$fdo_created":"1","x":"y","noslash":{},"F/a/b":{"$fdo_modified":7,
            "extra":1,"attributes":{"k":"v","n":3}},"F/c":5,"G/d":{"$fdo_created":"bad"},
            "H/e":{"$fdo_mime_type":"image/png"},"H/f":{"$fdo_mime_type":5}}"#;
        let meta = read_attributes(json).expect("parse");
        assert_eq!(meta.len(), 4);
        assert_eq!(meta[&_k("H", "e")].mime_type.as_deref(), Some("image/png"));
        assert_eq!(meta[&_k("H", "f")].mime_type, None);
        let ab = &meta[&_k("F", "a/b")];
        assert_eq!((ab.created, ab.modified), (0, 7));
        assert_eq!(ab.attributes.len(), 1);
        assert_eq!(ab.attributes["k"], "v");
        assert_eq!(meta[&_k("G", "d")], FdoMeta::default());
    }

    /// Missing file (empty input) is an empty map; broken JSON is an error.
    #[test]
    fn empty_and_invalid_input() {
        assert!(read_attributes(b"").expect("empty").is_empty());
        assert!(read_attributes(b" \n").expect("blank").is_empty());
        assert!(matches!(
            read_attributes(b"{oops"),
            Err(KringError::InvalidInput(_))
        ));
        assert!(matches!(
            read_attributes(b"[]"),
            Err(KringError::InvalidInput(_))
        ));
    }
}
