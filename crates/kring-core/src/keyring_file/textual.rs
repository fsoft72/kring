//! Tolerant parser for the textual (plaintext) gnome-keyring file format.
//!
//! The format is a GLib key file: `[keyring]` holds keyring metadata, `[N]`
//! groups are items and `[N:attributeM]` groups are item attributes. Strict
//! parsers (GLib, oo7) reject files where a `secret=` value contains raw
//! newlines. This parser recovers them.
//!
//! # Line rules
//!
//! - Empty lines and lines starting with `#` (after leading whitespace) are
//!   ignored.
//! - `[name]` is a group header.
//! - `key=value` is an entry only when the text before the first `=` is a valid
//!   GLib key: non-empty, `[A-Za-z0-9_-]+` optionally followed by `[locale]`,
//!   with no spaces (trailing whitespace before `=` is tolerated).
//! - Any other line is a continuation line: it is appended, with a `\n`
//!   separator and verbatim (leading whitespace kept), to the value of the last
//!   key of the current group, and a [`WarningKind::ContinuationLine`] is
//!   recorded.
//! - Empty lines between a key and a following continuation line are kept as
//!   empty lines of the value. Blank lines before a `key=` or `[group]` line
//!   are dropped.
//!
//! [`TextualKeyring::daemon_readable`] is false when any continuation line was
//! found (gnome-keyring would reject the file).

use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::error::{KringError, Result};
use crate::model::{Attributes, SecretValue};

/// Group name holding keyring metadata.
const KEYRING_GROUP: &str = "keyring";
/// Attribute holding the schema name.
const SCHEMA_ATTRIBUTE: &str = "xdg:schema";
/// Content type of `secret=` values.
const TEXT_CONTENT_TYPE: &str = "text/plain";
/// Content type of `binary-secret=` values.
const BINARY_CONTENT_TYPE: &str = "application/octet-stream";

/// An item read from a textual keyring file.
#[derive(Clone, Debug)]
pub struct OfflineItem {
    /// Item label (`display-name`).
    pub label: String,
    /// Item attributes, including `xdg:schema` when it can be derived.
    pub attributes: Attributes,
    /// The item secret.
    pub secret: SecretValue,
    /// Creation time, unix seconds (0 if unknown).
    pub created: u64,
    /// Modification time, unix seconds (0 if unknown).
    pub modified: u64,
    /// True when the file has no secret for this item (neither `secret` nor
    /// `binary-secret`); `secret` is then empty and the item is not imported.
    pub secret_missing: bool,
}

/// What kind of irregularity a [`ParseWarning`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WarningKind {
    /// A line was neither a group header nor `key=value`; joined to the previous value.
    ContinuationLine,
    /// A value contained an unknown or dangling escape sequence, kept literally.
    UnknownEscape,
    /// `binary-secret` was not valid hex; the secret is empty.
    BadBinarySecret,
    /// An item has neither `secret` nor `binary-secret`; the secret is empty.
    MissingSecret,
    /// A numeric field could not be parsed.
    BadNumber,
}

/// A recoverable irregularity found while parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseWarning {
    /// 1-based line number.
    pub line: usize,
    /// What went wrong.
    pub kind: WarningKind,
}

/// Result of parsing a textual keyring file.
#[derive(Debug)]
pub struct TextualKeyring {
    /// Keyring label (`display-name` of the `[keyring]` group).
    pub display_name: Option<String>,
    /// Items in file order.
    pub items: Vec<OfflineItem>,
    /// Recoverable irregularities.
    pub warnings: Vec<ParseWarning>,
    /// True when gnome-keyring's strict GLib parser would accept the file.
    pub daemon_readable: bool,
}

/// A raw value: the still escaped text after `key=` plus verbatim continuation lines.
struct RawValue {
    first: Zeroizing<String>,
    continuation: Vec<Zeroizing<String>>,
    line: usize,
}

/// A parsed group: entries by key, plus the last key for continuations.
#[derive(Default)]
struct Group {
    /// Line of the group header.
    line: usize,
    entries: HashMap<String, RawValue>,
    last_key: Option<String>,
}

/// Returns true if `key` is a valid GLib key: `[A-Za-z0-9_-]+` with an optional `[locale]`.
fn is_valid_key(key: &str) -> bool {
    let name = match key.split_once('[') {
        Some((name, locale)) => {
            if !locale.ends_with(']') || locale.len() < 2 {
                return false;
            }
            name
        }
        None => key,
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Returns the group name when `line` is a `[group]` header.
fn parse_group_header(line: &str) -> Option<&str> {
    let (name, rest) = line.strip_prefix('[')?.split_once(']')?;
    rest.trim_matches([' ', '\t']).is_empty().then_some(name)
}

/// Decodes GLib escapes (`\n \t \r \\ \s`). Returns the text and whether an
/// unknown or dangling escape was kept literally.
fn unescape(raw: &str) -> (Zeroizing<String>, bool) {
    let mut out = Zeroizing::new(String::with_capacity(raw.len()));
    let mut unknown = false;
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('s') => out.push(' '),
            Some('\\') => out.push('\\'),
            Some(other) => {
                unknown = true;
                out.push('\\');
                out.push(other);
            }
            None => {
                unknown = true;
                out.push('\\');
            }
        }
    }
    (out, unknown)
}

/// Maps a gnome-keyring `item-type` to its schema name.
fn item_type_schema(item_type: u32) -> Option<&'static str> {
    match item_type {
        0 => Some("org.freedesktop.Secret.Generic"),
        1 => Some("org.gnome.keyring.NetworkPassword"),
        2 => Some("org.gnome.keyring.Note"),
        3 => Some("org.gnome.keyring.ChainedKeyring"),
        4 => Some("org.gnome.keyring.EncryptionKey"),
        0x100 => Some("org.gnome.keyring.PkStorage"),
        _ => None,
    }
}

/// Splits the file into ordered groups, recording continuation warnings.
fn read_groups(
    content: &str,
    warnings: &mut Vec<ParseWarning>,
    daemon_readable: &mut bool,
) -> Result<Vec<(String, Group)>> {
    let mut groups: Vec<(String, Group)> = Vec::new();
    let mut current: Option<usize> = None;
    let mut pending_blank = 0usize;
    for (index, line) in content.split('\n').enumerate() {
        let number = index + 1;
        let line = line.strip_suffix('\r').unwrap_or(line);
        let trimmed = line.trim_start_matches([' ', '\t']);
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.is_empty() {
            pending_blank += 1;
            continue;
        }
        let blanks = std::mem::take(&mut pending_blank);
        if let Some(name) = parse_group_header(trimmed) {
            if groups.is_empty() && name != KEYRING_GROUP {
                return Err(KringError::InvalidInput(
                    "not a textual keyring: first group is not [keyring]".into(),
                ));
            }
            // Duplicated groups are merged, like GLib does.
            let pos = match groups.iter().position(|(n, _)| n == name) {
                Some(pos) => pos,
                None => {
                    groups.push((
                        name.to_string(),
                        Group {
                            line: number,
                            ..Group::default()
                        },
                    ));
                    groups.len() - 1
                }
            };
            current = Some(pos);
            continue;
        }
        let Some(pos) = current else {
            return Err(KringError::InvalidInput(
                "not a textual keyring: content before the [keyring] group".into(),
            ));
        };
        let group = &mut groups[pos].1;
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim_end_matches([' ', '\t']);
            if is_valid_key(key) {
                let value = value.trim_start_matches([' ', '\t']);
                group.entries.insert(
                    key.to_string(),
                    RawValue {
                        first: Zeroizing::new(value.to_string()),
                        continuation: Vec::new(),
                        line: number,
                    },
                );
                group.last_key = Some(key.to_string());
                continue;
            }
        }
        // Continuation line.
        warnings.push(ParseWarning {
            line: number,
            kind: WarningKind::ContinuationLine,
        });
        *daemon_readable = false;
        let Some(entry) = group
            .last_key
            .as_ref()
            .and_then(|key| group.entries.get_mut(key))
        else {
            continue;
        };
        for _ in 0..blanks {
            entry.continuation.push(Zeroizing::new(String::new()));
        }
        entry.continuation.push(Zeroizing::new(line.to_string()));
    }
    Ok(groups)
}

/// Returns the unescaped value of `key`, recording an escape warning if needed.
fn string_value(
    group: &Group,
    key: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Option<Zeroizing<String>> {
    let raw = group.entries.get(key)?;
    // Only the first physical line is GLib-escaped; continuation lines stay verbatim.
    let (first, unknown) = unescape(&raw.first);
    let extra: usize = raw.continuation.iter().map(|l| l.len() + 1).sum();
    let mut text = Zeroizing::new(String::with_capacity(first.len() + extra));
    text.push_str(&first);
    for line in &raw.continuation {
        text.push('\n');
        text.push_str(line);
    }
    if unknown {
        warnings.push(ParseWarning {
            line: raw.line,
            kind: WarningKind::UnknownEscape,
        });
    }
    Some(text)
}

/// Parses an unsigned number field; a present but invalid value warns and yields `None`.
fn number_value(group: &Group, key: &str, warnings: &mut Vec<ParseWarning>) -> Option<u64> {
    let raw = group.entries.get(key)?;
    let parsed = raw.first.trim().parse::<u64>().ok();
    if parsed.is_none() {
        warnings.push(ParseWarning {
            line: raw.line,
            kind: WarningKind::BadNumber,
        });
    }
    parsed
}

/// Builds the secret of an item from `secret` or `binary-secret`.
///
/// Returns the secret and whether the group had neither key.
fn read_secret(group: &Group, warnings: &mut Vec<ParseWarning>) -> (SecretValue, bool) {
    if let Some(text) = string_value(group, "secret", warnings) {
        return (
            SecretValue::new(text.as_bytes().to_vec(), TEXT_CONTENT_TYPE),
            false,
        );
    }
    let Some(raw) = group.entries.get("binary-secret") else {
        warnings.push(ParseWarning {
            line: group.line,
            kind: WarningKind::MissingSecret,
        });
        return (SecretValue::new(Vec::new(), BINARY_CONTENT_TYPE), true);
    };
    let secret = match hex::decode(raw.first.trim()) {
        Ok(bytes) => SecretValue::new(bytes, BINARY_CONTENT_TYPE),
        Err(_) => {
            warnings.push(ParseWarning {
                line: raw.line,
                kind: WarningKind::BadBinarySecret,
            });
            SecretValue::new(Vec::new(), BINARY_CONTENT_TYPE)
        }
    };
    (secret, false)
}

/// Builds the attributes of an item from its `[id:attributeN]` groups.
fn read_attributes(
    id: &str,
    group: &Group,
    all: &[(String, Group)],
    warnings: &mut Vec<ParseWarning>,
) -> Attributes {
    let prefix = format!("{id}:attribute");
    let mut attributes = Attributes::new();
    for (_, attr) in all.iter().filter(|(name, _)| name.starts_with(&prefix)) {
        let Some(name) = string_value(attr, "name", warnings) else {
            continue;
        };
        let is_uint = attr
            .entries
            .get("type")
            .is_some_and(|t| t.first.trim() == "uint32");
        if is_uint {
            // gnome-keyring reads a u64 and truncates it to u32.
            if let Some(number) = number_value(attr, "value", warnings) {
                attributes.insert((*name).clone(), (number as u32).to_string());
            }
            continue;
        }
        if let Some(value) = string_value(attr, "value", warnings) {
            attributes.insert((*name).clone(), (*value).clone());
        }
    }
    if !attributes.contains_key(SCHEMA_ATTRIBUTE) {
        let item_type = number_value(group, "item-type", warnings).unwrap_or(0);
        if let Some(schema) = item_type_schema(item_type as u32) {
            attributes.insert(SCHEMA_ATTRIBUTE.to_string(), schema.to_string());
        }
    }
    attributes
}

/// Parses a textual keyring file, recovering values that span several lines.
///
/// See the module documentation for the line rules. Fails with
/// [`KringError::InvalidInput`] when the bytes are not UTF-8 or do not start
/// with a `[keyring]` group.
pub fn parse_textual(bytes: &[u8]) -> Result<TextualKeyring> {
    let content = std::str::from_utf8(bytes)
        .map_err(|_| KringError::InvalidInput("keyring file is not valid UTF-8".into()))?;
    let mut warnings = Vec::new();
    let mut daemon_readable = true;
    let groups = read_groups(content, &mut warnings, &mut daemon_readable)?;

    let display_name = groups
        .iter()
        .find(|(name, _)| name == KEYRING_GROUP)
        .and_then(|(_, group)| string_value(group, "display-name", &mut warnings))
        .map(|name| (*name).clone());

    let mut items = Vec::new();
    for (id, group) in groups
        .iter()
        .filter(|(name, _)| name != KEYRING_GROUP && !name.contains(':'))
    {
        let label = string_value(group, "display-name", &mut warnings)
            .map(|l| (*l).clone())
            .unwrap_or_default();
        let attributes = read_attributes(id, group, &groups, &mut warnings);
        let (secret, secret_missing) = read_secret(group, &mut warnings);
        items.push(OfflineItem {
            label,
            attributes,
            secret,
            created: number_value(group, "ctime", &mut warnings).unwrap_or(0),
            modified: number_value(group, "mtime", &mut warnings).unwrap_or(0),
            secret_missing,
        });
    }
    warnings.sort_by_key(|w| w.line);
    Ok(TextualKeyring {
        display_name,
        items,
        warnings,
        daemon_readable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two plain items with attributes and times are read in file order.
    #[test]
    fn parses_two_items_with_attributes() {
        let text = "[keyring]\ndisplay-name=Test\nctime=1\nmtime=2\n\n\
[1]\ndisplay-name=First\nsecret=fixture-secret-1\nctime=10\nmtime=11\n\n\
[1:attribute0]\nname=user\ntype=string\nvalue=alice\n\n\
[2]\ndisplay-name=Second\nsecret=fixture-secret-2\n";
        let kr = parse_textual(text.as_bytes()).unwrap();
        assert_eq!(kr.display_name.as_deref(), Some("Test"));
        assert!(kr.daemon_readable);
        assert!(kr.warnings.is_empty());
        assert_eq!(kr.items.len(), 2);
        let first = &kr.items[0];
        assert_eq!(first.label, "First");
        assert_eq!(first.secret.as_text(), Some("fixture-secret-1"));
        assert_eq!(first.secret.content_type, "text/plain");
        assert_eq!((first.created, first.modified), (10, 11));
        assert_eq!(first.attributes["user"], "alice");
        assert!(!first.secret_missing);
        assert_eq!(kr.items[1].label, "Second");
        assert_eq!((kr.items[1].created, kr.items[1].modified), (0, 0));
    }

    /// A secret with raw newlines is recovered byte for byte.
    #[test]
    fn multiline_secret_recovered() {
        let text = "[keyring]\ndisplay-name=Default\n\n[1]\ndisplay-name=Multi\nsecret={\n  \"key\": \"a=b\",\n  \"other\": \"x\"\n}\nitem-type=0\nmtime=5\n";
        let kr = parse_textual(text.as_bytes()).unwrap();
        assert!(!kr.daemon_readable);
        assert_eq!(kr.items.len(), 1);
        assert_eq!(
            kr.items[0].secret.as_bytes(),
            b"{\n  \"key\": \"a=b\",\n  \"other\": \"x\"\n}"
        );
        assert_eq!(kr.items[0].modified, 5);
        let lines: Vec<usize> = kr.warnings.iter().map(|w| w.line).collect();
        assert_eq!(lines, vec![7, 8, 9]);
        assert!(
            kr.warnings
                .iter()
                .all(|w| w.kind == WarningKind::ContinuationLine)
        );
    }

    /// Blank lines inside a multi-line value are preserved.
    #[test]
    fn blank_line_inside_continuation_kept() {
        let text = "[keyring]\n\n[1]\nsecret=a\n\nb c\nitem-type=0\n";
        let kr = parse_textual(text.as_bytes()).unwrap();
        assert_eq!(kr.items[0].secret.as_text(), Some("a\n\nb c"));
    }

    /// Continuation lines are not unescaped and raise no escape warning.
    #[test]
    fn continuation_lines_stay_verbatim() {
        let text = "[keyring]\n\n[1]\nsecret=a\\sb\n  \"k\": \"q\\\"x\\ny\\\\z\"\nitem-type=0\n";
        let kr = parse_textual(text.as_bytes()).unwrap();
        assert_eq!(
            kr.items[0].secret.as_bytes(),
            b"a b\n  \"k\": \"q\\\"x\\ny\\\\z\""
        );
        assert_eq!(kr.warnings.len(), 1);
        assert_eq!(kr.warnings[0].kind, WarningKind::ContinuationLine);
    }

    /// The multiline fixture keeps its JSON `\"` escapes literally.
    #[test]
    fn multiline_fixture_keeps_json_quotes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/keyrings/textual_multiline_secret.keyring");
        let kr = parse_textual(&std::fs::read(path).unwrap()).unwrap();
        let text = kr.items[0].secret.as_text().unwrap().to_string();
        assert!(text.contains("\"quote\": \"say \\\"hi\\\"\""));
        assert!(
            kr.warnings
                .iter()
                .all(|w| w.kind == WarningKind::ContinuationLine)
        );
    }

    /// CRLF line endings are handled, comments ignored, locale keys accepted.
    #[test]
    fn crlf_comment_and_locale_key() {
        let text = "[keyring]\r\ndisplay-name=K\r\n# comment\r\n\r\n[1]\r\ndisplay-name[it]=Ciao\r\nsecret=s\r\n";
        let kr = parse_textual(text.as_bytes()).unwrap();
        assert!(kr.daemon_readable);
        assert!(kr.warnings.is_empty());
        assert_eq!(kr.display_name.as_deref(), Some("K"));
        assert_eq!(kr.items[0].secret.as_text(), Some("s"));
        assert!(kr.items[0].label.is_empty());
    }

    /// A continuation line before any key of a group is dropped with a warning.
    #[test]
    fn continuation_before_any_key_dropped() {
        let kr = parse_textual(b"[keyring]\nstray line\n\n[1]\nsecret=x\n").unwrap();
        assert!(!kr.daemon_readable);
        assert_eq!(
            kr.warnings,
            vec![ParseWarning {
                line: 2,
                kind: WarningKind::ContinuationLine
            }]
        );
        assert_eq!(kr.items[0].secret.as_text(), Some("x"));
    }

    /// A line with a space in the key is a continuation line, not an entry.
    #[test]
    fn key_with_space_is_continuation() {
        let kr = parse_textual(b"[keyring]\n\n[1]\nsecret=a\nfoo bar=baz\n").unwrap();
        assert_eq!(kr.items[0].secret.as_text(), Some("a\nfoo bar=baz"));
        assert!(!kr.daemon_readable);
    }

    /// A group without entries warns at its header line.
    #[test]
    fn empty_group_missing_secret_points_at_header() {
        let kr = parse_textual(b"[keyring]\n\n[7]\n").unwrap();
        assert_eq!(
            kr.warnings,
            vec![ParseWarning {
                line: 3,
                kind: WarningKind::MissingSecret
            }]
        );
    }

    /// Prefixes of the fixtures, tricky inputs and pseudo-random bytes never panic.
    #[test]
    fn never_panics() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keyrings");
        for entry in std::fs::read_dir(dir).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            for end in 0..=bytes.len() {
                let _ = parse_textual(&bytes[..end]);
            }
        }
        let tricky: [&[u8]; 9] = [
            "[keyring]\n\u{e9}[=\\]\u{20ac}\n".as_bytes(),
            "[keyring]\n[1]\nsecret=\u{1f600}\\\n".as_bytes(),
            b"[keyring]\n[1]\nsecret=\\",
            b"[keyring",
            b"[keyring]\r\n[1]\r\nsecret=a\r\nb\r\n",
            b"[keyring]\n[1\n=x\n[]\n[1]]\n",
            b"[keyring]\n[1:attribute0]\nname=\\\ntype=uint32\nvalue=99999999999999999999999\n",
            b"[",
            b"",
        ];
        for input in tricky {
            let _ = parse_textual(input);
        }
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        for _ in 0..256 {
            let mut buf = b"[keyring]\n[1]\n".to_vec();
            for _ in 0..(state % 64) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                buf.push((state & 0xff) as u8);
            }
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let _ = parse_textual(&buf);
            let _ = parse_textual(&buf[10..]);
        }
    }

    /// GLib escapes are decoded; unknown ones stay literal and warn.
    #[test]
    fn glib_escapes_decoded() {
        let text = "[keyring]\n\n[1]\ndisplay-name=a\\tb\nsecret=l1\\nl2\\\\x\\sy\\q\n";
        let kr = parse_textual(text.as_bytes()).unwrap();
        assert_eq!(kr.items[0].label, "a\tb");
        assert_eq!(kr.items[0].secret.as_text(), Some("l1\nl2\\x y\\q"));
        assert_eq!(
            kr.warnings,
            vec![ParseWarning {
                line: 5,
                kind: WarningKind::UnknownEscape
            }]
        );
        assert!(kr.daemon_readable);
    }

    /// `binary-secret` is hex decoded; bad hex warns and gives an empty secret.
    #[test]
    fn binary_secret_hex() {
        let text = "[keyring]\n\n[1]\nbinary-secret=00ff10\n\n[2]\nbinary-secret=zz\n\n[3]\ndisplay-name=none\n";
        let kr = parse_textual(text.as_bytes()).unwrap();
        assert_eq!(kr.items[0].secret.as_bytes(), &[0x00, 0xff, 0x10]);
        assert_eq!(kr.items[0].secret.content_type, "application/octet-stream");
        assert!(kr.items[1].secret.is_empty());
        assert!(kr.items[2].secret.is_empty());
        // Bad hex still had a secret line; only the third item has none.
        let missing: Vec<bool> = kr.items.iter().map(|i| i.secret_missing).collect();
        assert_eq!(missing, [false, false, true]);
        let kinds: Vec<WarningKind> = kr.warnings.iter().map(|w| w.kind).collect();
        assert_eq!(
            kinds,
            vec![WarningKind::BadBinarySecret, WarningKind::MissingSecret]
        );
    }

    /// `uint32` attributes are truncated to 32 bits.
    #[test]
    fn uint32_attribute_truncated() {
        let text = "[keyring]\n\n[1]\nsecret=x\n\n[1:attribute0]\nname=port\ntype=uint32\nvalue=4294967301\n";
        let kr = parse_textual(text.as_bytes()).unwrap();
        assert_eq!(kr.items[0].attributes["port"], "5");
    }

    /// `xdg:schema` is derived from `item-type` unless already present.
    #[test]
    fn schema_from_item_type() {
        let text = "[keyring]\n\n[1]\nsecret=x\nitem-type=2\n\n[2]\nsecret=y\nitem-type=1\n\n\
[2:attribute0]\nname=xdg:schema\ntype=string\nvalue=custom.Schema\n\n[3]\nsecret=z\nitem-type=999\n";
        let kr = parse_textual(text.as_bytes()).unwrap();
        assert_eq!(
            kr.items[0].attributes[SCHEMA_ATTRIBUTE],
            "org.gnome.keyring.Note"
        );
        assert_eq!(kr.items[1].attributes[SCHEMA_ATTRIBUTE], "custom.Schema");
        assert!(!kr.items[2].attributes.contains_key(SCHEMA_ATTRIBUTE));
    }

    /// Non-UTF-8 input and non-keyring text are rejected.
    #[test]
    fn non_utf8_rejected() {
        assert!(matches!(
            parse_textual(&[0xff, 0xfe, b'[']),
            Err(KringError::InvalidInput(_))
        ));
        assert!(parse_textual(b"[other]\nfoo=bar\n").is_err());
        assert!(parse_textual(b"hello\n").is_err());
    }

    /// Bad `ctime` warns and falls back to 0.
    #[test]
    fn bad_number_warns() {
        let kr = parse_textual(b"[keyring]\n\n[1]\nsecret=x\nctime=abc\n").unwrap();
        assert_eq!(kr.items[0].created, 0);
        assert_eq!(kr.warnings[0].kind, WarningKind::BadNumber);
    }
}
