//! `QDataStream` decoding of the decrypted wallet payload.
//!
//! Layout written by `BlowfishPersistHandler::write` and read by
//! `BlowfishPersistHandler::read` (backendpersisthandler.cpp), repeated until
//! the payload ends:
//!
//! ```text
//! QString folder, quint32 entry count,
//!   per entry: QString key, qint32 type, QByteArray value
//! ```
//!
//! All integers are big-endian (the `QDataStream` default). A `QString` is a
//! quint32 byte length (`0xffffffff` = null) followed by UTF-16BE code units;
//! a `QByteArray` is a quint32 length (`0xffffffff` = null) followed by the
//! bytes. Qt >= 6.7 writes `0xfffffffe` followed by a quint64 length for
//! sizes that do not fit 32 bits; that is accepted too.

use std::collections::BTreeMap;

use super::{EntryValue, WalletEntry};
use crate::error::{KringError, Result};
use crate::model::SecretValue;

/// `KWallet::Wallet::Password`.
const TYPE_PASSWORD: u32 = 1;
/// `KWallet::Wallet::Stream`.
const TYPE_STREAM: u32 = 2;
/// `KWallet::Wallet::Map`.
const TYPE_MAP: u32 = 3;
/// Length marking a null `QString` / `QByteArray`.
const NULL_SIZE: u32 = 0xffff_ffff;
/// Length announcing a following quint64 size (Qt >= 6.7).
const EXTENDED_SIZE: u32 = 0xffff_fffe;
/// Content type of password and map value secrets.
const TEXT_CONTENT_TYPE: &str = "text/plain";
/// Content type of stream secrets.
const BINARY_CONTENT_TYPE: &str = "application/octet-stream";

/// Big-endian `QDataStream` reader over a byte slice; every read is bounds checked.
pub(super) struct DataStream<'a> {
    /// Input bytes.
    buf: &'a [u8],
    /// Offset of the next unread byte.
    pos: usize,
}

impl<'a> DataStream<'a> {
    /// Creates a reader positioned at the start of `buf`.
    pub(super) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns true when every byte has been read (`QDataStream::atEnd`).
    pub(super) fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Returns the bytes not read yet.
    pub(super) fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos.min(self.buf.len())..]
    }

    /// Reads `len` raw bytes (`QDataStream::readRawData`).
    pub(super) fn raw(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let bytes = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(bytes)
    }

    /// Reads a big-endian quint32.
    pub(super) fn u32(&mut self) -> Option<u32> {
        let bytes = self.raw(4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a big-endian quint64.
    fn u64(&mut self) -> Option<u64> {
        let bytes = self.raw(8)?;
        let mut word = [0u8; 8];
        word.copy_from_slice(bytes);
        Some(u64::from_be_bytes(word))
    }

    /// Reads a `QString` / `QByteArray` size; `Some(None)` is a null value.
    fn size(&mut self) -> Option<Option<usize>> {
        let size = self.u32()?;
        if size == NULL_SIZE {
            return Some(None);
        }
        if size != EXTENDED_SIZE {
            return Some(Some(size as usize));
        }
        let wide = self.u64()?;
        Some(Some(usize::try_from(wide).ok()?))
    }

    /// Reads a `QByteArray`; a null array reads as empty.
    pub(super) fn byte_array(&mut self) -> Option<&'a [u8]> {
        match self.size()? {
            None => Some(&[]),
            Some(len) => self.raw(len),
        }
    }

    /// Reads a `QString` (null reads as empty); an odd byte length is corrupt.
    ///
    /// Unpaired surrogates become U+FFFD, as `QString::toUtf8` does.
    pub(super) fn string(&mut self) -> Option<String> {
        let Some(len) = self.size()? else {
            return Some(String::new());
        };
        if !len.is_multiple_of(2) {
            return None;
        }
        Some(_utf16be_to_string(self.raw(len)?))
    }
}

/// Decodes UTF-16BE into a string allocated once (no reallocated copies of secrets).
fn _utf16be_to_string(bytes: &[u8]) -> String {
    let (pairs, _) = bytes.as_chunks::<2>();
    let units = pairs.iter().map(|p| u16::from_be_bytes(*p));
    // A UTF-16 unit never needs more than 3 UTF-8 bytes.
    let mut text = String::with_capacity(bytes.len() / 2 * 3);
    for c in char::decode_utf16(units) {
        text.push(c.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    text
}

/// Builds the error for a malformed payload.
fn _corrupt(what: &str) -> KringError {
    KringError::InvalidInput(format!("Corrupt wallet data: {what}"))
}

/// Parses every folder and entry of a decrypted, integrity-checked payload.
///
/// Mirrors the `while (!eStream.atEnd())` loop of `BlowfishPersistHandler::read`.
/// Deviation: for an unknown entry type KWallet `continue`s without reading
/// the value, desynchronizing the stream, although `write` always stores it;
/// here the value is read and dropped, yielding [`EntryValue::Unknown`].
/// Any truncation or malformed value is an error (no partial result).
pub(super) fn parse_entries(payload: &[u8]) -> Result<Vec<WalletEntry>> {
    let mut stream = DataStream::new(payload);
    let mut entries = Vec::new();
    while !stream.at_end() {
        let folder = stream.string().ok_or_else(|| _corrupt("folder name"))?;
        let count = stream.u32().ok_or_else(|| _corrupt("entry count"))?;
        for _ in 0..count {
            entries.push(_parse_entry(&mut stream, &folder)?);
        }
    }
    Ok(entries)
}

/// Parses one `key, type, value` entry of `folder`.
fn _parse_entry(stream: &mut DataStream<'_>, folder: &str) -> Result<WalletEntry> {
    let key = stream
        .string()
        .ok_or_else(|| _corrupt(&format!("entry key in folder {folder:?}")))?;
    let location = format!("{folder}/{key}");
    let kind = stream
        .u32()
        .ok_or_else(|| _corrupt(&format!("type of {location:?}")))?;
    let bytes = stream
        .byte_array()
        .ok_or_else(|| _corrupt(&format!("value of {location:?}")))?;
    let value = match kind {
        TYPE_PASSWORD => EntryValue::Password(
            _decode_password(bytes).ok_or_else(|| _corrupt(&format!("password {location:?}")))?,
        ),
        TYPE_STREAM => EntryValue::Stream(SecretValue::new(bytes.to_vec(), BINARY_CONTENT_TYPE)),
        TYPE_MAP => EntryValue::Map(
            _decode_map(bytes).ok_or_else(|| _corrupt(&format!("map {location:?}")))?,
        ),
        other => EntryValue::Unknown(other),
    };
    Ok(WalletEntry {
        folder: folder.to_string(),
        key,
        value,
    })
}

/// Decodes a password value: a `QDataStream` `QString` (`Entry::password`, kwalletentry.cc).
///
/// An empty value is an empty password, as Qt reads a null string from it.
fn _decode_password(bytes: &[u8]) -> Option<SecretValue> {
    if bytes.is_empty() {
        return Some(SecretValue::new(Vec::new(), TEXT_CONTENT_TYPE));
    }
    let text = DataStream::new(bytes).string()?;
    Some(SecretValue::new(text.into_bytes(), TEXT_CONTENT_TYPE))
}

/// Decodes a map value: a `QDataStream` `QMap<QString,QString>` (quint32 count, key/value pairs).
///
/// Qt 5 wrote pairs in descending key order, Qt 6 ascending; the result is
/// sorted by key and a repeated key keeps its last value, as `QMap` does.
/// An empty value is an empty map.
fn _decode_map(bytes: &[u8]) -> Option<Vec<(String, SecretValue)>> {
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let mut stream = DataStream::new(bytes);
    let count = stream.u32()?;
    let mut map = BTreeMap::new();
    for _ in 0..count {
        let key = stream.string()?;
        let value = stream.string()?;
        map.insert(key, SecretValue::new(value.into_bytes(), TEXT_CONTENT_TYPE));
    }
    Some(map.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Appends a `QString` (quint32 byte length + UTF-16BE).
    fn _put_string(out: &mut Vec<u8>, text: &str) {
        let units: Vec<u16> = text.encode_utf16().collect();
        out.extend(((units.len() * 2) as u32).to_be_bytes());
        for unit in units {
            out.extend(unit.to_be_bytes());
        }
    }

    /// Appends a `QByteArray`.
    fn _put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend((bytes.len() as u32).to_be_bytes());
        out.extend(bytes);
    }

    /// Builds a payload with one folder holding the given `(key, type, value)` entries.
    fn _payload(folder: &str, entries: &[(&str, u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        _put_string(&mut out, folder);
        out.extend((entries.len() as u32).to_be_bytes());
        for (key, kind, value) in entries {
            _put_string(&mut out, key);
            out.extend(kind.to_be_bytes());
            _put_bytes(&mut out, value);
        }
        out
    }

    /// Unknown types are kept as `Unknown` and the following entries still parse.
    #[test]
    fn unknown_type_keeps_stream_in_sync() {
        let mut password = Vec::new();
        _put_string(&mut password, "pw");
        let payload = _payload("F", &[("odd", 7, vec![1, 2, 3]), ("next", 1, password)]);
        let entries = parse_entries(&payload).expect("parse");
        assert_eq!(entries.len(), 2);
        assert!(matches!(entries[0].value, EntryValue::Unknown(7)));
        match &entries[1].value {
            EntryValue::Password(s) => assert_eq!(s.as_text(), Some("pw")),
            other => panic!("expected password, got {other:?}"),
        }
    }

    /// Null strings and arrays read as empty values.
    #[test]
    fn null_values_read_as_empty() {
        let mut payload = Vec::new();
        _put_string(&mut payload, "F");
        payload.extend(2u32.to_be_bytes());
        payload.extend(NULL_SIZE.to_be_bytes()); // null key
        payload.extend(TYPE_PASSWORD.to_be_bytes());
        payload.extend(NULL_SIZE.to_be_bytes()); // null value
        _put_string(&mut payload, "m");
        payload.extend(TYPE_MAP.to_be_bytes());
        let mut map = Vec::new();
        map.extend(1u32.to_be_bytes());
        _put_string(&mut map, "k");
        map.extend(NULL_SIZE.to_be_bytes());
        _put_bytes(&mut payload, &map);
        let entries = parse_entries(&payload).expect("parse");
        assert_eq!(entries[0].key, "");
        assert!(matches!(&entries[0].value, EntryValue::Password(s) if s.is_empty()));
        match &entries[1].value {
            EntryValue::Map(pairs) => {
                assert_eq!(pairs.len(), 1);
                assert_eq!(pairs[0].0, "k");
                assert!(pairs[0].1.is_empty());
            }
            other => panic!("expected map, got {other:?}"),
        }
    }

    /// Map pairs written in descending order (Qt 5) come back sorted; last value wins.
    #[test]
    fn map_is_sorted_and_deduplicated() {
        let mut map = Vec::new();
        map.extend(3u32.to_be_bytes());
        for (k, v) in [("user", "u"), ("pass", "old"), ("pass", "new")] {
            _put_string(&mut map, k);
            _put_string(&mut map, v);
        }
        let pairs = _decode_map(&map).expect("map");
        let got: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_text().expect("text")))
            .collect();
        assert_eq!(got, [("pass", "new"), ("user", "u")]);
    }

    /// Non-BMP characters survive the UTF-16 surrogate decoding.
    #[test]
    fn utf16_surrogates_decode() {
        let mut out = Vec::new();
        _put_string(&mut out, "k\u{1f511}y");
        assert_eq!(
            DataStream::new(&out).string().as_deref(),
            Some("k\u{1f511}y")
        );
    }

    /// Truncated payloads and odd string lengths are errors naming the place.
    #[test]
    fn truncation_is_an_error() {
        let payload = _payload("F", &[("k", TYPE_STREAM, vec![1, 2, 3])]);
        for len in 1..payload.len() {
            assert!(parse_entries(&payload[..len]).is_err(), "prefix {len}");
        }
        let mut odd = Vec::new();
        odd.extend(3u32.to_be_bytes());
        odd.extend([0, 70, 0]);
        let err = parse_entries(&odd).expect_err("odd length");
        assert!(err.to_string().contains("folder name"), "{err}");
    }

    /// Huge declared sizes fail cleanly instead of allocating.
    #[test]
    fn huge_sizes_fail_cleanly() {
        let mut payload = Vec::new();
        payload.extend(EXTENDED_SIZE.to_be_bytes());
        payload.extend(u64::MAX.to_be_bytes());
        assert!(parse_entries(&payload).is_err());
        let mut payload = Vec::new();
        _put_string(&mut payload, "F");
        payload.extend(u32::MAX.to_be_bytes());
        assert!(parse_entries(&payload).is_err());
    }
}
