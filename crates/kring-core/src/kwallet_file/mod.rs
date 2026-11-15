//! Offline reader for KWallet `.kwl` wallet files (no daemon involved).
//!
//! Mirrors the KWallet backend in `src/runtime/kwalletbackend` of
//! <https://invent.kde.org/frameworks/kwallet> (the code `ksecretd` uses):
//!
//! 1. [`format`]: magic and version bytes (`Backend::openInternal`,
//!    kwalletbackend.cc) and the clear-text MD5 hash block
//!    (`BlowfishPersistHandler::read`, backendpersisthandler.cpp).
//! 2. [`crypto`]: PBKDF2-SHA512 key (`password2PBKDF2_SHA512`, kwalletbackend.cc),
//!    Blowfish (blowfish.cc) in CBC mode (`CipherBlockChain::decrypt`, cbc.cc),
//!    random block + size + payload + digest layout (`BlowfishPersistHandler::read`),
//!    digest = KWallet's own SHA-1 variant (sha1.cc).
//! 3. [`parse`]: the `QDataStream` payload of folders and entries
//!    (`BlowfishPersistHandler::read`, `Entry::password`, kwalletentry.cc).
//!
//! Only modern wallets (version 0.1, Blowfish CBC, PBKDF2-SHA512) are
//! supported; other formats yield a clear `InvalidInput` naming the format.

mod crypto;
mod format;
mod parse;

pub use format::{WalletHeader, read_header};

use crate::error::{KringError, Result};
use crate::model::SecretValue;

/// Error message for a wallet whose integrity hash does not match the key.
pub const MSG_WRONG_PASSWORD: &str = "Wrong wallet password";

/// Value of one wallet entry (`KWallet::Wallet::EntryType`); secrets stay in [`SecretValue`].
#[derive(Clone, Debug)]
pub enum EntryValue {
    /// Type 1: a password (`text/plain`).
    Password(SecretValue),
    /// Type 3: a string map, sorted by key; values are `text/plain` secrets.
    Map(Vec<(String, SecretValue)>),
    /// Type 2: raw bytes (`application/octet-stream`).
    Stream(SecretValue),
    /// Any other type code; its value bytes are dropped.
    Unknown(u32),
}

/// One entry of a wallet: `<folder>/<key>` and its value.
#[derive(Clone, Debug)]
pub struct WalletEntry {
    /// Folder name.
    pub folder: String,
    /// Entry key inside the folder.
    pub key: String,
    /// Entry value.
    pub value: EntryValue,
}

/// Decrypts a wallet file and returns its entries in file order.
///
/// `kwl` is the `.kwl` file, `salt` the matching `.salt` file and `password`
/// the wallet password (UTF-8, as KWallet passes `QString::toUtf8()`).
/// A wrong password yields `InvalidInput("Wrong wallet password")` (detected
/// by the integrity hash, never by garbage items); an unsupported format
/// yields `InvalidInput` naming the format, before any key derivation.
pub fn open_wallet(kwl: &[u8], salt: &[u8], password: &SecretValue) -> Result<Vec<WalletEntry>> {
    read_header(kwl)?.ensure_supported()?;
    if salt.is_empty() {
        return Err(KringError::InvalidInput("Missing wallet salt".into()));
    }
    let key = crypto::derive_key(password, salt);
    decrypt_with_key(kwl, &key)
}

/// Opens a wallet with an already derived key (`Backend::openPreHashed` semantics).
///
/// Checks the header, skips the hash block, decrypts, verifies the
/// integrity hash and parses the payload; the decrypted buffer is zeroized.
fn decrypt_with_key(kwl: &[u8], key: &[u8]) -> Result<Vec<WalletEntry>> {
    read_header(kwl)?.ensure_supported()?;
    let body = format::encrypted_body(kwl)?;
    let plain = crypto::decrypt_payload(body, key)?;
    let payload = crypto::checked_payload(&plain)?;
    parse::parse_entries(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Password of the committed fixture wallet.
    const FIXTURE_PASSWORD: &str = "fixture-pw";

    /// Reads a file of the KWallet fixtures dir.
    fn _fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/kwallet")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    /// Returns the text of a text secret.
    fn _text(secret: &SecretValue) -> &str {
        secret.as_text().expect("text secret")
    }

    /// Returns the expected entry as `(folder, key, description)` for comparison.
    fn _describe(entry: &WalletEntry) -> (String, String, String) {
        let value = match &entry.value {
            EntryValue::Password(s) => format!("password {} {}", s.content_type, _text(s)),
            EntryValue::Map(pairs) => {
                let parts: Vec<String> = pairs
                    .iter()
                    .map(|(k, v)| format!("{k}={}:{}", v.content_type, _text(v)))
                    .collect();
                format!("map {}", parts.join(","))
            }
            EntryValue::Stream(s) => format!("stream {} {:02x?}", s.content_type, s.as_bytes()),
            EntryValue::Unknown(t) => format!("unknown {t}"),
        };
        (entry.folder.clone(), entry.key.clone(), value)
    }

    /// Returns the fixture bytes with one header byte replaced.
    fn _patched_header(offset: usize, value: u8) -> Vec<u8> {
        let mut kwl = _fixture("fixture.kwl");
        kwl[format::KWALLET_MAGIC.len() + offset] = value;
        kwl
    }

    /// Asserts that `result` is `InvalidInput` containing `needle`.
    fn _assert_invalid<T: std::fmt::Debug>(result: Result<T>, needle: &str) {
        match result {
            Err(KringError::InvalidInput(msg)) => {
                assert!(msg.contains(needle), "message {msg:?} lacks {needle:?}")
            }
            other => panic!("expected InvalidInput({needle}), got {other:?}"),
        }
    }

    /// The fixture opens with its password and yields exactly the Task 1 entries.
    #[test]
    fn fixture_opens_with_password() {
        let entries = open_wallet(
            &_fixture("fixture.kwl"),
            &_fixture("fixture.salt"),
            &SecretValue::from_text(FIXTURE_PASSWORD),
        )
        .expect("open fixture");
        let got: Vec<(String, String, String)> = entries.iter().map(_describe).collect();
        let expected = [
            (
                "Apps",
                "Fixture carol",
                "password text/plain fixture-secret-4",
            ),
            (
                "Maps",
                "form",
                "map pass=text/plain:fixture-secret-2,user=text/plain:alice",
            ),
            ("Passwords", "site", "password text/plain fixture-secret-1"),
            (
                "Secret Service",
                "Fixture bob",
                "password text/plain fixture-secret-3",
            ),
            (
                "Secret Service",
                "Fixture bob__0_",
                "password text/plain fixture-secret-5",
            ),
            (
                "Secret Service",
                "Fixture map",
                "map pass=text/plain:fixture-secret-6,user=text/plain:dave",
            ),
            (
                "Streams",
                "blob",
                "stream application/octet-stream [00, ff, 10]",
            ),
        ];
        let expected: Vec<(String, String, String)> = expected
            .iter()
            .map(|(f, k, v)| (f.to_string(), k.to_string(), v.to_string()))
            .collect();
        assert_eq!(got, expected);
    }

    /// A wrong password is detected by the integrity hash and yields no items.
    #[test]
    fn wrong_password_is_rejected() {
        let result = open_wallet(
            &_fixture("fixture.kwl"),
            &_fixture("fixture.salt"),
            &SecretValue::from_text("not-the-password"),
        );
        match result {
            Err(KringError::InvalidInput(msg)) => assert_eq!(msg, MSG_WRONG_PASSWORD),
            other => panic!("expected wrong password, got {other:?}"),
        }
    }

    /// The wrong salt is a wrong key too.
    #[test]
    fn wrong_salt_is_rejected() {
        let result = open_wallet(
            &_fixture("fixture.kwl"),
            &[7u8; 56],
            &SecretValue::from_text(FIXTURE_PASSWORD),
        );
        _assert_invalid(result, MSG_WRONG_PASSWORD);
    }

    /// The fixture header reads as version 0.1, Blowfish CBC, PBKDF2-SHA512.
    #[test]
    fn header_of_fixture() {
        let header = read_header(&_fixture("fixture.kwl")).expect("header");
        assert_eq!(
            header,
            WalletHeader {
                major: 0,
                minor: 1,
                cipher: 3,
                hash: 2
            }
        );
        assert!(header.is_supported());
    }

    /// Files without the magic or too short for a header are not wallets.
    #[test]
    fn header_rejects_non_wallets() {
        _assert_invalid(
            read_header(b"GnomeKeyring\n\r\0\n\0\0\0\0"),
            "Not a KWallet",
        );
        _assert_invalid(read_header(&_fixture("fixture.kwl")[..14]), "Not a KWallet");
        _assert_invalid(read_header(b""), "Not a KWallet");
    }

    /// Unsupported cipher, hash or version yield an error naming the format.
    #[test]
    fn unsupported_formats_are_named() {
        let salt = _fixture("fixture.salt");
        let password = SecretValue::from_text(FIXTURE_PASSWORD);
        let cases = [
            (2, 2, "cipher GPG"),
            (2, 0, "cipher Blowfish ECB"),
            (2, 1, "cipher 3DES CBC"),
            (2, 9, "cipher unknown (9)"),
            (3, 0, "hash SHA-1"),
            (3, 1, "hash MD5"),
            (1, 0, "version 0.0"),
            (0, 1, "version 1.1"),
        ];
        for (offset, value, needle) in cases {
            let kwl = _patched_header(offset, value);
            let result = open_wallet(&kwl, &salt, &password);
            _assert_invalid(result, "Unsupported wallet format");
            let result = open_wallet(&kwl, &salt, &password);
            _assert_invalid(result, needle);
            assert!(!read_header(&kwl).expect("header").is_supported());
        }
    }

    /// An empty salt cannot derive the PBKDF2 key.
    #[test]
    fn empty_salt_is_rejected() {
        let result = open_wallet(
            &_fixture("fixture.kwl"),
            &[],
            &SecretValue::from_text(FIXTURE_PASSWORD),
        );
        _assert_invalid(result, "salt");
    }

    /// Deterministic xorshift generator for garbage inputs.
    struct _XorShift(u64);

    impl _XorShift {
        /// Returns the next pseudo-random byte.
        fn byte(&mut self) -> u8 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 24) as u8
        }

        /// Returns `len` pseudo-random bytes.
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| self.byte()).collect()
        }
    }

    /// Truncated, bit-flipped and garbage wallets never panic; truncated ones never open.
    #[test]
    fn decrypting_garbage_never_panics() {
        let kwl = _fixture("fixture.kwl");
        let key = crypto::derive_key(
            &SecretValue::from_text(FIXTURE_PASSWORD),
            &_fixture("fixture.salt"),
        );
        assert!(decrypt_with_key(&kwl, &key).is_ok(), "full fixture opens");
        for len in 0..kwl.len() {
            let result = decrypt_with_key(&kwl[..len], &key);
            assert!(result.is_err(), "prefix of {len} bytes opened");
        }
        for pos in 0..kwl.len() {
            let mut flipped = kwl.clone();
            flipped[pos] ^= 0x5a;
            let _ = decrypt_with_key(&flipped, &key);
        }
        let mut rng = _XorShift(0x9e37_79b9_7f4a_7c15);
        let header = &kwl[..format::HEADER_LEN];
        for round in 0..2000 {
            let len = round % 300;
            let mut garbage = header.to_vec();
            garbage.extend(rng.bytes(len));
            let _ = decrypt_with_key(&garbage, &key);
            let _ = decrypt_with_key(&rng.bytes(len), &key);
        }
    }

    /// Truncated and garbage payloads never panic the structure parser.
    #[test]
    fn parsing_garbage_never_panics() {
        let kwl = _fixture("fixture.kwl");
        let key = crypto::derive_key(
            &SecretValue::from_text(FIXTURE_PASSWORD),
            &_fixture("fixture.salt"),
        );
        let body = format::encrypted_body(&kwl).expect("body");
        let plain = crypto::decrypt_payload(body, &key).expect("decrypt");
        let payload = crypto::checked_payload(&plain).expect("integrity");
        assert_eq!(parse::parse_entries(payload).expect("parse").len(), 7);
        for len in 0..payload.len() {
            let _ = parse::parse_entries(&payload[..len]);
        }
        let mut rng = _XorShift(0x2545_f491_4f6c_dd1d);
        for round in 0..5000 {
            let len = round % 200;
            let _ = parse::parse_entries(&rng.bytes(len));
            let mut mixed = payload[..len.min(payload.len())].to_vec();
            mixed.extend(rng.bytes(16));
            let _ = parse::parse_entries(&mixed);
        }
    }
}
