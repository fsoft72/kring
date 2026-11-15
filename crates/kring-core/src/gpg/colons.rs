//! Parser for GnuPG's machine readable `--with-colons` key listings.
//!
//! Field numbers follow GnuPG's `doc/DETAILS` (1-based): 1 record type, 2 validity,
//! 3 key length, 4 algorithm, 5 key id, 6 creation date, 7 expiration date,
//! 9 ownertrust (primary keys), 10 user id or fingerprint, 12 capabilities,
//! 15 token serial number (secret keys), 17 curve name. Dates are epoch seconds
//! (`--fixed-list-mode`). Unknown records and malformed fields are ignored; parsing
//! never panics.

use std::fmt;

/// Character used for an empty validity or trust field.
const NO_FLAG: char = '-';

/// Field 15 of a `sec`/`ssb` record: the secret key is available on disk.
const SECRET_AVAILABLE: &str = "+";

/// Field 15 of a `sec`/`ssb` record: the secret key is a stub (offline).
const SECRET_STUB: &str = "#";

/// OpenPGP public key algorithm of a key or subkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpgAlgorithm {
    /// RSA (algorithm 1, 2 or 3).
    Rsa,
    /// Elgamal (algorithm 16 or 20).
    Elgamal,
    /// DSA (algorithm 17).
    Dsa,
    /// ECDH (algorithm 18) on the named curve.
    Ecdh(String),
    /// ECDSA (algorithm 19) on the named curve.
    Ecdsa(String),
    /// EdDSA (algorithm 22) on the named curve.
    EdDsa(String),
    /// Any other algorithm number.
    Other(u32),
}

impl GpgAlgorithm {
    /// Maps an algorithm number and curve name (field 4 and 17) to an algorithm.
    pub fn from_fields(algo: &str, curve: &str) -> Self {
        let curve = curve.to_string();
        match algo.parse::<u32>().unwrap_or(0) {
            1..=3 => Self::Rsa,
            16 | 20 => Self::Elgamal,
            17 => Self::Dsa,
            18 => Self::Ecdh(curve),
            19 => Self::Ecdsa(curve),
            22 => Self::EdDsa(curve),
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for GpgAlgorithm {
    /// Short human name, e.g. `RSA`, `EdDSA ed25519`, `ECDH cv25519`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let with_curve = |f: &mut fmt::Formatter<'_>, name: &str, curve: &str| {
            if curve.is_empty() {
                return write!(f, "{name}");
            }
            write!(f, "{name} {curve}")
        };
        match self {
            Self::Rsa => write!(f, "RSA"),
            Self::Elgamal => write!(f, "Elgamal"),
            Self::Dsa => write!(f, "DSA"),
            Self::Ecdh(c) => with_curve(f, "ECDH", c),
            Self::Ecdsa(c) => with_curve(f, "ECDSA", c),
            Self::EdDsa(c) => with_curve(f, "EdDSA", c),
            Self::Other(n) => write!(f, "algorithm {n}"),
        }
    }
}

/// A user id of a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpgUid {
    /// The user id text (unescaped), e.g. `Name <mail@example.org>`.
    pub uid: String,
    /// Validity flag (field 2), e.g. `u` ultimate, `f` full, `r` revoked, `e` expired.
    pub validity: char,
}

/// A subkey of a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpgSubkey {
    /// Full fingerprint (upper case hex).
    pub fingerprint: String,
    /// Public key algorithm.
    pub algorithm: GpgAlgorithm,
    /// Key length in bits (255 for Curve25519 keys).
    pub bits: u32,
    /// Creation time (seconds since the epoch, 0 when unknown).
    pub created: u64,
    /// Expiration time (seconds since the epoch), `None` when it never expires.
    pub expires: Option<u64>,
    /// Capabilities (field 12), e.g. `e` or `s`.
    pub capabilities: String,
}

/// A primary key with its user ids and subkeys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpgKey {
    /// Full fingerprint of the primary key (upper case hex).
    pub fingerprint: String,
    /// Long key id (16 hex digits).
    pub key_id: String,
    /// Public key algorithm.
    pub algorithm: GpgAlgorithm,
    /// Key length in bits.
    pub bits: u32,
    /// Creation time (seconds since the epoch, 0 when unknown).
    pub created: u64,
    /// Expiration time (seconds since the epoch), `None` when it never expires.
    pub expires: Option<u64>,
    /// Validity flag (field 2).
    pub validity: char,
    /// Ownertrust flag (field 9).
    pub trust: char,
    /// Capabilities (field 12); upper case letters are those of the whole key.
    pub capabilities: String,
    /// User ids in listing order.
    pub uids: Vec<GpgUid>,
    /// Subkeys in listing order.
    pub subkeys: Vec<GpgSubkey>,
    /// True when the secret primary key or a secret subkey is available.
    pub secret: bool,
    /// True when the secret key or a secret subkey lives on a smartcard.
    pub card: bool,
}

/// What the last `fpr` record belongs to.
enum FprTarget {
    /// The current primary key.
    Primary,
    /// The last subkey of the current primary key.
    Subkey,
    /// Nothing that needs a fingerprint (e.g. no key yet).
    None,
}

/// Parses a colon listing (`--list-keys` or `--list-secret-keys`) into keys.
///
/// Keys from `sec` records have `secret` set. Keys without a fingerprint are dropped.
pub fn parse_listing(output: &[u8]) -> Vec<GpgKey> {
    let text = String::from_utf8_lossy(output);
    let mut keys: Vec<GpgKey> = Vec::new();
    let mut target = FprTarget::None;
    for line in text.lines() {
        let fields: Vec<&str> = line.trim_end_matches('\r').split(':').collect();
        let field = |n: usize| fields.get(n - 1).copied().unwrap_or("");
        match field(1) {
            kind @ ("pub" | "sec") => {
                keys.push(primary_from(&field, kind == "sec"));
                target = FprTarget::Primary;
            }
            kind @ ("sub" | "ssb") => {
                let Some(key) = keys.last_mut() else {
                    target = FprTarget::None;
                    continue;
                };
                if kind == "ssb" {
                    key.secret |= secret_available(field(15));
                    key.card |= on_card(field(15));
                }
                key.subkeys.push(subkey_from(&field));
                target = FprTarget::Subkey;
            }
            "uid" => {
                let Some(key) = keys.last_mut() else { continue };
                key.uids.push(GpgUid {
                    uid: unescape(field(10)),
                    validity: flag(field(2)),
                });
            }
            "fpr" => {
                let fpr = field(10).to_ascii_uppercase();
                let Some(key) = keys.last_mut() else { continue };
                match target {
                    FprTarget::Primary => key.fingerprint = fpr,
                    FprTarget::Subkey => {
                        if let Some(sub) = key.subkeys.last_mut() {
                            sub.fingerprint = fpr;
                        }
                    }
                    FprTarget::None => {}
                }
                target = FprTarget::None;
            }
            _ => {}
        }
    }
    keys.retain(|k| !k.fingerprint.is_empty());
    keys
}

/// Builds a primary key from a `pub`/`sec` record.
fn primary_from<'a>(field: &dyn Fn(usize) -> &'a str, is_secret: bool) -> GpgKey {
    GpgKey {
        fingerprint: String::new(),
        key_id: field(5).to_ascii_uppercase(),
        algorithm: GpgAlgorithm::from_fields(field(4), field(17)),
        bits: field(3).parse().unwrap_or(0),
        created: field(6).parse().unwrap_or(0),
        expires: expiry(field(7)),
        validity: flag(field(2)),
        trust: flag(field(9)),
        capabilities: field(12).to_string(),
        uids: Vec::new(),
        subkeys: Vec::new(),
        secret: is_secret && secret_available(field(15)),
        card: is_secret && on_card(field(15)),
    }
}

/// Builds a subkey from a `sub`/`ssb` record (fingerprint follows in `fpr`).
fn subkey_from<'a>(field: &dyn Fn(usize) -> &'a str) -> GpgSubkey {
    GpgSubkey {
        fingerprint: String::new(),
        algorithm: GpgAlgorithm::from_fields(field(4), field(17)),
        bits: field(3).parse().unwrap_or(0),
        created: field(6).parse().unwrap_or(0),
        expires: expiry(field(7)),
        capabilities: field(12).to_string(),
    }
}

/// Secret material is usable for a `sec`/`ssb` serial field: on disk or on a card.
///
/// An empty field (older GnuPG) counts as available; a stub (`#`) does not.
fn secret_available(serial: &str) -> bool {
    serial != SECRET_STUB
}

/// True when the serial field names a smartcard.
fn on_card(serial: &str) -> bool {
    !serial.is_empty() && serial != SECRET_AVAILABLE && serial != SECRET_STUB
}

/// Expiration from field 7: empty or 0 means never.
fn expiry(field: &str) -> Option<u64> {
    field.parse::<u64>().ok().filter(|&t| t != 0)
}

/// First character of a flag field, or [`NO_FLAG`] when empty.
fn flag(field: &str) -> char {
    field.chars().next().unwrap_or(NO_FLAG)
}

/// Undoes GnuPG's C-style `\xNN` escaping of colon listing strings.
///
/// The bytes are decoded as UTF-8 (lossy); a malformed escape is kept verbatim.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = bytes.get(i..i + 4).and_then(|chunk| {
            let hex = chunk.strip_prefix(b"\\x")?;
            u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()
        });
        if let Some(byte) = escaped {
            out.push(byte);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Public listing captured from a throwaway home directory.
    const LIST_KEYS: &[u8] = include_bytes!("../../tests/fixtures/gpg/list-keys.txt");
    /// Secret listing captured from the same home directory.
    const LIST_SECRET_KEYS: &[u8] = include_bytes!("../../tests/fixtures/gpg/list-secret-keys.txt");

    /// Fingerprint of the Ed25519 fixture key.
    const ED_FPR: &str = "F304378CE8CEEF63BB59F93CEF2CA8C2F6A348DC";
    /// Fingerprint of the RSA fixture key.
    const RSA_FPR: &str = "33D3B2A8F4F45A6EC3F9B1093DFE5E9430B05224";

    /// The public fixture yields both keys with all their fields.
    #[test]
    fn parses_public_listing() {
        let keys = parse_listing(LIST_KEYS);
        assert_eq!(keys.len(), 2);

        let ed = &keys[0];
        assert_eq!(ed.fingerprint, ED_FPR);
        assert_eq!(ed.key_id, "EF2CA8C2F6A348DC");
        assert_eq!(ed.algorithm, GpgAlgorithm::EdDsa("ed25519".into()));
        assert_eq!(ed.algorithm.to_string(), "EdDSA ed25519");
        assert_eq!(ed.bits, 255);
        assert_eq!(ed.created, 1794761568);
        assert_eq!(ed.expires, None);
        assert_eq!(ed.validity, 'u');
        assert_eq!(ed.trust, 'u');
        assert_eq!(ed.capabilities, "scESC");
        assert!(!ed.secret);
        assert!(!ed.card);
        assert_eq!(
            ed.uids,
            [GpgUid {
                uid: "Fixture User <fixture@example.invalid>".into(),
                validity: 'u',
            }]
        );
        assert_eq!(
            ed.subkeys,
            [GpgSubkey {
                fingerprint: "49908C6FA4859CC3121E1758379031F537EDF8E9".into(),
                algorithm: GpgAlgorithm::Ecdh("cv25519".into()),
                bits: 255,
                created: 1794761568,
                expires: None,
                capabilities: "e".into(),
            }]
        );

        let rsa = &keys[1];
        assert_eq!(rsa.fingerprint, RSA_FPR);
        assert_eq!(rsa.algorithm, GpgAlgorithm::Rsa);
        assert_eq!(rsa.algorithm.to_string(), "RSA");
        assert_eq!(rsa.bits, 2048);
        assert_eq!(rsa.expires, Some(1893495600));
        assert_eq!(rsa.capabilities, "scSC");
        assert_eq!(
            rsa.uids[0].uid,
            "Colon: Tester (rsa) <colon@example.invalid>"
        );
        assert!(rsa.subkeys.is_empty());
    }

    /// The secret fixture marks the key secret; `grp` records are ignored.
    #[test]
    fn parses_secret_listing() {
        let keys = parse_listing(LIST_SECRET_KEYS);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fingerprint, ED_FPR);
        assert!(keys[0].secret);
        assert!(!keys[0].card);
        assert_eq!(keys[0].subkeys.len(), 1);
        assert_eq!(
            keys[0].subkeys[0].fingerprint,
            "49908C6FA4859CC3121E1758379031F537EDF8E9"
        );
    }

    /// A card serial number on a secret subkey sets `card`; a stub primary is not secret.
    #[test]
    fn card_and_stub_serials() {
        let listing = b"sec:u:255:22:AAAA:1:::u:::scESC:::#::ed25519:::0:\n\
            fpr:::::::::AAAAAAAA:\n\
            ssb:u:255:18:BBBB:1::::::e:::D2760001240100000006012345670000::cv25519::\n\
            fpr:::::::::BBBBBBBB:\n";
        let keys = parse_listing(listing);
        assert_eq!(keys.len(), 1);
        assert!(keys[0].card);
        assert!(keys[0].secret, "the card subkey is usable");

        let stub_only = b"sec:u:255:22:AAAA:1:::u:::scESC:::#::ed25519:::0:\nfpr:::::::::AA:\n";
        let keys = parse_listing(stub_only);
        assert!(!keys[0].secret);
        assert!(!keys[0].card);
    }

    /// Algorithm numbers map to names, with the curve when there is one.
    #[test]
    fn algorithm_mapping() {
        assert_eq!(GpgAlgorithm::from_fields("1", ""), GpgAlgorithm::Rsa);
        assert_eq!(GpgAlgorithm::from_fields("16", ""), GpgAlgorithm::Elgamal);
        assert_eq!(GpgAlgorithm::from_fields("17", ""), GpgAlgorithm::Dsa);
        let ecdsa = GpgAlgorithm::from_fields("19", "nistp256");
        assert_eq!(ecdsa, GpgAlgorithm::Ecdsa("nistp256".into()));
        assert_eq!(ecdsa.to_string(), "ECDSA nistp256");
        assert_eq!(GpgAlgorithm::from_fields("18", "").to_string(), "ECDH");
        assert_eq!(GpgAlgorithm::from_fields("99", ""), GpgAlgorithm::Other(99));
        assert_eq!(GpgAlgorithm::from_fields("x", ""), GpgAlgorithm::Other(0));
    }

    /// Escapes are decoded; malformed ones are kept verbatim.
    #[test]
    fn unescape_cases() {
        assert_eq!(unescape(r"a\x3ab"), "a:b");
        assert_eq!(unescape(r"\x5c"), "\\");
        assert_eq!(unescape(r"caf\xc3\xa9"), "caf\u{e9}");
        assert_eq!(unescape(r"bad\xzz"), r"bad\xzz");
        assert_eq!(unescape(r"end\x3"), r"end\x3");
        assert_eq!(unescape(""), "");
    }

    /// Records before any key, unknown records, CRLF and junk are ignored.
    #[test]
    fn ignores_orphans_and_unknown_records() {
        let listing = b"uid:u::::::::Orphan::\r\n\
            sub:u:1:1:X:1::::::e:\r\n\
            fpr:::::::::DEAD:\r\n\
            tru::1:0:0:3:1:5\r\n\
            cfg:version:2.4.8\r\n\
            pub:f:4096:1:CCCC:abc:0::-:::sc:\r\n\
            rvk:::1::::::FFFF:80:\r\n\
            fpr:::::::::cccc:\r\n\
            uat:u::::1::X::1 2::\r\n";
        let keys = parse_listing(listing);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fingerprint, "CCCC");
        assert_eq!(keys[0].created, 0);
        assert_eq!(keys[0].expires, None);
        assert_eq!(keys[0].validity, 'f');
        assert_eq!(keys[0].trust, '-');
        assert!(keys[0].uids.is_empty());
    }

    /// A key whose `fpr` record is missing is dropped.
    #[test]
    fn key_without_fingerprint_is_dropped() {
        assert!(parse_listing(b"pub:u:255:22:AAAA:1:::u:::sc:\n").is_empty());
        assert!(parse_listing(b"").is_empty());
    }

    /// Truncations, byte mutations and random lines never panic.
    #[test]
    fn fuzz_never_panics() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let base = [LIST_KEYS, LIST_SECRET_KEYS].concat();
        for end in 0..=base.len() {
            let _ = parse_listing(&base[..end]);
        }
        let alphabet = b"pubsecsubssbuidfprgrp:\\x3a0123456789abcdef\n\r+#\xff\xc3";
        for _ in 0..2000 {
            let mut mutated = base.clone();
            for _ in 0..8 {
                let at = (next() as usize) % mutated.len();
                mutated[at] = alphabet[(next() as usize) % alphabet.len()];
            }
            let _ = parse_listing(&mutated);
            let random: Vec<u8> = (0..(next() % 200))
                .map(|_| alphabet[(next() as usize) % alphabet.len()])
                .collect();
            let _ = parse_listing(&random);
        }
    }
}
