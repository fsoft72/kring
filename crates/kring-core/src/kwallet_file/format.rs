//! Wallet file header and clear-text hash block.
//!
//! File layout (`Backend::sync` in kwalletbackend.cc and
//! `BlowfishPersistHandler::write` in backendpersisthandler.cpp):
//!
//! ```text
//! "KWALLET\n\r\0\r\n"            magic (KWMAGIC)
//! major minor cipher hash        4 version bytes
//! quint32 folder count           hash block, clear text:
//!   per folder: 16 bytes MD5(folder), quint32 n, n * 16 bytes MD5(key)
//! encrypted body                 Blowfish CBC, see `crypto`
//! ```

use super::parse::DataStream;
use crate::error::{KringError, Result};

/// File magic (`KWMAGIC`, kwalletbackend.cc).
pub(super) const KWALLET_MAGIC: &[u8] = b"KWALLET\n\r\0\r\n";
/// Magic plus the 4 version bytes.
pub(super) const HEADER_LEN: usize = KWALLET_MAGIC.len() + 4;
/// `KWALLETSTORAGE_VERSION_MAJOR` (kwalletbackend.cc).
const VERSION_MAJOR: u8 = 0;
/// Minor version since KWallet 4.13: the key is the PBKDF2-SHA512 hash
/// (`Backend::openInternal` calls `swapToNewHash` for minor 1; minor 0 uses
/// the legacy iterated SHA-1 `password2hash`).
const VERSION_MINOR_PBKDF2: u8 = 1;
/// `KWALLET_CIPHER_BLOWFISH_ECB` (backendpersisthandler.cpp).
const CIPHER_BLOWFISH_ECB: u8 = 0;
/// `KWALLET_CIPHER_3DES_CBC` (unsupported by KWallet itself).
const CIPHER_3DES_CBC: u8 = 1;
/// `KWALLET_CIPHER_GPG`.
const CIPHER_GPG: u8 = 2;
/// `KWALLET_CIPHER_BLOWFISH_CBC`.
const CIPHER_BLOWFISH_CBC: u8 = 3;
/// `KWALLET_HASH_SHA1`.
const HASH_SHA1: u8 = 0;
/// `KWALLET_HASH_MD5` (unsupported by KWallet itself).
const HASH_MD5: u8 = 1;
/// `KWALLET_HASH_PBKDF2_SHA512`.
const HASH_PBKDF2_SHA512: u8 = 2;
/// Folder count sanity limit of `BlowfishPersistHandler::read`.
const MAX_FOLDERS: u32 = 0xffff;
/// Size of one MD5 digest in the hash block.
const DIGEST_LEN: usize = 16;

/// The 4 version bytes following the magic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletHeader {
    /// Storage major version (always 0).
    pub major: u8,
    /// Storage minor version: 1 = PBKDF2-SHA512 key, 0 = legacy SHA-1 key.
    pub minor: u8,
    /// Cipher code: 0 Blowfish ECB, 1 3DES CBC, 2 GPG, 3 Blowfish CBC.
    pub cipher: u8,
    /// Hash code: 0 SHA-1, 1 MD5, 2 PBKDF2-SHA512.
    pub hash: u8,
}

impl WalletHeader {
    /// Returns true for the only format kring reads: version 0.1, Blowfish CBC, PBKDF2-SHA512.
    ///
    /// This is what `BlowfishPersistHandler::write` produces since KWallet
    /// 4.13 (it always writes cipher 3, and minor 1 with hash 2 when the salt
    /// based key is in use).
    pub fn is_supported(&self) -> bool {
        self.major == VERSION_MAJOR
            && self.minor == VERSION_MINOR_PBKDF2
            && self.cipher == CIPHER_BLOWFISH_CBC
            && self.hash == HASH_PBKDF2_SHA512
    }

    /// Returns `Ok` for a supported header, else `InvalidInput` naming the format.
    pub(super) fn ensure_supported(&self) -> Result<()> {
        if self.is_supported() {
            return Ok(());
        }
        Err(KringError::InvalidInput(format!(
            "Unsupported wallet format: version {}.{}, cipher {}, hash {}",
            self.major,
            self.minor,
            _cipher_name(self.cipher),
            _hash_name(self.hash)
        )))
    }
}

/// Returns a readable cipher name.
fn _cipher_name(code: u8) -> String {
    match code {
        CIPHER_BLOWFISH_ECB => "Blowfish ECB".into(),
        CIPHER_3DES_CBC => "3DES CBC".into(),
        CIPHER_GPG => "GPG".into(),
        CIPHER_BLOWFISH_CBC => "Blowfish CBC".into(),
        other => format!("unknown ({other})"),
    }
}

/// Returns a readable hash name.
fn _hash_name(code: u8) -> String {
    match code {
        HASH_SHA1 => "SHA-1".into(),
        HASH_MD5 => "MD5".into(),
        HASH_PBKDF2_SHA512 => "PBKDF2-SHA512".into(),
        other => format!("unknown ({other})"),
    }
}

/// Builds the error for a malformed file outside the encrypted body.
fn _corrupt(what: &str) -> KringError {
    KringError::InvalidInput(format!("Corrupt wallet file: {what}"))
}

/// Reads the magic and version bytes (`Backend::openInternal`, kwalletbackend.cc).
///
/// Anything shorter than the header or without the magic yields
/// `InvalidInput("Not a KWallet wallet file")`. The format is not checked here.
pub fn read_header(bytes: &[u8]) -> Result<WalletHeader> {
    let not_wallet = || KringError::InvalidInput("Not a KWallet wallet file".into());
    let header = bytes.get(..HEADER_LEN).ok_or_else(not_wallet)?;
    if &header[..KWALLET_MAGIC.len()] != KWALLET_MAGIC {
        return Err(not_wallet());
    }
    let version = &header[KWALLET_MAGIC.len()..];
    Ok(WalletHeader {
        major: version[0],
        minor: version[1],
        cipher: version[2],
        hash: version[3],
    })
}

/// Skips the header and the clear-text hash block, returning the encrypted body.
///
/// The MD5 digests (`BlowfishPersistHandler::read`, backendpersisthandler.cpp)
/// only serve KWallet's `hasFolder`/`hasEntry` on closed wallets; they are
/// skipped, not verified. A folder count above `0xffff` or a truncated block
/// is corrupt, as in KWallet (`-43`).
pub(super) fn encrypted_body(kwl: &[u8]) -> Result<&[u8]> {
    let mut stream = DataStream::new(kwl.get(HEADER_LEN..).unwrap_or_default());
    let folders = stream.u32().ok_or_else(|| _corrupt("missing hash block"))?;
    if folders > MAX_FOLDERS {
        return Err(_corrupt("too many folders in hash block"));
    }
    for _ in 0..folders {
        let truncated = || _corrupt("truncated hash block");
        stream.raw(DIGEST_LEN).ok_or_else(truncated)?;
        let keys = stream.u32().ok_or_else(truncated)?;
        let len = (keys as usize)
            .checked_mul(DIGEST_LEN)
            .ok_or_else(truncated)?;
        stream.raw(len).ok_or_else(truncated)?;
    }
    Ok(stream.rest())
}
