//! Key derivation, Blowfish CBC decryption and integrity check of the wallet body.
//!
//! Plain-text layout before encryption (`BlowfishPersistHandler::write`,
//! backendpersisthandler.cpp):
//!
//! ```text
//! 8 random bytes | quint32 BE payload size | payload | random padding | SHA-1(payload)
//! ```
//!
//! padded so the whole buffer is a multiple of the 8-byte block size, then
//! encrypted with Blowfish in CBC mode.
//!
//! The digest is KWallet's own `SHA1` class (sha1.cc), not standard SHA-1:
//! see [`kwallet_sha1`].

use blowfish::Blowfish;
use blowfish::cipher::{BlockCipherDecrypt, KeyInit};
use sha2::Sha512;
use zeroize::Zeroizing;

use super::MSG_WRONG_PASSWORD;
use crate::error::{KringError, Result};
use crate::model::SecretValue;

/// `PBKDF2_SHA512_ITERATIONS` (kwalletbackend.h).
const PBKDF2_ITERATIONS: u32 = 50_000;
/// `PBKDF2_SHA512_KEYSIZE` (kwalletbackend.h): 448 bits, Blowfish's maximum.
const KEY_LEN: usize = 56;
/// Blowfish block size (`BlowFish::_blksz`, blowfish.cc).
const BLOCK_LEN: usize = 8;
/// Size of the big-endian payload size field.
const SIZE_LEN: usize = 4;
/// Size of the trailing SHA-1 digest.
const SHA1_LEN: usize = 20;
/// Smallest body holding the random block, the size and the digest.
const MIN_BODY_LEN: usize = BLOCK_LEN + SIZE_LEN + SHA1_LEN;
/// SHA-1 block size.
const SHA1_BLOCK_LEN: usize = 64;
/// Offset of the 64-bit length in the last padded SHA-1 block.
const SHA1_LENGTH_OFFSET: usize = 56;
/// SHA-1 initial state (`SHA1::reset`, sha1.cc).
const SHA1_INIT: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// Derives the 56-byte Blowfish key with PBKDF2-HMAC-SHA512, 50000 iterations.
///
/// Same as `password2PBKDF2_SHA512` (kwalletbackend.cc, via
/// `gcry_kdf_derive(GCRY_KDF_PBKDF2, GCRY_MD_SHA512)`) on the bytes of the
/// `<wallet>.salt` file, as read by `Backend::setPassword`.
pub(super) fn derive_key(password: &SecretValue, salt: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
    pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Builds the error for a malformed encrypted body (independent of the key).
fn _corrupt(what: &str) -> KringError {
    KringError::InvalidInput(format!("Corrupt wallet file: {what}"))
}

/// Decrypts the body with Blowfish CBC, zero IV (`CipherBlockChain::decrypt`, cbc.cc).
///
/// `CipherBlockChain` starts from a zeroed register (`initRegister`), and per
/// 8-byte block computes `plain = D(cipher) ^ register; register = cipher`.
/// `BlowFish::decrypt` (blowfish.cc) loads each 32-bit half natively and then
/// byte-swaps it (`shuffle`, with `Q_BYTE_ORDER` forced to big endian), so on
/// little-endian hosts the halves are big-endian: standard Blowfish, as
/// [`Blowfish`] implements it. A body that is not a whole number of blocks is
/// corrupt (`-5` in `BlowfishPersistHandler::read`).
pub(super) fn decrypt_payload(body: &[u8], key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if !body.len().is_multiple_of(BLOCK_LEN) {
        return Err(_corrupt("encrypted data is not a whole number of blocks"));
    }
    if body.len() < MIN_BODY_LEN {
        return Err(_corrupt("encrypted data too short"));
    }
    let cipher: Blowfish = Blowfish::new_from_slice(key)
        .map_err(|_| KringError::InvalidInput("Invalid wallet key length".into()))?;
    let mut plain = Zeroizing::new(body.to_vec());
    let mut register = [0u8; BLOCK_LEN];
    let (blocks, _) = plain.as_chunks_mut::<BLOCK_LEN>();
    for block in blocks {
        let next = *block;
        cipher.decrypt_block(block.into());
        for (byte, chain) in block.iter_mut().zip(register) {
            *byte ^= chain;
        }
        register = next;
    }
    Ok(plain)
}

/// Returns the payload of a decrypted body after checking its size and SHA-1.
///
/// As `BlowfishPersistHandler::read`: skip one random block, read the
/// big-endian size, reject a size larger than the rest (`-9`), and compare
/// SHA-1 of the payload with the last 20 bytes (`-8`). With a wrong key both
/// checks fail on garbage, so both yield `InvalidInput("Wrong wallet password")`.
pub(super) fn checked_payload(plain: &[u8]) -> Result<&[u8]> {
    let wrong = || KringError::InvalidInput(MSG_WRONG_PASSWORD.into());
    if plain.len() < MIN_BODY_LEN {
        return Err(_corrupt("encrypted data too short"));
    }
    let size_field = &plain[BLOCK_LEN..BLOCK_LEN + SIZE_LEN];
    let size = u32::from_be_bytes([size_field[0], size_field[1], size_field[2], size_field[3]]);
    let start = BLOCK_LEN + SIZE_LEN;
    let size = size as usize;
    if size > plain.len() - start {
        return Err(wrong());
    }
    let payload = &plain[start..start + size];
    if kwallet_sha1(payload) != plain[plain.len() - SHA1_LEN..] {
        return Err(wrong());
    }
    Ok(payload)
}

/// KWallet's SHA-1 as computed on little-endian hosts (`SHA1::process` / `SHA1::hash`, sha1.cc).
///
/// sha1.cc forces `Q_BYTE_ORDER` to big endian, so `SHA1::transform` loads
/// the 32-bit message words with a native (little-endian) `memcpy` and
/// `SHA1::hash` stores the result words natively. Padding and the 64-bit
/// big-endian bit length are standard. Equivalent: byte-swap every 4-byte
/// group of the standard padded message, run the standard compression, and
/// write the state words little-endian. Validated against a real wallet
/// written by `ksecretd` on x86-64.
fn kwallet_sha1(data: &[u8]) -> [u8; SHA1_LEN] {
    let padded_len = (data.len() + 1 + 8).div_ceil(SHA1_BLOCK_LEN) * SHA1_BLOCK_LEN;
    let mut padded = Zeroizing::new(vec![0u8; padded_len]);
    padded[..data.len()].copy_from_slice(data);
    padded[data.len()] = 0x80;
    let bits = (data.len() as u64).wrapping_mul(8);
    padded[padded_len - (SHA1_BLOCK_LEN - SHA1_LENGTH_OFFSET)..]
        .copy_from_slice(&bits.to_be_bytes());
    let (words, _) = padded.as_chunks_mut::<4>();
    for word in words {
        word.reverse();
    }
    let mut state = SHA1_INIT;
    let (blocks, _) = padded.as_chunks::<SHA1_BLOCK_LEN>();
    sha1::block_api::compress(&mut state, blocks);
    let mut digest = [0u8; SHA1_LEN];
    let (outs, _) = digest.as_chunks_mut::<4>();
    for (out, word) in outs.iter_mut().zip(state) {
        *out = word.to_le_bytes();
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use blowfish::cipher::BlockCipherEncrypt;

    /// Encrypts like `BlowfishPersistHandler::write` + `CipherBlockChain::encrypt`.
    fn _encrypt(plain: &[u8], key: &[u8]) -> Vec<u8> {
        let cipher: Blowfish = Blowfish::new_from_slice(key).expect("key");
        let mut out = plain.to_vec();
        let mut register = [0u8; BLOCK_LEN];
        let (blocks, _) = out.as_chunks_mut::<BLOCK_LEN>();
        for block in blocks {
            for (byte, chain) in block.iter_mut().zip(register) {
                *byte ^= chain;
            }
            cipher.encrypt_block(block.into());
            register = *block;
        }
        out
    }

    /// Builds a plain body around `payload` with the given padding length.
    fn _body(payload: &[u8], pad: usize) -> Vec<u8> {
        let mut out = vec![0xa5; BLOCK_LEN];
        out.extend((payload.len() as u32).to_be_bytes());
        out.extend(payload);
        out.extend(vec![0x3c; pad]);
        out.extend(kwallet_sha1(payload));
        out
    }

    /// KWallet's digest of "abc" is the standard compression of the
    /// word-swapped padded block, written little-endian, not standard SHA-1.
    #[test]
    fn kwallet_sha1_uses_little_endian_words() {
        use sha1::{Digest, Sha1};
        // Standard SHA-1 of the bytes KWallet's transform sees for "abc":
        // the padded block with every 4-byte group reversed.
        let mut block = [0u8; SHA1_BLOCK_LEN];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[63] = 24;
        let (words, _) = block.as_chunks_mut::<4>();
        for word in words {
            word.reverse();
        }
        let mut state = SHA1_INIT;
        sha1::block_api::compress(&mut state, &[block]);
        let expected: Vec<u8> = state.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(kwallet_sha1(b"abc").to_vec(), expected);
        let standard = Sha1::digest(b"abc");
        assert_ne!(kwallet_sha1(b"abc").as_slice(), standard.as_slice());
    }

    /// CBC round trip: chained blocks (identical plain blocks encrypt differently) decrypt back.
    #[test]
    fn cbc_round_trip_chains_blocks() {
        let key = [0x42u8; KEY_LEN];
        let payload = [0u8; 21];
        let body = _body(&payload, 3);
        let encrypted = _encrypt(&body, &key);
        assert_ne!(encrypted[16..24], encrypted[24..32], "blocks are chained");
        let plain = decrypt_payload(&encrypted, &key).expect("decrypt");
        assert_eq!(checked_payload(&plain).expect("payload"), payload);
    }

    /// A modified digest or an oversized length field reads as a wrong password.
    #[test]
    fn integrity_failures_are_wrong_password() {
        let mut body = _body(b"data", 4);
        let last = body.len() - 1;
        body[last] ^= 1;
        let err = checked_payload(&body).expect_err("bad digest");
        assert_eq!(
            err.to_string(),
            format!("invalid input: {MSG_WRONG_PASSWORD}")
        );
        let mut body = _body(b"data", 4);
        body[BLOCK_LEN..BLOCK_LEN + SIZE_LEN].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(checked_payload(&body).is_err());
    }

    /// Bodies that are not whole blocks or are too short are corrupt files.
    #[test]
    fn malformed_bodies_are_corrupt() {
        let key = [1u8; KEY_LEN];
        let err = decrypt_payload(&[0u8; 33], &key).expect_err("partial block");
        assert!(err.to_string().contains("whole number of blocks"), "{err}");
        let err = decrypt_payload(&[0u8; 24], &key).expect_err("short");
        assert!(err.to_string().contains("too short"), "{err}");
    }
}
