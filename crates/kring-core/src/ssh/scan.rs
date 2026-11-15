//! Scan a directory for SSH key pairs and describe them.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, PublicKey};

use crate::error::{KringError, Result};

/// Files larger than this are never read: real key files are a few KiB at most.
pub(super) const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
/// Header of the OpenSSH private key format.
const OPENSSH_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
/// Bytes read first from every candidate file to decide whether it is worth reading.
const PROBE_BYTES: usize = 128;
/// Start of a PEM block.
const PEM_PREFIX: &str = "-----BEGIN ";
/// Leading tokens of an OpenSSH public key line.
const PUBLIC_TOKENS: [&str; 3] = ["ssh-", "ecdsa-", "sk-"];
/// Suffix of public key files.
const PUBLIC_SUFFIX: &str = ".pub";
/// Algorithm name used for legacy keys without a readable `.pub`.
const LEGACY_ALGORITHM_NAME: &str = "legacy";

/// Public key algorithm of an SSH key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshAlgorithm {
    /// Ed25519.
    Ed25519,
    /// ECDSA over NIST P-256.
    EcdsaP256,
    /// ECDSA over NIST P-384.
    EcdsaP384,
    /// ECDSA over NIST P-521.
    EcdsaP521,
    /// RSA.
    Rsa,
    /// Anything else (DSA, security keys, or `legacy` when unknown).
    Other(String),
}

/// What is known about one SSH key (private file, public file, or both).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyInfo {
    /// File stem: the private file name, or the `.pub` name without suffix.
    pub name: String,
    /// Path of the private key file, if present.
    pub private_path: Option<PathBuf>,
    /// Path of the public key file, if present.
    pub public_path: Option<PathBuf>,
    /// Key algorithm.
    pub algorithm: SshAlgorithm,
    /// Key size in bits (RSA modulus, curve size, 256 for Ed25519), if known.
    pub bits: Option<u32>,
    /// `SHA256:...` fingerprint; empty for a legacy key without a `.pub`.
    pub fingerprint: String,
    /// Comment of the key (from the `.pub`, else from the private key).
    pub comment: String,
    /// Whether the private key is passphrase-protected; `None` without a private key.
    pub encrypted: Option<bool>,
    /// True for PEM / PKCS#8 private keys (read-only for kring).
    pub legacy_format: bool,
    /// True when the private key and the `.pub` hold different public keys.
    /// Algorithm, bits, fingerprint and comment then describe the private key.
    pub pub_mismatch: bool,
}

/// Parsed view of a private key file.
pub(super) struct PrivateProbe {
    /// Path of the file.
    pub(super) path: PathBuf,
    /// Whether the key is passphrase-protected.
    pub(super) encrypted: bool,
    /// True for legacy PEM / PKCS#8 keys.
    pub(super) legacy: bool,
    /// Public part, only available for the OpenSSH format.
    pub(super) public: Option<PublicKey>,
}

/// Parsed view of a public key file.
struct PublicProbe {
    path: PathBuf,
    key: PublicKey,
}

/// Scans `dir` for SSH keys, pairing `<name>` with `<name>.pub`.
///
/// Only regular files (no symlinks) up to 64 KiB are read. A private file
/// counts only if it starts with a private key PEM header (OpenSSH, or legacy
/// PEM / PKCS#8); a `.pub` file only if it parses as an OpenSSH public key.
/// Everything else (`authorized_keys`, `known_hosts`, `config`, ...) is ignored.
/// For OpenSSH private keys the algorithm and fingerprint come from the key
/// itself (the public part is readable even when encrypted); for legacy keys
/// they come from the paired `.pub`. If an OpenSSH private key and its `.pub`
/// hold different public keys, the private key wins and `pub_mismatch` is set.
/// An unreadable file is skipped; only a failing `read_dir` is an error. A missing directory yields an empty list.
pub fn scan_keys(dir: &Path) -> Result<Vec<SshKeyInfo>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut privates: BTreeMap<String, PrivateProbe> = BTreeMap::new();
    let mut publics: BTreeMap<String, PublicProbe> = BTreeMap::new();
    for entry in read_dir(dir)? {
        // An unreadable directory entry must not hide the other keys.
        let Ok(entry) = entry else { continue };
        let is_regular = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
        if !is_regular {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if let Some(stem) = file_name.strip_suffix(PUBLIC_SUFFIX) {
            if let Some(key) = probe_public(&path) {
                publics.insert(stem.to_string(), PublicProbe { path, key });
            }
        } else if let Some(probe) = probe_private(&path) {
            privates.insert(file_name, probe);
        }
    }
    let mut names: Vec<String> = privates.keys().chain(publics.keys()).cloned().collect();
    names.sort();
    names.dedup();
    Ok(names
        .into_iter()
        .filter_map(|name| build_info(&name, privates.remove(&name), publics.remove(&name)))
        .collect())
}

/// Opens a directory for listing, mapping the error.
fn read_dir(dir: &Path) -> Result<fs::ReadDir> {
    fs::read_dir(dir).map_err(|e| io_err(dir, &e))
}

/// Builds a [`KringError::Io`] for `path`.
fn io_err(path: &Path, e: &std::io::Error) -> KringError {
    KringError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    }
}

/// Reads a candidate file as UTF-8 text, in two steps.
///
/// Opens without following symlinks, skips files over [`MAX_KEY_FILE_BYTES`],
/// reads a [`PROBE_BYTES`] prefix and reads the rest only if `wanted(prefix)`.
/// Any open or read error, or non-UTF-8 content, yields `None`: a single
/// unreadable file never aborts a scan.
fn read_candidate(path: &Path, wanted: impl Fn(&str) -> bool) -> Option<String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_KEY_FILE_BYTES {
        return None;
    }
    let mut file = file;
    let mut bytes = Vec::new();
    (&mut file)
        .take(PROBE_BYTES as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    note_bytes_read(bytes.len());
    // A prefix cut inside a multi-byte character is fine for the ASCII checks.
    if !wanted(&String::from_utf8_lossy(&bytes)) {
        return None;
    }
    let before = bytes.len();
    file.take(MAX_KEY_FILE_BYTES).read_to_end(&mut bytes).ok()?;
    note_bytes_read(bytes.len() - before);
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
thread_local! {
    /// Bytes read by [`read_candidate`] on this thread (test instrumentation).
    static BYTES_READ: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Adds to the test-only read counter.
#[cfg(test)]
fn note_bytes_read(n: usize) {
    BYTES_READ.with(|c| c.set(c.get() + n));
}

/// No-op outside tests.
#[cfg(not(test))]
fn note_bytes_read(_n: usize) {}

/// Parses a `.pub` file; `None` when it is not an OpenSSH public key.
fn probe_public(path: &Path) -> Option<PublicKey> {
    let text = read_candidate(path, |prefix| {
        let head = prefix.trim_start();
        PUBLIC_TOKENS.iter().any(|t| head.starts_with(t))
    })?;
    PublicKey::from_openssh(text.trim()).ok()
}

/// Cheap header check, then parse; `None` when the file is not a private key.
fn probe_private(path: &Path) -> Option<PrivateProbe> {
    let text = read_candidate(path, |prefix| prefix.trim_start().starts_with(PEM_PREFIX))?;
    classify_private(path, &text)
}

/// Classifies the text of `path` as an OpenSSH or legacy private key.
///
/// `None` when the text is neither a parseable OpenSSH private key nor a PEM
/// `-----BEGIN ... PRIVATE KEY-----` block.
pub(super) fn classify_private(path: &Path, text: &str) -> Option<PrivateProbe> {
    let head = text.trim_start();
    if head.starts_with(OPENSSH_HEADER) {
        let key = PrivateKey::from_openssh(text).ok()?;
        return Some(PrivateProbe {
            path: path.to_path_buf(),
            encrypted: key.is_encrypted(),
            legacy: false,
            public: Some(key.public_key().clone()),
        });
    }
    let first_line = head.lines().next().unwrap_or("");
    let is_pem_private =
        first_line.starts_with("-----BEGIN ") && first_line.contains("PRIVATE KEY-----");
    if !is_pem_private {
        return None;
    }
    // "Proc-Type: 4,ENCRYPTED" (traditional PEM) or PKCS#8 "ENCRYPTED PRIVATE KEY".
    let encrypted = first_line.contains("ENCRYPTED") || text.contains("Proc-Type: 4,ENCRYPTED");
    Some(PrivateProbe {
        path: path.to_path_buf(),
        encrypted,
        legacy: true,
        public: None,
    })
}

/// Combines the probes of one name into an [`SshKeyInfo`].
fn build_info(
    name: &str,
    private: Option<PrivateProbe>,
    public: Option<PublicProbe>,
) -> Option<SshKeyInfo> {
    let key = private
        .as_ref()
        .and_then(|p| p.public.as_ref())
        .or(public.as_ref().map(|p| &p.key));
    let (algorithm, bits, fingerprint) = match key {
        Some(key) => (
            algorithm_of(key.algorithm()),
            bits_of(key.key_data()),
            key.fingerprint(HashAlg::Sha256).to_string(),
        ),
        // Legacy private key without a readable .pub: nothing to derive from.
        None => private.as_ref().map(|_| {
            (
                SshAlgorithm::Other(LEGACY_ALGORITHM_NAME.into()),
                None,
                String::new(),
            )
        })?,
    };
    let pub_mismatch = match (
        private.as_ref().and_then(|p| p.public.as_ref()),
        public.as_ref(),
    ) {
        (Some(from_private), Some(from_pub)) => from_private.key_data() != from_pub.key.key_data(),
        _ => false,
    };
    // On a mismatch the .pub describes another key: its comment is not ours.
    let comment = public
        .as_ref()
        .filter(|_| !pub_mismatch)
        .map(|p| p.key.comment().to_string())
        .filter(|c| !c.is_empty())
        .or_else(|| key.map(|k| k.comment().to_string()))
        .unwrap_or_default();
    Some(SshKeyInfo {
        name: name.to_string(),
        encrypted: private.as_ref().map(|p| p.encrypted),
        legacy_format: private.as_ref().is_some_and(|p| p.legacy),
        pub_mismatch,
        private_path: private.map(|p| p.path),
        public_path: public.map(|p| p.path),
        algorithm,
        bits,
        fingerprint,
        comment,
    })
}

/// Maps the `ssh-key` algorithm to [`SshAlgorithm`].
fn algorithm_of(algorithm: Algorithm) -> SshAlgorithm {
    match algorithm {
        Algorithm::Ed25519 => SshAlgorithm::Ed25519,
        Algorithm::Rsa { .. } => SshAlgorithm::Rsa,
        Algorithm::Ecdsa { curve } => match curve {
            EcdsaCurve::NistP256 => SshAlgorithm::EcdsaP256,
            EcdsaCurve::NistP384 => SshAlgorithm::EcdsaP384,
            EcdsaCurve::NistP521 => SshAlgorithm::EcdsaP521,
        },
        other => SshAlgorithm::Other(other.to_string()),
    }
}

/// Key size in bits, when it is defined for the key type.
fn bits_of(data: &KeyData) -> Option<u32> {
    match data {
        KeyData::Ed25519(_) => Some(256),
        KeyData::Ecdsa(key) => Some(match key.curve() {
            EcdsaCurve::NistP256 => 256,
            EcdsaCurve::NistP384 => 384,
            EcdsaCurve::NistP521 => 521,
        }),
        KeyData::Rsa(key) => {
            let modulus = key.n.as_positive_bytes()?;
            let first = *modulus.first()?;
            let bits = modulus.len() * 8 - first.leading_zeros() as usize;
            u32::try_from(bits).ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A big non-key file is only probed (prefix), never read in full.
    #[test]
    fn non_key_files_are_only_probed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("decoy"), "x".repeat(60 * 1024)).unwrap();
        fs::write(dir.path().join("decoy.pub"), "y".repeat(60 * 1024)).unwrap();
        BYTES_READ.with(|c| c.set(0));
        assert!(scan_keys(dir.path()).unwrap().is_empty());
        let read = BYTES_READ.with(|c| c.get());
        assert!(read <= 2 * PROBE_BYTES, "read {read} bytes");
    }
}
