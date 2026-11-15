//! Scan a directory for SSH key pairs and describe them.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, PublicKey};

use crate::error::{KringError, Result};

/// Files larger than this are never read: real key files are a few KiB at most.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
/// Header of the OpenSSH private key format.
const OPENSSH_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
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
}

/// Parsed view of a private key file.
struct PrivateProbe {
    path: PathBuf,
    encrypted: bool,
    legacy: bool,
    /// Public part, only available for the OpenSSH format.
    public: Option<PublicKey>,
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
/// they come from the paired `.pub`. A missing directory yields an empty list.
pub fn scan_keys(dir: &Path) -> Result<Vec<SshKeyInfo>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut privates: BTreeMap<String, PrivateProbe> = BTreeMap::new();
    let mut publics: BTreeMap<String, PublicProbe> = BTreeMap::new();
    for entry in read_dir(dir)? {
        let entry = entry.map_err(|e| io_err(dir, &e))?;
        let is_regular = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
        if !is_regular {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if let Some(stem) = file_name.strip_suffix(PUBLIC_SUFFIX) {
            if let Some(key) = probe_public(&path)? {
                publics.insert(stem.to_string(), PublicProbe { path, key });
            }
        } else if let Some(probe) = probe_private(&path)? {
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

/// Reads at most [`MAX_KEY_FILE_BYTES`] of a regular file as UTF-8 text.
///
/// Returns `None` for oversized or non-UTF-8 files (never keys).
fn read_bounded(path: &Path) -> Result<Option<String>> {
    let file = fs::File::open(path).map_err(|e| io_err(path, &e))?;
    let len = file.metadata().map_err(|e| io_err(path, &e))?.len();
    if len > MAX_KEY_FILE_BYTES {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    file.take(MAX_KEY_FILE_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|e| io_err(path, &e))?;
    Ok(String::from_utf8(bytes).ok())
}

/// Parses a `.pub` file; `None` when it is not an OpenSSH public key.
fn probe_public(path: &Path) -> Result<Option<PublicKey>> {
    let Some(text) = read_bounded(path)? else {
        return Ok(None);
    };
    Ok(PublicKey::from_openssh(text.trim()).ok())
}

/// Cheap header check, then parse; `None` when the file is not a private key.
fn probe_private(path: &Path) -> Result<Option<PrivateProbe>> {
    let Some(text) = read_bounded(path)? else {
        return Ok(None);
    };
    let head = text.trim_start();
    if head.starts_with(OPENSSH_HEADER) {
        let Ok(key) = PrivateKey::from_openssh(&text) else {
            return Ok(None);
        };
        return Ok(Some(PrivateProbe {
            path: path.to_path_buf(),
            encrypted: key.is_encrypted(),
            legacy: false,
            public: Some(key.public_key().clone()),
        }));
    }
    let first_line = head.lines().next().unwrap_or("");
    let is_pem_private =
        first_line.starts_with("-----BEGIN ") && first_line.contains("PRIVATE KEY-----");
    if !is_pem_private {
        return Ok(None);
    }
    // "Proc-Type: 4,ENCRYPTED" (traditional PEM) or PKCS#8 "ENCRYPTED PRIVATE KEY".
    let encrypted = first_line.contains("ENCRYPTED") || text.contains("Proc-Type: 4,ENCRYPTED");
    Ok(Some(PrivateProbe {
        path: path.to_path_buf(),
        encrypted,
        legacy: true,
        public: None,
    }))
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
    let comment = public
        .as_ref()
        .map(|p| p.key.comment().to_string())
        .filter(|c| !c.is_empty())
        .or_else(|| key.map(|k| k.comment().to_string()))
        .unwrap_or_default();
    Some(SshKeyInfo {
        name: name.to_string(),
        encrypted: private.as_ref().map(|p| p.encrypted),
        legacy_format: private.as_ref().is_some_and(|p| p.legacy),
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
