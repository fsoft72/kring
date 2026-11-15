//! GnuPG keys, managed by driving the `gpg` binary.
//!
//! [`GpgRunner`] runs gpg with captured output, timeouts and passphrases over a
//! pipe (loopback pinentry); [`list_keys`] lists public keys with their secret
//! state, parsed from the colon format.

mod colons;
mod runner;

pub use colons::{GpgAlgorithm, GpgKey, GpgSubkey, GpgUid, parse_listing};
pub use runner::{
    GpgOutput, GpgRunner, MAX_OUTPUT, MSG_GPG_NOT_FOUND, MSG_PASSPHRASE_NEWLINE, TIMEOUT_DEFAULT,
    TIMEOUT_KEYGEN,
};

use crate::error::{KringError, Result};

/// Options of every colon listing.
const LIST_OPTIONS: [&str; 4] = [
    "--with-colons",
    "--fixed-list-mode",
    "--with-fingerprint",
    "--with-subkey-fingerprint",
];

/// Lists all public keys, with `secret`/`card` taken from the secret key listing.
///
/// Secret keys without a public key (should not happen) are listed too.
pub fn list_keys(runner: &GpgRunner) -> Result<Vec<GpgKey>> {
    let public = parse_listing(&listing(runner, "--list-keys")?);
    let secret = parse_listing(&listing(runner, "--list-secret-keys")?);
    Ok(merge(public, secret))
}

/// Runs one colon listing command and returns its stdout.
fn listing(runner: &GpgRunner, command: &str) -> Result<Vec<u8>> {
    let mut args: Vec<&str> = LIST_OPTIONS.to_vec();
    args.push(command);
    let out = runner.run(args, None, None, TIMEOUT_DEFAULT)?;
    if !out.success() {
        return Err(KringError::Gpg(format!(
            "{command} failed ({}): {}",
            out.status,
            out.stderr_text()
        )));
    }
    Ok(out.stdout)
}

/// Marks public keys that have a secret counterpart and appends secret-only keys.
fn merge(mut public: Vec<GpgKey>, secret: Vec<GpgKey>) -> Vec<GpgKey> {
    for sec in secret {
        match public.iter_mut().find(|k| k.fingerprint == sec.fingerprint) {
            Some(key) => {
                key.secret = sec.secret;
                key.card = sec.card;
            }
            None => public.push(sec),
        }
    }
    public
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Public listing fixture.
    const LIST_KEYS: &[u8] = include_bytes!("../../tests/fixtures/gpg/list-keys.txt");
    /// Secret listing fixture.
    const LIST_SECRET_KEYS: &[u8] = include_bytes!("../../tests/fixtures/gpg/list-secret-keys.txt");

    /// The secret flag is merged onto the matching public key only.
    #[test]
    fn merge_marks_secret_keys() {
        let keys = merge(parse_listing(LIST_KEYS), parse_listing(LIST_SECRET_KEYS));
        assert_eq!(keys.len(), 2);
        assert!(keys[0].secret, "ed25519 key has its secret");
        assert!(!keys[1].secret, "rsa key is public only");
        assert_eq!(keys[0].uids.len(), 1, "public uids are kept");
    }

    /// A secret key missing from the public listing is still listed.
    #[test]
    fn merge_keeps_secret_only_keys() {
        let keys = merge(Vec::new(), parse_listing(LIST_SECRET_KEYS));
        assert_eq!(keys.len(), 1);
        assert!(keys[0].secret);
    }
}
