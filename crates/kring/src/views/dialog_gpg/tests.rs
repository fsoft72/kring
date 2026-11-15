//! Tests of the GPG dialogs: validation, commands and remembered passphrases.

use std::path::PathBuf;

use kring_core::gpg::{GpgKey, parse_listing};
use kring_core::model::SecretValue;
use zeroize::Zeroizing;

use super::*;

/// Test key passphrase.
const PASS: &str = "key-pass";
/// Test backup passphrase.
const BACKUP: &str = "backup-pass";

/// The fixture keys: a secret ed25519 key, then a public-only RSA key.
pub(crate) fn keys() -> Vec<GpgKey> {
    let public = include_bytes!("../../../../kring-core/tests/fixtures/gpg/list-keys.txt");
    let secret = include_bytes!("../../../../kring-core/tests/fixtures/gpg/list-secret-keys.txt");
    let secret = parse_listing(secret);
    parse_listing(public)
        .into_iter()
        .map(|mut k| {
            if let Some(s) = secret.iter().find(|s| s.fingerprint == k.fingerprint) {
                k.secret = true;
                k.primary_secret = s.primary_secret;
                k.card = s.card;
            }
            k
        })
        .collect()
}

/// The secret fixture key.
pub(crate) fn secret_key() -> GpgKey {
    keys().into_iter().find(|k| k.secret).unwrap()
}

/// The public-only fixture key.
pub(crate) fn public_key() -> GpgKey {
    keys().into_iter().find(|k| !k.secret).unwrap()
}

/// Sets a buffer.
fn set(buffer: &mut Zeroizing<String>, text: &str) {
    buffer.clear();
    buffer.push_str(text);
}

/// Text of an optional secret.
fn text(secret: &Option<SecretValue>) -> Option<&str> {
    secret.as_ref().and_then(|s| s.as_text())
}

/// The fixtures have one secret key with its primary secret and one public key.
#[test]
fn fixture_keys() {
    let secret = secret_key();
    assert!(secret.primary_secret && !secret.card);
    assert!(!public_key().secret);
}

/// The new key dialog builds `Name <email>` with the chosen algorithm,
/// expiry and passphrase; no passphrase leaves the key unprotected.
#[test]
fn create_builds_key() {
    let mut d = GpgDialog::create();
    let GpgDialog::Create {
        name,
        email,
        algo,
        expiry,
        passphrase,
        confirm,
        ..
    } = &mut d
    else {
        panic!("expected Create");
    };
    assert_eq!(*algo, GpgAlgo::Ed25519Cv25519, "default algorithm");
    assert_eq!(*expiry, ExpiryChoice::TwoYears, "default expiry");
    *name = " Ada Lovelace ".into();
    *email = " ada@example.org ".into();
    *algo = GpgAlgo::Rsa4096;
    *expiry = ExpiryChoice::Never;
    set(passphrase, PASS);
    set(confirm, PASS);
    match d.command_for().unwrap() {
        Command::CreateGpgKey {
            uid,
            algo,
            expire,
            passphrase,
        } => {
            assert_eq!(uid, "Ada Lovelace <ada@example.org>");
            assert_eq!(algo, GpgAlgo::Rsa4096);
            assert_eq!(expire, None);
            assert_eq!(text(&passphrase), Some(PASS));
        }
        other => panic!("unexpected {other:?}"),
    }
    if let GpgDialog::Create {
        email,
        expiry,
        no_passphrase,
        ..
    } = &mut d
    {
        email.clear();
        *expiry = ExpiryChoice::OneYear;
        *no_passphrase = true;
    }
    match d.command_for().unwrap() {
        Command::CreateGpgKey {
            uid,
            expire,
            passphrase,
            ..
        } => {
            assert_eq!(uid, "Ada Lovelace");
            assert_eq!(expire.as_deref(), Some("1y"));
            assert!(passphrase.is_none());
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// Names and emails are validated; passphrases must match.
#[test]
fn create_validation() {
    assert_eq!(user_id("", "a@b.c"), Err(MSG_NO_NAME.to_string()));
    assert_eq!(user_id("A <x>", ""), Err(MSG_BAD_NAME.to_string()));
    assert_eq!(user_id("A\nB", ""), Err(MSG_BAD_NAME.to_string()));
    assert_eq!(user_id("A", "nope"), Err(MSG_BAD_EMAIL.to_string()));
    assert_eq!(user_id("A", "a b@c.d"), Err(MSG_BAD_EMAIL.to_string()));
    assert_eq!(user_id("A", "<a@c.d>"), Err(MSG_BAD_EMAIL.to_string()));
    assert_eq!(user_id("A", "a@c.d").unwrap(), "A <a@c.d>");
    let mut d = GpgDialog::create();
    if let GpgDialog::Create {
        name,
        passphrase,
        confirm,
        ..
    } = &mut d
    {
        *name = "A".into();
        set(passphrase, "one");
        set(confirm, "two");
    }
    assert!(d.command_for().is_err(), "mismatch");
    for c in EXPIRY_CHOICES {
        assert!(!c.label().is_empty());
    }
    assert_eq!(ExpiryChoice::FiveYears.value(), Some("5y"));
    assert_eq!(
        algo_label(GpgAlgo::Ed25519Cv25519),
        "Ed25519 / Cv25519 (recommended)"
    );
}

/// Import and save public need a path; they send the path as typed.
#[test]
fn import_and_save_public() {
    let mut d = GpgDialog::import();
    assert!(d.command_for().is_err(), "empty path");
    if let GpgDialog::Import { source } = &mut d {
        *source = "/k/keys.asc".into();
    }
    assert!(matches!(
        d.command_for().unwrap(),
        Command::ImportGpgKeys { path } if path == std::path::Path::new("/k/keys.asc")
    ));
    let key = public_key();
    let mut d = GpgDialog::save_public(&key);
    let GpgDialog::SavePublic { dest, .. } = &mut d else {
        panic!("expected SavePublic");
    };
    assert_eq!(*dest, format!("~/{}-public.asc", key.key_id));
    *dest = "/k/p.asc".into();
    match d.command_for().unwrap() {
        Command::SaveGpgPublic { fpr, dest } => {
            assert_eq!(fpr, key.fingerprint);
            assert_eq!(dest, PathBuf::from("/k/p.asc"));
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// The secret export sends the key passphrase when typed; empty is allowed
/// (unprotected key) until the worker said one is required.
#[test]
fn export_secret_command() {
    let key = secret_key();
    let mut d = GpgDialog::export_secret(&key);
    if let GpgDialog::ExportSecret { dest, .. } = &mut d {
        assert_eq!(*dest, format!("~/{}-secret.asc", key.key_id));
        *dest = "/k/s.asc".into();
    }
    match d.command_for().unwrap() {
        Command::ExportGpgSecret {
            fpr,
            dest,
            passphrase,
        } => {
            assert_eq!(fpr, key.fingerprint);
            assert_eq!(dest, PathBuf::from("/k/s.asc"));
            assert!(passphrase.is_none());
        }
        other => panic!("unexpected {other:?}"),
    }
    let mut d = d.needing_key_passphrase();
    assert_eq!(d.command_for().unwrap_err(), MSG_NO_KEY_PASSPHRASE);
    d.fill(PASS);
    match d.command_for().unwrap() {
        Command::ExportGpgSecret { passphrase, .. } => assert_eq!(text(&passphrase), Some(PASS)),
        other => panic!("unexpected {other:?}"),
    }
}

/// Changing the passphrase always needs a new one and a backup passphrase
/// (the backup holds the secret key); the old one is optional until required.
#[test]
fn change_passphrase_command() {
    let key = secret_key();
    let mut d = GpgDialog::change_passphrase(&key);
    assert!(d.command_for().is_err(), "new passphrase missing");
    if let GpgDialog::ChangePassphrase { new, confirm, .. } = &mut d {
        set(new, "new-pass");
        set(confirm, "new-pass");
    }
    assert!(d.command_for().is_err(), "backup passphrase missing");
    if let GpgDialog::ChangePassphrase {
        backup,
        backup_confirm,
        ..
    } = &mut d
    {
        set(backup, BACKUP);
        set(backup_confirm, BACKUP);
    }
    match d.command_for().unwrap() {
        Command::ChangeGpgPassphrase {
            fpr,
            old,
            new,
            backup_passphrase,
        } => {
            assert_eq!(fpr, key.fingerprint);
            assert!(old.is_none());
            assert_eq!(text(&new), Some("new-pass"));
            assert_eq!(text(&backup_passphrase), Some(BACKUP));
        }
        other => panic!("unexpected {other:?}"),
    }
    let d = d.needing_key_passphrase();
    assert_eq!(d.command_for().unwrap_err(), MSG_NO_KEY_PASSPHRASE);
}

/// Deleting a secret key asks the key passphrase (optional) and a backup
/// passphrase (required); a public key needs neither.
#[test]
fn delete_command() {
    let key = secret_key();
    let mut d = GpgDialog::delete(&key);
    assert!(d.command_for().is_err(), "backup passphrase missing");
    if let GpgDialog::Delete {
        backup,
        backup_confirm,
        key_passphrase,
        ..
    } = &mut d
    {
        set(backup, BACKUP);
        set(backup_confirm, BACKUP);
        set(key_passphrase, PASS);
    }
    match d.command_for().unwrap() {
        Command::DeleteGpgKey {
            fpr,
            key_passphrase,
            backup_passphrase,
        } => {
            assert_eq!(fpr, key.fingerprint);
            assert_eq!(text(&key_passphrase), Some(PASS));
            assert_eq!(text(&backup_passphrase), Some(BACKUP));
        }
        other => panic!("unexpected {other:?}"),
    }
    let public = GpgDialog::delete(&public_key());
    match public.command_for().unwrap() {
        Command::DeleteGpgKey {
            key_passphrase,
            backup_passphrase,
            ..
        } => assert!(key_passphrase.is_none() && backup_passphrase.is_none()),
        other => panic!("unexpected {other:?}"),
    }
    assert!(!public.asks_passphrase() && !public.reopens_when_wrong());
}

/// The remembered passphrase fills the key and backup passphrases, never a
/// new key passphrase; clearing empties every field.
#[test]
fn fill_and_clear() {
    let key = secret_key();
    let mut d = GpgDialog::change_passphrase(&key);
    d.fill(PASS);
    let GpgDialog::ChangePassphrase {
        old,
        new,
        backup,
        backup_confirm,
        ..
    } = &d
    else {
        panic!("expected ChangePassphrase");
    };
    assert_eq!(old.as_str(), PASS);
    assert_eq!(backup.as_str(), PASS);
    assert_eq!(backup_confirm.as_str(), PASS);
    assert!(new.is_empty(), "a new passphrase is never filled");
    d.clear_secrets();
    let GpgDialog::ChangePassphrase { old, backup, .. } = &d else {
        panic!("expected ChangePassphrase");
    };
    assert!(old.is_empty() && backup.is_empty());
    let mut create = GpgDialog::create();
    create.fill(PASS);
    let GpgDialog::Create { passphrase, .. } = &create else {
        panic!("expected Create");
    };
    assert!(passphrase.is_empty());
    for d in [
        GpgDialog::create(),
        GpgDialog::import(),
        GpgDialog::save_public(&key),
    ] {
        assert!(!d.asks_passphrase() && !d.reopens_when_wrong());
    }
    for d in [
        GpgDialog::export_secret(&key),
        GpgDialog::change_passphrase(&key),
        GpgDialog::delete(&key),
    ] {
        assert!(d.asks_passphrase() && d.reopens_when_wrong());
    }
}
