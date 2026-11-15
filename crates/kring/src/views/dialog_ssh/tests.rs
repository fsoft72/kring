//! Tests of the SSH dialogs: validation, commands and remembered passphrases.

use std::path::PathBuf;

use kring_core::model::SecretValue;
use kring_core::ssh::{SshAlgorithm, SshKeyInfo};
use zeroize::Zeroizing;

use super::*;

/// Test passphrase.
const PASS: &str = "key-pass";
/// Another test passphrase.
const OTHER: &str = "other-pass";

/// A key named `name`; `encrypted` as the scan reports it.
pub(crate) fn key(name: &str, encrypted: Option<bool>) -> SshKeyInfo {
    SshKeyInfo {
        name: name.into(),
        private_path: encrypted.map(|_| PathBuf::from(format!("/h/.ssh/{name}"))),
        public_path: Some(PathBuf::from(format!("/h/.ssh/{name}.pub"))),
        algorithm: SshAlgorithm::Ed25519,
        bits: Some(256),
        fingerprint: format!("SHA256:{name}"),
        comment: format!("{name}@test"),
        encrypted,
        legacy_format: false,
        pub_mismatch: false,
    }
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

/// The new key name avoids existing keys; the dialog builds the key.
#[test]
fn generate_builds_new_key() {
    let existing = [key("id_ed25519", Some(false)), key("id_ed25519_2", None)];
    let mut d = SshDialog::generate(&existing);
    let SshDialog::Generate {
        name,
        choice,
        comment,
        passphrase,
        confirm,
        ..
    } = &mut d
    else {
        panic!("expected Generate");
    };
    assert_eq!(name, "id_ed25519_3");
    *choice = KeyChoice::Rsa4096;
    *comment = " me@host ".into();
    set(passphrase, PASS);
    set(confirm, PASS);
    let Ok(Command::GenerateSshKey(k)) = d.command_for() else {
        panic!("expected GenerateSshKey");
    };
    assert_eq!(k.name, "id_ed25519_3");
    assert_eq!((k.algorithm, k.rsa_bits), (SshAlgorithm::Rsa, 4096));
    assert_eq!(k.comment, "me@host");
    assert_eq!(k.passphrase.as_ref().unwrap().as_text(), Some(PASS));
    assert!(
        !d.asks_passphrase(),
        "a new key passphrase is never remembered"
    );
}

/// Generate refuses a bad name, a multi-line comment, a missing or
/// mismatched passphrase; "No passphrase" sends none.
#[test]
fn generate_validation() {
    let dialog = |n: &str, c: &str, none: bool, p: &str, q: &str| {
        let mut d = SshDialog::generate(&[]);
        if let SshDialog::Generate {
            name,
            comment,
            no_passphrase,
            passphrase,
            confirm,
            ..
        } = &mut d
        {
            *name = n.into();
            *comment = c.into();
            *no_passphrase = none;
            set(passphrase, p);
            set(confirm, q);
        }
        d
    };
    let error = |d: SshDialog| d.command_for().err();
    let bad = Some(MSG_BAD_KEY_NAME.to_string());
    assert_eq!(error(dialog("known_hosts", "", true, "", "")), bad);
    assert_eq!(error(dialog("../x", "", true, "", "")), bad);
    assert_eq!(
        error(dialog("k", "a\nb", true, "", "")).as_deref(),
        Some(MSG_COMMENT_LINE)
    );
    assert!(error(dialog("k", "", false, "", "")).is_some(), "empty");
    assert!(
        error(dialog("k", "", false, PASS, OTHER)).is_some(),
        "mismatch"
    );
    let Ok(Command::GenerateSshKey(k)) = dialog("k", "", true, "", "").command_for() else {
        panic!("expected a key without passphrase");
    };
    assert!(k.passphrase.is_none());
}

/// Import resolves `~` and keeps the file name unless a valid name is given.
#[test]
fn import_command() {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut d = SshDialog::import();
    assert!(d.command_for().is_err(), "path required");
    if let SshDialog::Import { source, .. } = &mut d {
        *source = "~/keys/id_work".into();
    }
    let Ok(Command::ImportSshKey { source, name }) = d.command_for() else {
        panic!("expected ImportSshKey");
    };
    if !home.is_empty() {
        assert_eq!(source, PathBuf::from(&home).join("keys/id_work"));
    }
    assert!(name.is_none());
    if let SshDialog::Import { name, .. } = &mut d {
        *name = "bad/name".into();
    }
    assert_eq!(d.command_for().err().as_deref(), Some(MSG_BAD_KEY_NAME));
    if let SshDialog::Import { name, .. } = &mut d {
        *name = " work ".into();
    }
    let Ok(Command::ImportSshKey { name, .. }) = d.command_for() else {
        panic!("expected ImportSshKey");
    };
    assert_eq!(name.as_deref(), Some("work"));
}

/// Adding an encrypted key needs its passphrase; an unencrypted one sends
/// none; the lifetime is passed through.
#[test]
fn agent_add_command() {
    let mut enc = SshDialog::agent_add(&key("k", Some(true)));
    assert!(enc.asks_passphrase() && enc.reopens_when_wrong());
    assert_eq!(
        enc.command_for().err().as_deref(),
        Some(MSG_NO_KEY_PASSPHRASE)
    );
    enc.fill(PASS);
    if let SshDialog::AgentAdd { lifetime, .. } = &mut enc {
        *lifetime = LIFETIMES[2].0;
    }
    let Ok(Command::AgentAdd {
        name,
        passphrase,
        lifetime_secs,
    }) = enc.command_for()
    else {
        panic!("expected AgentAdd");
    };
    assert_eq!((name.as_str(), text(&passphrase)), ("k", Some(PASS)));
    assert_eq!(lifetime_secs, Some(3600));
    let plain = SshDialog::agent_add(&key("p", Some(false)));
    assert!(!plain.asks_passphrase() && plain.reopens_when_wrong());
    let Ok(Command::AgentAdd { passphrase, .. }) = plain.command_for() else {
        panic!("expected AgentAdd");
    };
    assert!(passphrase.is_none());
}

/// Export copies as is, or re-encrypts (the current passphrase only for
/// an encrypted key); the remembered passphrase is the current one.
#[test]
fn export_command() {
    let mut d = SshDialog::export(&key("k", Some(true)));
    let Ok(Command::ExportSshPrivate {
        passphrase,
        new_passphrase,
        dest,
        ..
    }) = d.command_for()
    else {
        panic!("expected a verbatim copy");
    };
    assert!(passphrase.is_none() && new_passphrase.is_none());
    assert!(dest.ends_with("k-export"));
    assert!(!d.asks_passphrase());
    if let SshDialog::Export {
        reencrypt,
        new_passphrase,
        confirm,
        ..
    } = &mut d
    {
        *reencrypt = true;
        set(new_passphrase, OTHER);
        set(confirm, OTHER);
    }
    assert!(d.asks_passphrase());
    assert_eq!(
        d.command_for().err().as_deref(),
        Some(MSG_NO_KEY_PASSPHRASE)
    );
    d.fill(PASS);
    let Ok(Command::ExportSshPrivate {
        passphrase,
        new_passphrase,
        ..
    }) = d.command_for()
    else {
        panic!("expected a re-encrypted copy");
    };
    assert_eq!(
        (text(&passphrase), text(&new_passphrase)),
        (Some(PASS), Some(OTHER))
    );
    let plain = SshDialog::export(&key("p", Some(false)));
    assert!(matches!(
        plain,
        SshDialog::Export {
            reencrypt: true,
            ..
        }
    ));
    assert!(!plain.asks_passphrase());
}

/// Changing the passphrase of an encrypted key needs the old one; removing
/// it needs the explicit checkbox; an unencrypted key needs a backup
/// passphrase instead (filled by the remembered one).
#[test]
fn change_passphrase_command() {
    let mut d = SshDialog::change_passphrase(&key("k", Some(true)));
    assert!(d.asks_passphrase() && d.reopens_when_wrong());
    if let SshDialog::ChangePassphrase { new, confirm, .. } = &mut d {
        set(new, OTHER);
        set(confirm, OTHER);
    }
    assert_eq!(
        d.command_for().err().as_deref(),
        Some(MSG_NO_KEY_PASSPHRASE)
    );
    d.fill(PASS);
    let Ok(Command::ChangeSshPassphrase {
        old,
        new,
        allow_unencrypted,
        backup_passphrase,
        ..
    }) = d.command_for()
    else {
        panic!("expected ChangeSshPassphrase");
    };
    assert_eq!((text(&old), text(&new)), (Some(PASS), Some(OTHER)));
    assert!(!allow_unencrypted && backup_passphrase.is_none());
    if let SshDialog::ChangePassphrase { remove, .. } = &mut d {
        *remove = true;
    }
    let Ok(Command::ChangeSshPassphrase {
        new,
        allow_unencrypted,
        ..
    }) = d.command_for()
    else {
        panic!("expected a removal");
    };
    assert!(new.is_none() && allow_unencrypted);

    let mut plain = SshDialog::change_passphrase(&key("p", Some(false)));
    if let SshDialog::ChangePassphrase {
        new,
        confirm,
        remove,
        ..
    } = &mut plain
    {
        set(new, OTHER);
        set(confirm, OTHER);
        *remove = true;
    }
    assert!(plain.command_for().is_err(), "backup passphrase required");
    plain.fill(PASS);
    let Ok(Command::ChangeSshPassphrase {
        old,
        new,
        allow_unencrypted,
        backup_passphrase,
        ..
    }) = plain.command_for()
    else {
        panic!("expected ChangeSshPassphrase");
    };
    assert!(old.is_none());
    assert_eq!(text(&new), Some(OTHER));
    assert!(
        !allow_unencrypted,
        "an unencrypted key cannot lose a passphrase"
    );
    assert_eq!(text(&backup_passphrase), Some(PASS));
}

/// Deleting an unencrypted private key asks a backup passphrase upfront;
/// an encrypted key or a lone public key does not.
#[test]
fn delete_command() {
    let mut plain = SshDialog::delete(&key("p", Some(false)), true);
    let SshDialog::Delete {
        files, in_agent, ..
    } = &plain
    else {
        panic!("expected Delete");
    };
    assert_eq!(files, &["p", "p.pub"]);
    assert!(*in_agent);
    assert!(plain.asks_passphrase() && !plain.reopens_when_wrong());
    assert!(plain.command_for().is_err());
    plain.fill(PASS);
    let Ok(Command::DeleteSshKey {
        name,
        backup_passphrase,
    }) = plain.command_for()
    else {
        panic!("expected DeleteSshKey");
    };
    assert_eq!((name.as_str(), text(&backup_passphrase)), ("p", Some(PASS)));
    for info in [key("e", Some(true)), key("orphan", None)] {
        let d = SshDialog::delete(&info, false);
        assert!(!d.asks_passphrase());
        let Ok(Command::DeleteSshKey {
            backup_passphrase, ..
        }) = d.command_for()
        else {
            panic!("expected DeleteSshKey");
        };
        assert!(backup_passphrase.is_none());
    }
}

/// A key found encrypted by the worker reopens its dialog asking the key
/// passphrase; clearing empties every field, new passphrases included.
#[test]
fn needing_key_passphrase_and_clear() {
    let d = SshDialog::agent_add(&key("k", Some(false))).needing_key_passphrase();
    assert!(d.asks_passphrase());
    let d = SshDialog::export(&key("k", Some(false))).needing_key_passphrase();
    assert!(matches!(
        d,
        SshDialog::Export {
            encrypted: true,
            reencrypt: true,
            ..
        }
    ));
    let mut c = SshDialog::change_passphrase(&key("k", Some(false))).needing_key_passphrase();
    assert!(matches!(
        c,
        SshDialog::ChangePassphrase {
            encrypted: true,
            ..
        }
    ));
    c.fill(PASS);
    if let SshDialog::ChangePassphrase { new, confirm, .. } = &mut c {
        set(new, OTHER);
        set(confirm, OTHER);
    }
    assert!(c.command_for().is_ok());
    c.clear_secrets();
    let SshDialog::ChangePassphrase {
        old, new, confirm, ..
    } = &c
    else {
        panic!("expected ChangePassphrase");
    };
    assert!(old.is_empty() && new.is_empty() && confirm.is_empty());
}

/// Lifetime labels come from the table; other values show seconds.
#[test]
fn lifetime_labels() {
    assert_eq!(lifetime_label(None), "Until removed");
    assert_eq!(lifetime_label(Some(3600)), "1 hour");
    assert_eq!(lifetime_label(Some(42)), "42 s");
}
