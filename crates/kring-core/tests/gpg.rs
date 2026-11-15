//! gpg runner and key listing against the real `gpg` binary in temp home directories.
//!
//! Every test uses its own 0700 home directory ([`gpg_home::TempGnupgHome`]), so the
//! user's `~/.gnupg` and agent are never touched.

mod gpg_home;

use kring_core::KringError;
use kring_core::gpg::{GpgAlgorithm, TIMEOUT_DEFAULT, TIMEOUT_KEYGEN, list_keys};
use kring_core::model::SecretValue;

use gpg_home::{TempGnupgHome, kill_daemons, remove_socket_dir};

/// Passphrase of generated test keys.
const FIXTURE_PW: &str = "fixture-pw";

/// User id of the generated test key.
const TEST_UID: &str = "Kring Test <kring-test@example.invalid>";

/// A generated key is listed with its secret; its public export imported elsewhere is not.
#[test]
fn generate_list_export_import() {
    let Some(home) = TempGnupgHome::new() else {
        eprintln!("SKIPPED: gpg is not installed");
        return;
    };
    assert!(list_keys(&home.runner).unwrap().is_empty());

    let pw = SecretValue::from_text(FIXTURE_PW);
    let created = home
        .runner
        .run(
            ["--quick-gen-key", TEST_UID, "default", "default", "never"],
            None,
            Some(&pw),
            TIMEOUT_KEYGEN,
        )
        .unwrap();
    assert!(created.success(), "{}", created.stderr_text());
    assert!(created.has_status("KEY_CREATED"));

    let keys = list_keys(&home.runner).unwrap();
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    assert!(key.secret);
    assert!(!key.card);
    assert_eq!(key.fingerprint.len(), 40);
    assert!(key.fingerprint.ends_with(&key.key_id));
    assert_eq!(key.uids.len(), 1);
    assert_eq!(key.uids[0].uid, TEST_UID);
    assert_eq!(key.expires, None);
    assert!(key.created > 0);
    assert!(matches!(key.algorithm, GpgAlgorithm::EdDsa(_)), "{key:?}");
    assert_eq!(key.subkeys.len(), 1);
    assert_eq!(key.subkeys[0].capabilities, "e");
    assert_eq!(key.subkeys[0].fingerprint.len(), 40);

    let export = home
        .runner
        .run(
            ["--armor", "--export", key.fingerprint.as_str()],
            None,
            None,
            TIMEOUT_DEFAULT,
        )
        .unwrap();
    assert!(export.success(), "{}", export.stderr_text());
    assert!(
        export
            .stdout
            .starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
    );

    let Some(other) = TempGnupgHome::new() else {
        unreachable!("gpg was found above")
    };
    let imported = other
        .runner
        .run(
            ["--import"],
            Some(&export.stdout[..]),
            None,
            TIMEOUT_DEFAULT,
        )
        .unwrap();
    assert!(imported.success(), "{}", imported.stderr_text());
    assert!(imported.has_status("IMPORT_OK"));

    let listed = list_keys(&other.runner).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].fingerprint, key.fingerprint);
    assert!(!listed[0].secret);
    assert_eq!(listed[0].uids[0].uid, TEST_UID);
}

/// A failing listing (unusable home directory) is an error, not an empty list.
#[test]
fn listing_in_a_missing_home_fails() {
    let Some(home) = TempGnupgHome::new() else {
        eprintln!("SKIPPED: gpg is not installed");
        return;
    };
    let missing = home.dir.path().join("absent");
    let runner = home.runner.clone().with_homedir(missing.clone());
    let r = list_keys(&runner);
    kill_daemons(&home.gpgconf(), &missing);
    remove_socket_dir(&home.gpgconf(), &missing);
    assert!(
        matches!(&r, Err(KringError::Gpg(m)) if m.starts_with("--list-keys failed")),
        "{r:?}"
    );
}
