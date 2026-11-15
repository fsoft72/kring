//! SSH key operations on copies of the fixtures, inside temp dirs only.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use kring_core::KringError;
use kring_core::backup::{BackupInfo, BackupManager};
use kring_core::model::SecretValue;
use kring_core::ssh::{
    MSG_KEY_PASSPHRASE_REQUIRED, MSG_WRONG_KEY_PASSPHRASE, NewKey, SshAlgorithm, SshKeyInfo,
    change_passphrase, delete_key, export_private, export_public, generate_key, import_key,
    scan_keys,
};
use sha2::{Digest, Sha256};
use ssh_key::{PrivateKey, PublicKey};

/// Passphrase of the encrypted fixture.
const FIXTURE_PW: &str = "fixture-pw";
/// Passphrase protecting sensitive backup copies in these tests.
const BACKUP_PW: &str = "backup-pw";

/// Directory with the committed fixtures.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ssh")
}

/// Temp root with an `ssh` dir holding copies of `names` and a backup manager.
struct Env {
    _tmp: tempfile::TempDir,
    ssh: PathBuf,
    other: PathBuf,
    mgr: BackupManager,
}

/// Builds an [`Env`] with the named fixtures copied into its ssh dir.
fn env(names: &[&str]) -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let ssh = tmp.path().join("ssh");
    let other = tmp.path().join("other");
    fs::create_dir(&ssh).unwrap();
    fs::create_dir(&other).unwrap();
    for name in names {
        fs::copy(fixtures().join(name), ssh.join(name)).unwrap();
    }
    let mgr = BackupManager {
        root: tmp.path().join("backups"),
        keep: 20,
    };
    Env {
        _tmp: tmp,
        ssh,
        other,
        mgr,
    }
}

/// Scans `dir` and returns the key called `name`.
fn key(dir: &Path, name: &str) -> SshKeyInfo {
    scan_keys(dir)
        .unwrap()
        .into_iter()
        .find(|k| k.name == name)
        .unwrap_or_else(|| panic!("no key {name}"))
}

/// Text secret.
fn pw(text: &str) -> SecretValue {
    SecretValue::from_text(text)
}

/// Permission bits of `path`.
fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Asserts `result` failed with `InvalidInput(expected)`.
fn assert_invalid<T: std::fmt::Debug>(result: kring_core::error::Result<T>, expected: &str) {
    match result {
        Err(KringError::InvalidInput(msg)) => assert_eq!(msg, expected),
        other => panic!("expected InvalidInput({expected}), got {other:?}"),
    }
}

/// Asserts `result` failed with any `InvalidInput`.
fn assert_any_invalid<T: std::fmt::Debug>(result: kring_core::error::Result<T>) {
    assert!(
        matches!(result, Err(KringError::InvalidInput(_))),
        "{result:?}"
    );
}

/// New key request without a passphrase.
fn new_key(name: &str, algorithm: SshAlgorithm) -> NewKey {
    NewKey {
        name: name.into(),
        algorithm,
        rsa_bits: 3072,
        comment: format!("{name}@test"),
        passphrase: None,
    }
}

/// Generating each supported algorithm writes a 0600/0644 pair that scans back.
#[test]
fn generate_each_algorithm() {
    let e = env(&[]);
    let cases = [
        ("k_ed", SshAlgorithm::Ed25519, 256),
        ("k_p256", SshAlgorithm::EcdsaP256, 256),
        ("k_p384", SshAlgorithm::EcdsaP384, 384),
        ("k_rsa", SshAlgorithm::Rsa, 3072),
    ];
    for (name, algorithm, bits) in cases {
        let info = generate_key(&e.ssh, &new_key(name, algorithm.clone())).unwrap();
        assert_eq!(info, key(&e.ssh, name));
        assert_eq!(info.algorithm, algorithm);
        assert_eq!(info.bits, Some(bits));
        assert_eq!(info.encrypted, Some(false));
        assert_eq!(info.comment, format!("{name}@test"));
        assert!(info.fingerprint.starts_with("SHA256:"));
        assert_eq!(mode(info.private_path.as_ref().unwrap()), 0o600);
        assert_eq!(mode(info.public_path.as_ref().unwrap()), 0o644);
    }
    // No temporary files are left behind.
    let mut names: Vec<String> = fs::read_dir(&e.ssh)
        .unwrap()
        .map(|d| d.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 8, "{names:?}");
}

/// An RSA 4096 key gets 4096 bits; other RSA sizes are refused.
#[test]
fn generate_rsa_sizes() {
    let e = env(&[]);
    let mut k = new_key("big", SshAlgorithm::Rsa);
    k.rsa_bits = 4096;
    assert_eq!(generate_key(&e.ssh, &k).unwrap().bits, Some(4096));
    k.name = "small".into();
    k.rsa_bits = 2048;
    assert_any_invalid(generate_key(&e.ssh, &k));
    assert!(!e.ssh.join("small").exists());
}

/// An encrypted key needs its passphrase to decrypt and keeps its comment.
#[test]
fn generate_encrypted() {
    let e = env(&[]);
    let mut k = new_key("enc", SshAlgorithm::Ed25519);
    k.passphrase = Some(pw("s3cret"));
    let info = generate_key(&e.ssh, &k).unwrap();
    assert_eq!(info.encrypted, Some(true));
    assert_eq!(info.comment, "enc@test");
    let private = PrivateKey::read_openssh_file(info.private_path.as_ref().unwrap()).unwrap();
    assert!(private.decrypt("wrong").is_err());
    let clear = private.decrypt("s3cret").unwrap();
    assert_eq!(clear.comment(), "enc@test");
}

/// Bad names, reserved names, unsupported algorithms and existing files are refused.
#[test]
fn generate_refusals() {
    let e = env(&["id_ed25519", "id_ed25519.pub", "orphan.pub"]);
    let before = fs::read(e.ssh.join("id_ed25519")).unwrap();
    for name in [
        "",
        "a/b",
        "../x",
        "..",
        "a b",
        "config",
        "authorized_keys",
        "x.pub",
    ] {
        assert_any_invalid(generate_key(&e.ssh, &new_key(name, SshAlgorithm::Ed25519)));
    }
    assert_any_invalid(generate_key(
        &e.ssh,
        &new_key("p521", SshAlgorithm::EcdsaP521),
    ));
    // Existing private file, or an existing `.pub` without private file.
    assert_any_invalid(generate_key(
        &e.ssh,
        &new_key("id_ed25519", SshAlgorithm::Ed25519),
    ));
    assert_any_invalid(generate_key(
        &e.ssh,
        &new_key("orphan", SshAlgorithm::Ed25519),
    ));
    assert_eq!(fs::read(e.ssh.join("id_ed25519")).unwrap(), before);
    assert!(!e.ssh.join("orphan").exists());
    assert!(!e.ssh.join("p521").exists());
}

/// Import copies private and public verbatim and refuses to overwrite.
#[test]
fn import_with_public() {
    let e = env(&[]);
    let src = fixtures().join("id_ed25519");
    let info = import_key(&e.ssh, &src, None).unwrap();
    assert_eq!(info, key(&e.ssh, "id_ed25519"));
    assert_eq!(info.comment, "fixture@kring");
    assert_eq!(
        fs::read(e.ssh.join("id_ed25519")).unwrap(),
        fs::read(&src).unwrap()
    );
    assert_eq!(
        fs::read(e.ssh.join("id_ed25519.pub")).unwrap(),
        fs::read(fixtures().join("id_ed25519.pub")).unwrap()
    );
    assert_eq!(mode(&e.ssh.join("id_ed25519")), 0o600);
    assert_eq!(mode(&e.ssh.join("id_ed25519.pub")), 0o644);
    assert_any_invalid(import_key(&e.ssh, &src, None));
    let renamed = import_key(&e.ssh, &src, Some("work")).unwrap();
    assert_eq!(renamed.fingerprint, info.fingerprint);
}

/// Without a `.pub` next to the source, the public key is derived.
#[test]
fn import_derives_public() {
    let e = env(&[]);
    let src = e.other.join("lonely");
    fs::copy(fixtures().join("id_ed25519_enc"), &src).unwrap();
    let info = import_key(&e.ssh, &src, Some("enc")).unwrap();
    assert_eq!(info.encrypted, Some(true));
    let expected = PublicKey::read_openssh_file(&fixtures().join("id_ed25519_enc.pub")).unwrap();
    let written = PublicKey::read_openssh_file(&e.ssh.join("enc.pub")).unwrap();
    assert_eq!(written.key_data(), expected.key_data());
}

/// Non-keys, legacy keys, symlinks and bad names are refused on import.
#[test]
fn import_refusals() {
    let e = env(&[]);
    for decoy in ["authorized_keys", "known_hosts", "config", "id_ed25519.pub"] {
        assert_any_invalid(import_key(&e.ssh, &fixtures().join(decoy), Some("x")));
    }
    assert_any_invalid(import_key(&e.ssh, &fixtures().join("id_legacy"), None));
    let link = e.other.join("link");
    std::os::unix::fs::symlink(fixtures().join("id_ed25519"), &link).unwrap();
    assert!(import_key(&e.ssh, &link, Some("y")).is_err());
    assert_any_invalid(import_key(
        &e.ssh,
        &fixtures().join("id_ed25519"),
        Some("config"),
    ));
    assert_eq!(fs::read_dir(&e.ssh).unwrap().count(), 0);
}

/// The public export is the OpenSSH line, also for a key without `.pub`.
#[test]
fn export_public_line() {
    let e = env(&["id_ed25519", "id_ed25519.pub", "id_rsa"]);
    let line = export_public(&key(&e.ssh, "id_ed25519")).unwrap();
    let expected = fs::read_to_string(fixtures().join("id_ed25519.pub")).unwrap();
    assert_eq!(line, expected.trim());
    let derived = export_public(&key(&e.ssh, "id_rsa")).unwrap();
    let rsa = PublicKey::read_openssh_file(&fixtures().join("id_rsa.pub")).unwrap();
    assert_eq!(
        PublicKey::from_openssh(&derived).unwrap().key_data(),
        rsa.key_data()
    );
    assert!(!derived.contains('\n'));
}

/// The private export is a 0600 copy, re-encrypted with the new passphrase on request.
#[test]
fn export_private_copies() {
    let e = env(&[
        "id_ed25519",
        "id_ed25519_enc",
        "id_ed25519_enc.pub",
        "id_legacy",
    ]);
    let plain = key(&e.ssh, "id_ed25519");
    let verbatim = e.other.join("verbatim");
    export_private(&plain, &verbatim, None, None).unwrap();
    assert_eq!(
        fs::read(&verbatim).unwrap(),
        fs::read(e.ssh.join("id_ed25519")).unwrap()
    );
    assert_eq!(mode(&verbatim), 0o600);
    // Never overwrites.
    assert_any_invalid(export_private(&plain, &verbatim, None, None));

    let enc = key(&e.ssh, "id_ed25519_enc");
    let re = e.other.join("re");
    let new = pw("new-pw");
    assert_invalid(
        export_private(&enc, &re, Some(&pw("nope")), Some(&new)),
        MSG_WRONG_KEY_PASSPHRASE,
    );
    assert_invalid(
        export_private(&enc, &re, None, Some(&new)),
        MSG_KEY_PASSPHRASE_REQUIRED,
    );
    assert!(!re.exists());
    export_private(&enc, &re, Some(&pw(FIXTURE_PW)), Some(&new)).unwrap();
    let exported = PrivateKey::read_openssh_file(&re).unwrap();
    assert!(exported.is_encrypted());
    assert!(exported.decrypt(FIXTURE_PW).is_err());
    let clear = exported.decrypt("new-pw").unwrap();
    assert_eq!(
        clear.public_key().key_data(),
        exported.public_key().key_data()
    );
    assert_eq!(mode(&re), 0o600);

    // An unencrypted key can be exported encrypted.
    let plain_enc = e.other.join("plain_enc");
    export_private(&plain, &plain_enc, None, Some(&new)).unwrap();
    let k = PrivateKey::read_openssh_file(&plain_enc).unwrap();
    assert!(k.decrypt("new-pw").is_ok());

    assert_any_invalid(export_private(
        &key(&e.ssh, "id_legacy"),
        &e.other.join("legacy"),
        None,
        None,
    ));
}

/// Reads a stored backup copy, decrypting it with the test passphrase when encrypted.
fn backup_bytes(info: &BackupInfo, original: &Path) -> Vec<u8> {
    let entry = info.files.iter().find(|f| f.original == original).unwrap();
    let pass = entry.encrypted.then(|| pw(BACKUP_PW));
    kring_core::backup::read_backup_file(info, entry, pass.as_ref())
        .unwrap()
        .to_vec()
}

/// Changing the passphrase backs up first and replaces the private key only.
#[test]
fn change_passphrase_encrypted_key() {
    let e = env(&["id_ed25519_enc", "id_ed25519_enc.pub"]);
    let path = e.ssh.join("id_ed25519_enc");
    let before = fs::read(&path).unwrap();
    let info = key(&e.ssh, "id_ed25519_enc");
    let new = pw("changed");

    assert_invalid(
        change_passphrase(
            &e.mgr,
            &e.ssh,
            &info,
            Some(&pw("wrong")),
            Some(&new),
            false,
            None,
        ),
        MSG_WRONG_KEY_PASSPHRASE,
    );
    assert_invalid(
        change_passphrase(&e.mgr, &e.ssh, &info, None, Some(&new), false, None),
        MSG_KEY_PASSPHRASE_REQUIRED,
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(e.mgr.list().unwrap().is_empty());

    let old = pw(FIXTURE_PW);
    let backup =
        change_passphrase(&e.mgr, &e.ssh, &info, Some(&old), Some(&new), false, None).unwrap();
    assert_eq!(backup.reason, "change-ssh-passphrase");
    assert_eq!(backup.files.len(), 1);
    // An encrypted key is already protected: stored verbatim.
    assert!(!backup.files[0].encrypted);
    assert_eq!(backup_bytes(&backup, &path), before);
    let changed = PrivateKey::read_openssh_file(&path).unwrap();
    assert!(changed.decrypt(FIXTURE_PW).is_err());
    assert_eq!(
        changed.decrypt("changed").unwrap().comment(),
        "fixture-enc@kring"
    );
    assert_eq!(mode(&path), 0o600);
    let after = key(&e.ssh, "id_ed25519_enc");
    assert_eq!(after.fingerprint, info.fingerprint);
    assert_eq!(fs::read_dir(&e.ssh).unwrap().count(), 2);
}

/// Removing encryption needs the explicit flag; encrypting a plain key backs it up with age.
#[test]
fn change_passphrase_plain_and_removal() {
    let e = env(&["id_ed25519", "id_ed25519.pub"]);
    let path = e.ssh.join("id_ed25519");
    let before = fs::read(&path).unwrap();
    let info = key(&e.ssh, "id_ed25519");
    let new = pw("now-protected");
    let backup_pw = pw(BACKUP_PW);

    // The plaintext private key is sensitive: no backup passphrase, no change.
    assert!(matches!(
        change_passphrase(&e.mgr, &e.ssh, &info, None, Some(&new), false, None),
        Err(KringError::PassphraseRequired)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);

    let backup = change_passphrase(
        &e.mgr,
        &e.ssh,
        &info,
        None,
        Some(&new),
        false,
        Some(&backup_pw),
    )
    .unwrap();
    assert!(backup.files[0].encrypted);
    assert_eq!(backup_bytes(&backup, &path), before);
    assert!(PrivateKey::read_openssh_file(&path).unwrap().is_encrypted());

    // Removing the passphrase again needs the explicit flag.
    let info = key(&e.ssh, "id_ed25519");
    let protected = fs::read(&path).unwrap();
    assert_any_invalid(change_passphrase(
        &e.mgr,
        &e.ssh,
        &info,
        Some(&new),
        None,
        false,
        None,
    ));
    assert_eq!(fs::read(&path).unwrap(), protected);
    change_passphrase(&e.mgr, &e.ssh, &info, Some(&new), None, true, None).unwrap();
    assert_eq!(key(&e.ssh, "id_ed25519").encrypted, Some(false));
}

/// Delete backs up both files (unencrypted private key with age), then removes them.
#[test]
fn delete_plain_key() {
    let e = env(&["id_ed25519", "id_ed25519.pub"]);
    let private = e.ssh.join("id_ed25519");
    let public = e.ssh.join("id_ed25519.pub");
    let (priv_bytes, pub_bytes) = (fs::read(&private).unwrap(), fs::read(&public).unwrap());
    let info = key(&e.ssh, "id_ed25519");

    assert!(matches!(
        delete_key(&e.mgr, &e.ssh, &info, None),
        Err(KringError::PassphraseRequired)
    ));
    assert!(private.exists() && public.exists());

    let backup = delete_key(&e.mgr, &e.ssh, &info, Some(&pw(BACKUP_PW))).unwrap();
    assert_eq!(backup.reason, "delete-ssh-key");
    assert!(!private.exists() && !public.exists());
    let p = backup.files.iter().find(|f| f.original == private).unwrap();
    assert!(p.encrypted);
    assert_eq!(p.sha256, hex::encode(Sha256::digest(&priv_bytes)));
    let stored = fs::read(&p.stored).unwrap();
    assert!(!stored.starts_with(b"-----BEGIN"));
    assert_eq!(backup_bytes(&backup, &private), priv_bytes);
    let q = backup.files.iter().find(|f| f.original == public).unwrap();
    assert!(!q.encrypted);
    assert_eq!(fs::read(&q.stored).unwrap(), pub_bytes);
}

/// An encrypted key, an orphan `.pub` and a legacy key are deleted without a passphrase
/// (legacy unencrypted needs one).
#[test]
fn delete_other_kinds() {
    let e = env(&[
        "id_ed25519_enc",
        "id_ed25519_enc.pub",
        "orphan.pub",
        "id_legacy",
        "id_legacy.pub",
    ]);
    let enc = key(&e.ssh, "id_ed25519_enc");
    let backup = delete_key(&e.mgr, &e.ssh, &enc, None).unwrap();
    assert!(backup.files.iter().all(|f| !f.encrypted));
    assert!(!e.ssh.join("id_ed25519_enc").exists());

    delete_key(&e.mgr, &e.ssh, &key(&e.ssh, "orphan"), None).unwrap();
    assert!(!e.ssh.join("orphan.pub").exists());

    let legacy = key(&e.ssh, "id_legacy");
    assert!(matches!(
        delete_key(&e.mgr, &e.ssh, &legacy, None),
        Err(KringError::PassphraseRequired)
    ));
    let backup = delete_key(&e.mgr, &e.ssh, &legacy, Some(&pw(BACKUP_PW))).unwrap();
    assert!(backup.files.iter().any(|f| f.encrypted));
    assert_eq!(fs::read_dir(&e.ssh).unwrap().count(), 0);
}

/// Decoys, symlinks, paths outside the dir and stale infos are refused; nothing changes.
#[test]
fn destructive_ops_refuse_foreign_targets() {
    let e = env(&["id_ed25519", "id_ed25519.pub", "authorized_keys", "config"]);
    let real = key(&e.ssh, "id_ed25519");
    let pass = pw(BACKUP_PW);
    let new = pw("x");
    let try_both = |info: &SshKeyInfo| {
        assert_any_invalid(delete_key(&e.mgr, &e.ssh, info, Some(&pass)));
        assert_any_invalid(change_passphrase(
            &e.mgr,
            &e.ssh,
            info,
            None,
            Some(&new),
            false,
            Some(&pass),
        ));
    };

    // A decoy dressed up as a key.
    for decoy in ["authorized_keys", "config"] {
        let mut fake = real.clone();
        fake.name = decoy.into();
        fake.private_path = Some(e.ssh.join(decoy));
        fake.public_path = None;
        try_both(&fake);
    }
    // A key outside the ssh dir.
    fs::copy(fixtures().join("id_ed25519"), e.other.join("id_ed25519")).unwrap();
    let mut outside = real.clone();
    outside.private_path = Some(e.other.join("id_ed25519"));
    outside.public_path = None;
    try_both(&outside);
    // The real dir but another dir argument.
    assert_any_invalid(delete_key(&e.mgr, &e.other, &real, Some(&pass)));
    // A symlink in place of the key.
    let linked = e.ssh.join("linked");
    std::os::unix::fs::symlink(e.other.join("id_ed25519"), &linked).unwrap();
    let mut via_link = real.clone();
    via_link.name = "linked".into();
    via_link.private_path = Some(linked.clone());
    via_link.public_path = None;
    try_both(&via_link);
    // A stale info (fingerprint changed since the scan).
    let mut stale = real.clone();
    stale.fingerprint = "SHA256:stale".into();
    try_both(&stale);

    for name in ["id_ed25519", "id_ed25519.pub", "authorized_keys", "config"] {
        assert_eq!(
            fs::read(e.ssh.join(name)).unwrap(),
            fs::read(fixtures().join(name)).unwrap(),
            "{name}"
        );
    }
    assert!(linked.is_symlink() && e.other.join("id_ed25519").exists());
    assert!(e.mgr.list().unwrap().is_empty());
}
