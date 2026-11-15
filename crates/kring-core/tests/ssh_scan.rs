//! Scanning SSH key fixtures (real files made by `ssh-keygen`, see the fixtures README).

use std::fs;
use std::path::{Path, PathBuf};

use kring_core::ssh::{SshAlgorithm, SshKeyInfo, scan_keys};

/// Directory with the committed fixtures.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ssh")
}

/// Copies the named fixture files into a fresh temp dir.
fn copy_fixtures(names: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for name in names {
        fs::copy(fixtures().join(name), dir.path().join(name)).unwrap();
    }
    dir
}

/// Finds a key by name.
fn find<'a>(keys: &'a [SshKeyInfo], name: &str) -> &'a SshKeyInfo {
    keys.iter()
        .find(|k| k.name == name)
        .unwrap_or_else(|| panic!("no key {name}"))
}

/// Every fixture key is described with all fields; decoys are ignored.
#[test]
fn scans_fixtures_with_all_fields() {
    let dir = fixtures();
    let keys = scan_keys(&dir).unwrap();
    let names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "id_ecdsa",
            "id_ed25519",
            "id_ed25519_enc",
            "id_legacy",
            "id_rsa",
            "orphan"
        ]
    );

    let ed = find(&keys, "id_ed25519");
    assert_eq!(ed.private_path, Some(dir.join("id_ed25519")));
    assert_eq!(ed.public_path, Some(dir.join("id_ed25519.pub")));
    assert_eq!(ed.algorithm, SshAlgorithm::Ed25519);
    assert_eq!(ed.bits, Some(256));
    assert_eq!(
        ed.fingerprint,
        "SHA256:nn+sXDCeTItgzR4iEno+KHj3w0HTbYHTbgBq7FihJ0Y"
    );
    assert_eq!(ed.comment, "fixture@kring");
    assert_eq!(ed.encrypted, Some(false));
    assert!(!ed.legacy_format);

    let enc = find(&keys, "id_ed25519_enc");
    assert_eq!(
        enc.fingerprint,
        "SHA256:whTjq5QLKwBNlAXAVW1i1f/l4G8UiBWXcFz5xZ+aUvs"
    );
    assert_eq!(enc.comment, "fixture-enc@kring");
    assert_eq!(enc.encrypted, Some(true));
    assert!(!enc.legacy_format);

    let rsa = find(&keys, "id_rsa");
    assert_eq!(rsa.algorithm, SshAlgorithm::Rsa);
    assert_eq!(rsa.bits, Some(3072));
    assert_eq!(
        rsa.fingerprint,
        "SHA256:IxDXKd/IhtV5EYUkJ/VDLJjsgNX6iZC7AeHcwcpWSBY"
    );
    assert_eq!(rsa.comment, "fixture-rsa@kring");
    assert_eq!(rsa.encrypted, Some(false));

    let ec = find(&keys, "id_ecdsa");
    assert_eq!(ec.algorithm, SshAlgorithm::EcdsaP256);
    assert_eq!(ec.bits, Some(256));
    assert_eq!(
        ec.fingerprint,
        "SHA256:XVvQt8TXeBprWzkEl5I5BL0FEWeVpssrR9mjX3Lqyag"
    );

    let legacy = find(&keys, "id_legacy");
    assert!(legacy.legacy_format);
    assert_eq!(legacy.algorithm, SshAlgorithm::Rsa);
    assert_eq!(legacy.bits, Some(2048));
    assert_eq!(
        legacy.fingerprint,
        "SHA256:zcg/EsAdWcsuQyfR3WDLOaWCcoEIcIWABdQkoIkcSvU"
    );
    assert_eq!(legacy.encrypted, Some(false));
    assert!(legacy.private_path.is_some());

    let orphan = find(&keys, "orphan");
    assert_eq!(orphan.private_path, None);
    assert_eq!(orphan.public_path, Some(dir.join("orphan.pub")));
    assert_eq!(orphan.encrypted, None);
    assert!(!orphan.legacy_format);
    assert_eq!(
        orphan.fingerprint,
        "SHA256:fOuhEfeWEMg93GyS5o1FTgk1d6tgAfGJV+s1AgEvuKA"
    );
}

/// Without the `.pub`, OpenSSH keys (even encrypted) expose their public part.
#[test]
fn private_only_openssh_keys_expose_public_part() {
    let dir = copy_fixtures(&["id_ed25519", "id_ed25519_enc", "id_rsa"]);
    let keys = scan_keys(dir.path()).unwrap();
    assert_eq!(keys.len(), 3);
    let enc = find(&keys, "id_ed25519_enc");
    assert_eq!(enc.public_path, None);
    assert_eq!(enc.encrypted, Some(true));
    assert_eq!(enc.algorithm, SshAlgorithm::Ed25519);
    assert_eq!(
        enc.fingerprint,
        "SHA256:whTjq5QLKwBNlAXAVW1i1f/l4G8UiBWXcFz5xZ+aUvs"
    );
    let rsa = find(&keys, "id_rsa");
    assert_eq!(rsa.bits, Some(3072));
    assert_eq!(
        rsa.fingerprint,
        "SHA256:IxDXKd/IhtV5EYUkJ/VDLJjsgNX6iZC7AeHcwcpWSBY"
    );
}

/// A legacy PEM key without a `.pub` has no algorithm or fingerprint to show.
#[test]
fn legacy_without_pub_is_other_legacy() {
    let dir = copy_fixtures(&["id_legacy"]);
    let keys = scan_keys(dir.path()).unwrap();
    assert_eq!(keys.len(), 1);
    let k = &keys[0];
    assert!(k.legacy_format);
    assert_eq!(k.algorithm, SshAlgorithm::Other("legacy".into()));
    assert_eq!(k.bits, None);
    assert_eq!(k.fingerprint, "");
    assert_eq!(k.encrypted, Some(false));
}

/// Traditional PEM with `Proc-Type: 4,ENCRYPTED` and PKCS#8 encrypted keys count as encrypted.
#[test]
fn legacy_encrypted_markers_are_detected() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("pem_enc"),
        "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("p8_enc"),
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("p8_plain"),
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    let keys = scan_keys(dir.path()).unwrap();
    assert_eq!(find(&keys, "pem_enc").encrypted, Some(true));
    assert_eq!(find(&keys, "p8_enc").encrypted, Some(true));
    assert_eq!(find(&keys, "p8_plain").encrypted, Some(false));
    assert!(keys.iter().all(|k| k.legacy_format));
}

/// Decoys alone yield nothing, and so do garbage, oversized and invalid `.pub` files.
#[test]
fn decoys_and_garbage_are_ignored() {
    let dir = copy_fixtures(&["authorized_keys", "known_hosts", "config"]);
    fs::write(dir.path().join("notes.txt"), "hello").unwrap();
    fs::write(dir.path().join("bad.pub"), "not a key").unwrap();
    fs::write(dir.path().join("binary"), [0u8, 159, 146, 150]).unwrap();
    let huge = format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}",
        "A".repeat(70 * 1024)
    );
    fs::write(dir.path().join("huge"), huge).unwrap();
    fs::write(
        dir.path().join("broken"),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n",
    )
    .unwrap();
    fs::create_dir(dir.path().join("subdir")).unwrap();
    assert!(scan_keys(dir.path()).unwrap().is_empty());
}

/// Symlinks (to keys or anywhere) are never followed or listed.
#[test]
fn symlinks_are_ignored() {
    let outside = copy_fixtures(&["id_ed25519", "id_ed25519.pub"]);
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path().join("id_ed25519"), dir.path().join("linked"))
        .unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("id_ed25519.pub"),
        dir.path().join("linked.pub"),
    )
    .unwrap();
    assert!(scan_keys(dir.path()).unwrap().is_empty());
}

/// A missing directory is an empty list, not an error.
#[test]
fn missing_dir_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    assert!(scan_keys(&dir.path().join("nope")).unwrap().is_empty());
}

/// An unreadable file is skipped; the other keys are still listed.
#[test]
fn unreadable_file_is_skipped() {
    use std::os::unix::fs::PermissionsExt;
    let dir = copy_fixtures(&["id_ed25519", "id_ed25519.pub", "id_rsa"]);
    let locked = dir.path().join("id_rsa");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&locked).is_ok() {
        eprintln!("skipped: running as root, mode 000 is readable");
        return;
    }
    let keys = scan_keys(dir.path()).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].name, "id_ed25519");
}

/// Names with dots pair correctly and do not clash with the base name.
#[test]
fn dotted_names_pair_by_full_name() {
    let dir = copy_fixtures(&["id_ed25519", "id_ed25519.pub"]);
    fs::copy(fixtures().join("id_rsa"), dir.path().join("id_ed25519.old")).unwrap();
    fs::copy(
        fixtures().join("id_rsa.pub"),
        dir.path().join("id_ed25519.old.pub"),
    )
    .unwrap();
    let keys = scan_keys(dir.path()).unwrap();
    assert_eq!(keys.len(), 2);
    let base = find(&keys, "id_ed25519");
    assert_eq!(base.algorithm, SshAlgorithm::Ed25519);
    let old = find(&keys, "id_ed25519.old");
    assert_eq!(old.algorithm, SshAlgorithm::Rsa);
    assert_eq!(old.public_path, Some(dir.path().join("id_ed25519.old.pub")));
}

/// A `.pub` holding another key is flagged; the private key wins.
#[test]
fn mismatched_pub_is_flagged() {
    let dir = copy_fixtures(&["id_ed25519", "id_ed25519.pub"]);
    fs::copy(
        fixtures().join("id_rsa.pub"),
        dir.path().join("id_ed25519.pub"),
    )
    .unwrap();
    let keys = scan_keys(dir.path()).unwrap();
    let k = find(&keys, "id_ed25519");
    assert!(k.pub_mismatch);
    assert_eq!(k.algorithm, SshAlgorithm::Ed25519);
    assert_eq!(
        k.fingerprint,
        "SHA256:nn+sXDCeTItgzR4iEno+KHj3w0HTbYHTbgBq7FihJ0Y"
    );
    assert_eq!(k.comment, "fixture@kring");
    assert!(!find(&scan_keys(&fixtures()).unwrap(), "id_ed25519").pub_mismatch);
}
