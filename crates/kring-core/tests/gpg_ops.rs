//! GnuPG key operations against the real `gpg` binary in temp home directories.
//!
//! Every test uses its own 0700 homes ([`gpg_home::TempGnupgHome`]) and a backup
//! root in a temp dir, so the user's `~/.gnupg`, agent and backups are never touched.

mod gpg_home;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use kring_core::KringError;
use kring_core::backup::{BACKUP_KEEP, BackupInfo, BackupManager, read_backup_file};
use kring_core::gpg::{
    GpgAlgo, GpgAlgorithm, GpgKey, GpgRunner, MSG_GPG_PASSPHRASE_REQUIRED, MSG_LOOPBACK_REFUSED,
    MSG_PRIMARY_SECRET_UNAVAILABLE, MSG_WRONG_GPG_PASSPHRASE, TIMEOUT_DEFAULT, change_passphrase,
    create_key, delete_key, export_public, export_secret, import_keys, list_keys,
};
use kring_core::model::SecretValue;

use gpg_home::{TempGnupgHome, kill_daemons};

/// Passphrase of generated test keys.
const KEY_PW: &str = "key-pw-1";
/// Second key passphrase.
const NEW_PW: &str = "key-pw-2";
/// Passphrase protecting sensitive backup copies.
const BACKUP_PW: &str = "backup-pw";
/// User id of generated test keys.
const TEST_UID: &str = "Kring Ops <kring-ops@example.invalid>";
/// First line of an armored secret key export.
const SECRET_ARMOR: &[u8] = b"-----BEGIN PGP PRIVATE KEY BLOCK-----";
/// First line of an armored public key export.
const PUBLIC_ARMOR: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

/// Shorthand for a secret value.
fn pw(text: &str) -> SecretValue {
    SecretValue::from_text(text)
}

/// A temp home plus a backup manager in another temp dir.
struct Env {
    /// The GnuPG home.
    home: TempGnupgHome,
    /// Backups root parent.
    _backups: tempfile::TempDir,
    /// Backup manager writing below `_backups`.
    mgr: BackupManager,
}

impl Env {
    /// Builds an env; `None` when gpg is not installed.
    fn new() -> Option<Self> {
        let home = TempGnupgHome::new()?;
        let backups = tempfile::tempdir().unwrap();
        let mgr = BackupManager {
            root: backups.path().join("backups"),
            keep: BACKUP_KEEP,
        };
        Some(Self {
            home,
            _backups: backups,
            mgr,
        })
    }

    /// The runner of the home.
    fn runner(&self) -> &GpgRunner {
        &self.home.runner
    }

    /// Creates a default key protected with `passphrase` (or unprotected).
    fn key(&self, passphrase: Option<&str>) -> GpgKey {
        let pass = passphrase.map(pw);
        create_key(
            self.runner(),
            TEST_UID,
            GpgAlgo::default(),
            None,
            pass.as_ref(),
        )
        .unwrap()
    }
}

/// Skips the test (returns) when gpg is missing.
macro_rules! env_or_skip {
    () => {
        match Env::new() {
            Some(env) => env,
            None => {
                eprintln!("SKIPPED: gpg is not installed");
                return;
            }
        }
    };
}

/// Asserts that `r` is `InvalidInput(msg)`.
fn assert_msg<T: std::fmt::Debug>(r: kring_core::Result<T>, msg: &str) {
    assert!(
        matches!(&r, Err(KringError::InvalidInput(m)) if m == msg),
        "expected {msg:?}, got {r:?}"
    );
}

/// The key `fpr` as listed now, if any.
fn listed(runner: &GpgRunner, fpr: &str) -> Option<GpgKey> {
    list_keys(runner)
        .unwrap()
        .into_iter()
        .find(|k| k.fingerprint == fpr)
}

/// Reads the backup copy whose stored name ends with `suffix`.
fn backup_bytes(info: &BackupInfo, suffix: &str) -> Vec<u8> {
    let file = info
        .files
        .iter()
        .find(|f| f.stored.to_string_lossy().ends_with(suffix))
        .unwrap_or_else(|| panic!("no {suffix} in {info:?}"));
    read_backup_file(info, file, Some(&pw(BACKUP_PW)))
        .unwrap()
        .to_vec()
}

/// True when the secret export of `fpr` works with `passphrase`.
fn unlocks(runner: &GpgRunner, fpr: &str, passphrase: &str, dir: &Path) -> bool {
    let dest = dir.join(format!("probe-{passphrase}-{}.asc", rand_suffix()));
    export_secret(runner, fpr, &dest, Some(&pw(passphrase))).is_ok()
}

/// A process-unique suffix for probe files.
fn rand_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

/// Default keys are Ed25519 with a cv25519 encryption subkey; RSA keys get an RSA subkey.
#[test]
fn create_key_algorithms_and_expiry() {
    let env = env_or_skip!();
    let key = create_key(
        env.runner(),
        TEST_UID,
        GpgAlgo::Ed25519Cv25519,
        Some("2y"),
        Some(&pw(KEY_PW)),
    )
    .unwrap();
    assert_eq!(key.fingerprint.len(), 40);
    assert!(key.secret && key.primary_secret);
    assert_eq!(key.uids[0].uid, TEST_UID);
    assert!(matches!(&key.algorithm, GpgAlgorithm::EdDsa(c) if c == "ed25519"));
    assert!(key.capabilities.contains('s') && key.capabilities.contains('c'));
    assert!(key.expires.is_some());
    assert_eq!(key.subkeys.len(), 1);
    assert_eq!(key.subkeys[0].capabilities, "e");
    assert!(matches!(&key.subkeys[0].algorithm, GpgAlgorithm::Ecdh(c) if c == "cv25519"));
    assert!(key.subkeys[0].expires.is_some());

    let rsa = create_key(
        env.runner(),
        "Rsa Key <rsa@example.invalid>",
        GpgAlgo::Rsa3072,
        None,
        Some(&pw(KEY_PW)),
    )
    .unwrap();
    assert_eq!(rsa.algorithm, GpgAlgorithm::Rsa);
    assert_eq!(rsa.bits, 3072);
    assert_eq!(rsa.expires, None);
    assert_eq!(rsa.subkeys.len(), 1);
    assert_eq!(rsa.subkeys[0].algorithm, GpgAlgorithm::Rsa);
    assert_eq!(rsa.subkeys[0].capabilities, "e");
    assert_eq!(list_keys(env.runner()).unwrap().len(), 2);
}

/// A user id starting with a dash is a user id, not an option.
#[test]
fn create_key_with_dash_uid() {
    let env = env_or_skip!();
    let key = create_key(
        env.runner(),
        "-dash <dash@example.invalid>",
        GpgAlgo::default(),
        None,
        None,
    )
    .unwrap();
    assert_eq!(key.uids[0].uid, "-dash <dash@example.invalid>");
}

/// Public export is armored text; an unknown fingerprint is not found.
#[test]
fn export_public_key() {
    let env = env_or_skip!();
    let key = env.key(Some(KEY_PW));
    let text = export_public(env.runner(), &key.fingerprint).unwrap();
    assert!(text.starts_with(PUBLIC_ARMOR), "{text}");
    let lower = key.fingerprint.to_ascii_lowercase();
    assert_eq!(export_public(env.runner(), &lower).unwrap(), text);
    let r = export_public(env.runner(), &"A".repeat(40));
    assert!(matches!(r, Err(KringError::NotFound(_))), "{r:?}");
    let r = export_public(env.runner(), "ABCD");
    assert!(matches!(r, Err(KringError::InvalidInput(_))), "{r:?}");
}

/// Secret export needs the right passphrase and writes a new 0600 file.
#[test]
fn export_secret_key_and_import_elsewhere() {
    let env = env_or_skip!();
    let key = env.key(Some(KEY_PW));
    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("secret.asc");

    let r = export_secret(env.runner(), &key.fingerprint, &dest, Some(&pw("wrong-pw")));
    assert_msg(r, MSG_WRONG_GPG_PASSPHRASE);
    let r = export_secret(env.runner(), &key.fingerprint, &dest, None);
    assert_msg(r, MSG_GPG_PASSPHRASE_REQUIRED);
    assert!(!dest.exists(), "nothing written on failure");

    export_secret(env.runner(), &key.fingerprint, &dest, Some(&pw(KEY_PW))).unwrap();
    let meta = std::fs::metadata(&dest).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let bytes = std::fs::read(&dest).unwrap();
    assert!(bytes.starts_with(SECRET_ARMOR));
    let r = export_secret(env.runner(), &key.fingerprint, &dest, Some(&pw(KEY_PW)));
    assert!(matches!(r, Err(KringError::InvalidInput(m)) if m.contains("already exists")));

    let other = TempGnupgHome::new().unwrap();
    let report = import_keys(&other.runner, &bytes).unwrap();
    assert_eq!(report.imported, 1);
    assert_eq!(report.secret_imported, 1);
    assert_eq!(report.unchanged, 0);
    assert_eq!(report.fingerprints, std::slice::from_ref(&key.fingerprint));
    let imported = listed(&other.runner, &key.fingerprint).unwrap();
    assert!(imported.secret && imported.primary_secret);
    assert!(unlocks(&other.runner, &key.fingerprint, KEY_PW, out.path()));

    let again = import_keys(&other.runner, &bytes).unwrap();
    assert_eq!(again.imported, 0);
    assert_eq!(again.unchanged, 1);
    assert_eq!(again.secret_imported, 0);
    assert_eq!(again.fingerprints, std::slice::from_ref(&key.fingerprint));
}

/// Public keys import without secrets; garbage and empty input are refused.
#[test]
fn import_public_and_garbage() {
    let env = env_or_skip!();
    let key = env.key(None);
    let text = export_public(env.runner(), &key.fingerprint).unwrap();
    let other = TempGnupgHome::new().unwrap();
    let report = import_keys(&other.runner, text.as_bytes()).unwrap();
    assert_eq!(report.imported, 1);
    assert_eq!(report.secret_imported, 0);
    assert!(!listed(&other.runner, &key.fingerprint).unwrap().secret);

    let r = import_keys(&other.runner, b"not a key\n");
    assert!(matches!(r, Err(KringError::InvalidInput(_))), "{r:?}");
    let r = import_keys(&other.runner, b"");
    assert!(matches!(r, Err(KringError::InvalidInput(_))), "{r:?}");
}

/// Wrong or missing old passphrases change nothing and create no backup.
#[test]
fn change_passphrase_refusals() {
    let env = env_or_skip!();
    let key = env.key(Some(KEY_PW));
    let fpr = key.fingerprint.as_str();
    let (new, backup) = (pw(NEW_PW), pw(BACKUP_PW));

    let r = change_passphrase(
        env.runner(),
        &env.mgr,
        fpr,
        Some(&pw("wrong-pw")),
        &new,
        Some(&backup),
    );
    assert_msg(r, MSG_WRONG_GPG_PASSPHRASE);
    let r = change_passphrase(env.runner(), &env.mgr, fpr, None, &new, Some(&backup));
    assert_msg(r, MSG_GPG_PASSPHRASE_REQUIRED);
    let r = change_passphrase(env.runner(), &env.mgr, fpr, Some(&pw(KEY_PW)), &new, None);
    assert!(matches!(r, Err(KringError::PassphraseRequired)), "{r:?}");
    let r = change_passphrase(
        env.runner(),
        &env.mgr,
        fpr,
        Some(&pw(KEY_PW)),
        &pw(""),
        Some(&backup),
    );
    assert!(matches!(r, Err(KringError::InvalidInput(_))), "{r:?}");
    assert!(env.mgr.list().unwrap().is_empty(), "no backup written");

    let out = tempfile::tempdir().unwrap();
    assert!(
        unlocks(env.runner(), fpr, KEY_PW, out.path()),
        "passphrase unchanged"
    );
}

/// A changed passphrase protects primary and subkey; the age backup keeps the old one.
#[test]
fn change_passphrase_with_backup() {
    let env = env_or_skip!();
    let key = env.key(Some(KEY_PW));
    let fpr = key.fingerprint.as_str();
    let info = change_passphrase(
        env.runner(),
        &env.mgr,
        fpr,
        Some(&pw(KEY_PW)),
        &pw(NEW_PW),
        Some(&pw(BACKUP_PW)),
    )
    .unwrap();
    assert_eq!(info.reason, "change-gpg-passphrase");
    assert_eq!(info.files.len(), 2);
    let secret = info
        .files
        .iter()
        .find(|f| f.stored.to_string_lossy().ends_with(".secret.asc.age"))
        .unwrap();
    assert!(secret.encrypted);
    let stored = std::fs::read(&secret.stored).unwrap();
    assert!(
        !stored.starts_with(SECRET_ARMOR),
        "the stored copy is age encrypted"
    );
    assert!(backup_bytes(&info, ".public.asc").starts_with(PUBLIC_ARMOR.as_bytes()));

    let out = tempfile::tempdir().unwrap();
    assert!(unlocks(env.runner(), fpr, NEW_PW, out.path()));
    assert!(!unlocks(env.runner(), fpr, KEY_PW, out.path()));

    // The backup restores the key with its old passphrase.
    let other = TempGnupgHome::new().unwrap();
    let report = import_keys(&other.runner, &backup_bytes(&info, ".secret.asc.age")).unwrap();
    assert_eq!(report.secret_imported, 1);
    assert!(unlocks(&other.runner, fpr, KEY_PW, out.path()));
}

/// An unprotected key gets the new passphrase on primary and subkey; a given old one is ignored.
#[test]
fn change_passphrase_of_unprotected_key() {
    let env = env_or_skip!();
    let key = env.key(None);
    let fpr = key.fingerprint.as_str();
    change_passphrase(
        env.runner(),
        &env.mgr,
        fpr,
        Some(&pw("ignored-old")),
        &pw(NEW_PW),
        Some(&pw(BACKUP_PW)),
    )
    .unwrap();
    let out = tempfile::tempdir().unwrap();
    assert!(unlocks(env.runner(), fpr, NEW_PW, out.path()));
    assert!(!unlocks(env.runner(), fpr, "ignored-old", out.path()));
    let r = export_secret(env.runner(), fpr, &out.path().join("none.asc"), None);
    assert_msg(r, MSG_GPG_PASSPHRASE_REQUIRED);
}

/// Deleting a secret key needs both passphrases, backs it up and removes it.
#[test]
fn delete_secret_key_with_backup() {
    let env = env_or_skip!();
    let key = env.key(Some(KEY_PW));
    let fpr = key.fingerprint.as_str();

    let r = delete_key(env.runner(), &env.mgr, fpr, Some(&pw(KEY_PW)), None);
    assert!(matches!(r, Err(KringError::PassphraseRequired)), "{r:?}");
    let r = delete_key(
        env.runner(),
        &env.mgr,
        fpr,
        Some(&pw("wrong-pw")),
        Some(&pw(BACKUP_PW)),
    );
    assert_msg(r, MSG_WRONG_GPG_PASSPHRASE);
    let r = delete_key(env.runner(), &env.mgr, fpr, None, Some(&pw(BACKUP_PW)));
    assert_msg(r, MSG_GPG_PASSPHRASE_REQUIRED);
    assert!(listed(env.runner(), fpr).is_some(), "nothing deleted");
    assert!(env.mgr.list().unwrap().is_empty(), "no backup written");

    let info = delete_key(
        env.runner(),
        &env.mgr,
        fpr,
        Some(&pw(KEY_PW)),
        Some(&pw(BACKUP_PW)),
    )
    .unwrap();
    assert_eq!(info.reason, "delete-gpg-key");
    assert!(listed(env.runner(), fpr).is_none());
    assert!(list_keys(env.runner()).unwrap().is_empty());
    let listed_backups = env.mgr.list().unwrap();
    assert_eq!(listed_backups.len(), 1);
    assert_eq!(listed_backups[0].files.len(), 2);
    assert!(
        listed_backups[0]
            .files
            .iter()
            .any(|f| f.encrypted && f.stored.to_string_lossy().ends_with(".secret.asc.age"))
    );
    // No staging leftovers next to the backups.
    let names: Vec<String> = std::fs::read_dir(&env.mgr.root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");

    let other = TempGnupgHome::new().unwrap();
    let report = import_keys(&other.runner, &backup_bytes(&info, ".secret.asc.age")).unwrap();
    assert_eq!(report.secret_imported, 1);
    let out = tempfile::tempdir().unwrap();
    assert!(unlocks(&other.runner, fpr, KEY_PW, out.path()));
}

/// A public-only key is backed up in clear and deleted without passphrases.
#[test]
fn delete_public_key() {
    let env = env_or_skip!();
    let source = env.key(None);
    let text = export_public(env.runner(), &source.fingerprint).unwrap();
    let other = Env::new().unwrap();
    import_keys(other.runner(), text.as_bytes()).unwrap();

    let info = delete_key(other.runner(), &other.mgr, &source.fingerprint, None, None).unwrap();
    assert_eq!(info.files.len(), 1);
    assert!(!info.files[0].encrypted);
    assert_eq!(
        std::fs::read_to_string(&info.files[0].stored).unwrap(),
        text
    );
    assert!(listed(other.runner(), &source.fingerprint).is_none());
    assert!(
        listed(env.runner(), &source.fingerprint).is_some(),
        "other home untouched"
    );

    let r = delete_key(other.runner(), &other.mgr, &source.fingerprint, None, None);
    assert!(matches!(r, Err(KringError::NotFound(_))), "{r:?}");
}

/// A key whose primary secret is an offline stub cannot be deleted or re-protected.
#[test]
fn stub_primary_is_refused() {
    let env = env_or_skip!();
    let key = env.key(Some(KEY_PW));
    let subkeys = env
        .runner()
        .run(
            [
                "--armor",
                "--export-secret-subkeys",
                "--",
                key.fingerprint.as_str(),
            ],
            None,
            Some(&pw(KEY_PW)),
            TIMEOUT_DEFAULT,
        )
        .unwrap();
    assert!(subkeys.success(), "{}", subkeys.stderr_text());
    let other = Env::new().unwrap();
    import_keys(other.runner(), &subkeys.stdout).unwrap();
    let stub = listed(other.runner(), &key.fingerprint).unwrap();
    assert!(stub.secret, "the subkey secret is there");
    assert!(!stub.primary_secret, "the primary is a stub");

    let r = delete_key(
        other.runner(),
        &other.mgr,
        &key.fingerprint,
        Some(&pw(KEY_PW)),
        Some(&pw(BACKUP_PW)),
    );
    assert_msg(r, MSG_PRIMARY_SECRET_UNAVAILABLE);
    let r = change_passphrase(
        other.runner(),
        &other.mgr,
        &key.fingerprint,
        Some(&pw(KEY_PW)),
        &pw(NEW_PW),
        Some(&pw(BACKUP_PW)),
    );
    assert_msg(r, MSG_PRIMARY_SECRET_UNAVAILABLE);
    assert!(listed(other.runner(), &key.fingerprint).is_some());
}

/// An agent configured to refuse loopback yields the explanatory message.
#[test]
fn loopback_refused_is_explained() {
    let env = env_or_skip!();
    let key = env.key(Some(KEY_PW));
    let home = env.home.dir.path();
    kill_daemons(&env.home.gpgconf(), home);
    std::fs::write(home.join("gpg-agent.conf"), "no-allow-loopback-pinentry\n").unwrap();

    let r = list_keys(env.runner());
    assert_msg(r, MSG_LOOPBACK_REFUSED);
    let dest = home.join("out.asc");
    let r = export_secret(env.runner(), &key.fingerprint, &dest, Some(&pw(KEY_PW)));
    assert_msg(r, MSG_LOOPBACK_REFUSED);
    let uid = "Other <other@example.invalid>";
    let r = create_key(
        env.runner(),
        uid,
        GpgAlgo::default(),
        None,
        Some(&pw(KEY_PW)),
    );
    assert_msg(r, MSG_LOOPBACK_REFUSED);
    let r = change_passphrase(
        env.runner(),
        &env.mgr,
        &key.fingerprint,
        Some(&pw(KEY_PW)),
        &pw(NEW_PW),
        Some(&pw(BACKUP_PW)),
    );
    assert_msg(r, MSG_LOOPBACK_REFUSED);
}
