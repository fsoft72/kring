//! Unit tests of the GPG worker commands, against the real `gpg` in throwaway
//! GnuPG homes ([`gpg_home::TempGnupgHome`]: 0700 temp dir as `--homedir` and
//! `GNUPGHOME`, daemons killed and socket dir removed on drop). The user's
//! `~/.gnupg` and gpg-agent are never used. Tests skip when gpg is missing.

#[path = "../../../kring-core/tests/gpg_home/mod.rs"]
mod gpg_home;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::Duration;

use kring_core::KringError;
use kring_core::backup::{BACKUP_KEEP, BackupInfo, BackupManager};
use kring_core::fake_store::FakeStore;
use kring_core::gpg::{
    GpgAlgo, GpgKey, GpgRunner, MSG_GPG_NOT_FOUND, MSG_GPG_PASSPHRASE_REQUIRED,
    MSG_LOOPBACK_REFUSED, MSG_WRONG_GPG_PASSPHRASE, create_key, export_public, export_secret,
    list_keys,
};
use kring_core::model::SecretValue;

use gpg_home::{TempGnupgHome, kill_daemons, remove_socket_dir};

use super::{MSG_RESCAN_FAILED, handle_with, is_gpg, report_backed_up};
use crate::worker::{Command, Emitter, Event, WorkerConfig, WorkerHandle, passphrase_echo, spawn};
use crate::worker_transfer::invalidates_plan;

/// Passphrase of the seeded test keys.
const KEY_PW: &str = "gpg-key-pw-secret";
/// New key passphrase.
const NEW_PW: &str = "gpg-new-pw-secret";
/// Passphrase protecting the age copies of the backups.
const BACKUP_PW: &str = "gpg-backup-pw-secret";
/// Every passphrase used here: none may appear in an event.
const SECRETS: [&str; 3] = [KEY_PW, NEW_PW, BACKUP_PW];
/// User id of seeded keys.
const TEST_UID: &str = "Kring Worker <kring-worker@example.invalid>";
/// First line of an armored public key.
const PUBLIC_ARMOR: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
/// First line of an armored secret key.
const SECRET_ARMOR: &[u8] = b"-----BEGIN PGP PRIVATE KEY BLOCK-----";

/// A secret from text.
fn pw(text: &str) -> SecretValue {
    SecretValue::from_text(text)
}

/// Test environment: a temp GnuPG home, temp backups and the worker over them.
struct Env {
    /// Worker endpoints.
    handle: WorkerHandle,
    /// Number of the next command sent.
    seq: u64,
    /// Backup manager of the worker.
    backups: BackupManager,
    /// Temp dir holding the backups and test files.
    dir: tempfile::TempDir,
    /// The GnuPG home (its agent is killed on drop).
    home: TempGnupgHome,
}

impl Env {
    /// Starts a worker over a fresh home; `None` when gpg is not installed.
    fn new() -> Option<Self> {
        let home = TempGnupgHome::new()?;
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path(), Some(home.dir.path().to_path_buf()));
        let backups = config.backups.clone();
        let handle = spawn::<FakeStore>(None, None, config, || {});
        // Startup: ProviderUnavailable and Pam.
        for _ in 0..2 {
            let event = handle.rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert!(matches!(event, Event::ProviderUnavailable | Event::Pam(_)));
        }
        Some(Self {
            handle,
            seq: 0,
            backups,
            dir,
            home,
        })
    }

    /// The runner of the home (for seeding and checking keys directly).
    fn runner(&self) -> &GpgRunner {
        &self.home.runner
    }

    /// Creates a key protected with `passphrase` (or unprotected) in the home.
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

    /// Sends `cmd` and returns its events up to (excluding) its
    /// `CommandFinished`, asserting that no passphrase leaks in any event.
    fn run(&mut self, cmd: Command) -> Vec<Event> {
        self.handle.tx.send(cmd).unwrap();
        let mut events = Vec::new();
        loop {
            let event = self
                .handle
                .rx
                .recv_timeout(Duration::from_secs(150))
                .expect("event expected");
            assert_secret_free(&event);
            if let Event::CommandFinished(id) = event {
                assert_eq!(id, self.seq, "out of order CommandFinished");
                self.seq += 1;
                return events;
            }
            events.push(event);
        }
    }

    /// True when the secret export of `fpr` works with `passphrase`.
    fn unlocks(&self, fpr: &str, passphrase: &str) -> bool {
        let n = self.dir.path().read_dir().unwrap().count();
        let dest = self.dir.path().join(format!("probe-{n}.asc"));
        export_secret(self.runner(), fpr, &dest, Some(&pw(passphrase))).is_ok()
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

/// Builds the worker configuration over temp dir `dir` with GnuPG home `gnupg_home`.
fn config_in(dir: &Path, gnupg_home: Option<PathBuf>) -> WorkerConfig {
    WorkerConfig {
        backups: BackupManager {
            root: dir.join("backups"),
            keep: BACKUP_KEEP,
        },
        keyrings_dir: dir.join("keyrings"),
        pam_dir: dir.join("pam"),
        kwallet_dir: dir.join("kwalletd"),
        ssh_dir: None,
        ssh_agent_sock: None,
        gnupg_home,
    }
}

/// Fails when the debug text of `event` contains a test passphrase.
fn assert_secret_free(event: &Event) {
    let text = format!("{event:?}");
    for secret in SECRETS {
        assert!(!text.contains(secret), "secret leaked: {text}");
    }
}

/// The keys of the only `GpgKeys` event in `events`.
fn keys_of(events: &[Event]) -> &[GpgKey] {
    let found: Vec<&Vec<GpgKey>> = events
        .iter()
        .filter_map(|e| match e {
            Event::GpgKeys(keys) => Some(keys),
            _ => None,
        })
        .collect();
    assert_eq!(found.len(), 1, "{events:?}");
    found[0]
}

/// Fingerprints of `keys`.
fn fingerprints(keys: &[GpgKey]) -> Vec<&str> {
    keys.iter().map(|k| k.fingerprint.as_str()).collect()
}

/// The error messages in `events`.
fn errors(events: &[Event]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Error(m) => Some(m.as_str()),
            _ => None,
        })
        .collect()
}

/// True when `events` contain a `Done`.
fn has_done(events: &[Event]) -> bool {
    events.iter().any(|e| matches!(e, Event::Done(_)))
}

/// The backups announced in `events`.
fn backups_of(events: &[Event]) -> Vec<&BackupInfo> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::BackupCreated(info) => Some(info),
            _ => None,
        })
        .collect()
}

/// The scan lists the keys of the configured home, read-only commands keep plans.
#[test]
fn scan_lists_keys() {
    let mut env = env_or_skip!();
    let events = env.run(Command::ScanGpgKeys);
    assert!(keys_of(&events).is_empty(), "{events:?}");
    let key = env.key(Some(KEY_PW));
    let events = env.run(Command::ScanGpgKeys);
    assert_eq!(fingerprints(keys_of(&events)), [key.fingerprint.as_str()]);
    assert!(keys_of(&events)[0].secret);
    assert_eq!(events.len(), 1, "{events:?}");
}

/// Creating a key rescans and reports Done; a bad user id is one error.
#[test]
fn create_key_rescans() {
    let mut env = env_or_skip!();
    let events = env.run(Command::CreateGpgKey {
        uid: TEST_UID.into(),
        algo: GpgAlgo::default(),
        expire: Some("1y".into()),
        passphrase: Some(pw(KEY_PW)),
    });
    let keys = keys_of(&events);
    assert_eq!(keys.len(), 1, "{events:?}");
    assert_eq!(keys[0].uids[0].uid, TEST_UID);
    assert!(keys[0].expires.is_some());
    assert!(has_done(&events));
    assert!(env.unlocks(&keys[0].fingerprint, KEY_PW));

    let bad = env.run(Command::CreateGpgKey {
        uid: "a\nb".into(),
        algo: GpgAlgo::default(),
        expire: None,
        passphrase: None,
    });
    assert_eq!(errors(&bad).len(), 1, "{bad:?}");
    assert!(!has_done(&bad));
}

/// Importing reads the file, imports its keys, rescans and reports Done.
#[test]
fn import_keys_from_file() {
    let mut env = env_or_skip!();
    let other = TempGnupgHome::new().unwrap();
    let source = create_key(&other.runner, TEST_UID, GpgAlgo::default(), None, None).unwrap();
    let text = export_public(&other.runner, &source.fingerprint).unwrap();
    let path = env.dir.path().join("public.asc");
    std::fs::write(&path, &text).unwrap();

    let events = env.run(Command::ImportGpgKeys { path: path.clone() });
    assert_eq!(
        fingerprints(keys_of(&events)),
        [source.fingerprint.as_str()]
    );
    assert!(!keys_of(&events)[0].secret);
    assert!(has_done(&events), "{events:?}");

    let missing = env.run(Command::ImportGpgKeys {
        path: env.dir.path().join("missing.asc"),
    });
    assert_eq!(errors(&missing).len(), 1, "{missing:?}");
    let garbage = env.dir.path().join("garbage.asc");
    std::fs::write(&garbage, "not a key\n").unwrap();
    let events = env.run(Command::ImportGpgKeys { path: garbage });
    assert_eq!(errors(&events).len(), 1, "{events:?}");
}

/// The public key of a listed key by primary fingerprint only.
#[test]
fn export_public_by_primary_fingerprint() {
    let mut env = env_or_skip!();
    let key = env.key(None);
    let lower = key.fingerprint.to_ascii_lowercase();
    let events = env.run(Command::ExportGpgPublic { fpr: lower });
    match &events[..] {
        [Event::GpgPublicKey { fpr, text }] => {
            assert_eq!(fpr, &key.fingerprint);
            assert!(text.starts_with(PUBLIC_ARMOR), "{text}");
        }
        other => panic!("{other:?}"),
    }
    let subkey = key.subkeys[0].fingerprint.clone();
    for bad in [subkey, "A".repeat(40), key.key_id.clone(), String::new()] {
        let events = env.run(Command::ExportGpgPublic { fpr: bad.clone() });
        assert_eq!(errors(&events).len(), 1, "{bad}: {events:?}");
    }
}

/// Saving the public key writes the armored export to a new file and never
/// overwrites an existing one.
#[test]
fn save_public_key_to_new_file() {
    let mut env = env_or_skip!();
    let key = env.key(None);
    let dest = env.dir.path().join("public.asc");
    let save = || Command::SaveGpgPublic {
        fpr: key.fingerprint.clone(),
        dest: dest.clone(),
    };
    let events = env.run(save());
    assert!(has_done(&events), "{events:?}");
    let text = std::fs::read_to_string(&dest).unwrap();
    assert!(text.starts_with(PUBLIC_ARMOR), "{text}");
    let events = env.run(save());
    assert_eq!(errors(&events).len(), 1, "{events:?}");
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), text, "kept");
    assert!(is_gpg(&save()));
    assert!(!invalidates_plan(&save()), "read-only");
}

/// Secret export maps passphrase errors to the shared texts and writes a 0600 file.
#[test]
fn export_secret_key() {
    let mut env = env_or_skip!();
    let key = env.key(Some(KEY_PW));
    let dest = env.dir.path().join("secret.asc");
    let export = |passphrase: Option<&str>| Command::ExportGpgSecret {
        fpr: key.fingerprint.clone(),
        dest: dest.clone(),
        passphrase: passphrase.map(pw),
    };
    let events = env.run(export(Some("wrong-pw")));
    assert_eq!(errors(&events), [MSG_WRONG_GPG_PASSPHRASE]);
    let events = env.run(export(None));
    assert_eq!(errors(&events), [MSG_GPG_PASSPHRASE_REQUIRED]);
    assert!(!dest.exists());

    let events = env.run(export(Some(KEY_PW)));
    assert!(has_done(&events), "{events:?}");
    let meta = std::fs::metadata(&dest).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert!(std::fs::read(&dest).unwrap().starts_with(SECRET_ARMOR));
}

/// A passphrase change asks for the backup passphrase, maps a wrong old one,
/// then backs up, rescans and reports Done.
#[test]
fn change_passphrase_flow() {
    let mut env = env_or_skip!();
    let key = env.key(Some(KEY_PW));
    let fpr = key.fingerprint.clone();
    let change = |old: &str, backup: Option<&str>| Command::ChangeGpgPassphrase {
        fpr: fpr.clone(),
        old: Some(pw(old)),
        new: Some(pw(NEW_PW)),
        backup_passphrase: backup.map(pw),
    };

    let events = env.run(change(KEY_PW, None));
    match &events[..] {
        [Event::PassphraseNeeded(cmd)] => match cmd.as_ref() {
            Command::ChangeGpgPassphrase {
                fpr: echoed,
                old: None,
                new: None,
                backup_passphrase: None,
            } => assert_eq!(echoed, &fpr),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
    let events = env.run(change("wrong-pw", Some(BACKUP_PW)));
    assert_eq!(errors(&events), [MSG_WRONG_GPG_PASSPHRASE]);
    assert!(env.backups.list().unwrap().is_empty());

    let events = env.run(change(KEY_PW, Some(BACKUP_PW)));
    assert!(matches!(events[0], Event::BackupCreated(_)), "{events:?}");
    assert_eq!(backups_of(&events)[0].reason, "change-gpg-passphrase");
    assert_eq!(fingerprints(keys_of(&events)), [fpr.as_str()]);
    assert!(matches!(events.last(), Some(Event::Done(_))), "{events:?}");
    assert!(env.unlocks(&fpr, NEW_PW));
    assert!(!env.unlocks(&fpr, KEY_PW));
}

/// Deleting asks for the backup passphrase, then backs up, rescans and reports Done.
#[test]
fn delete_key_flow() {
    let mut env = env_or_skip!();
    let key = env.key(Some(KEY_PW));
    let fpr = key.fingerprint.clone();
    let delete = |backup: Option<&str>| Command::DeleteGpgKey {
        fpr: fpr.clone(),
        key_passphrase: Some(pw(KEY_PW)),
        backup_passphrase: backup.map(pw),
    };

    let events = env.run(delete(None));
    match &events[..] {
        [Event::PassphraseNeeded(cmd)] => match cmd.as_ref() {
            Command::DeleteGpgKey {
                fpr: echoed,
                key_passphrase: None,
                backup_passphrase: None,
            } => assert_eq!(echoed, &fpr),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
    assert_eq!(list_keys(env.runner()).unwrap().len(), 1, "nothing deleted");

    let events = env.run(delete(Some(BACKUP_PW)));
    assert!(matches!(events[0], Event::BackupCreated(_)), "{events:?}");
    assert_eq!(backups_of(&events)[0].reason, "delete-gpg-key");
    assert!(keys_of(&events).is_empty());
    assert!(matches!(events.last(), Some(Event::Done(_))), "{events:?}");
    assert!(list_keys(env.runner()).unwrap().is_empty());

    let again = env.run(delete(Some(BACKUP_PW)));
    assert_eq!(errors(&again).len(), 1, "{again:?}");
}

/// A failure after the backup still reports the backup, then the error and a rescan, no Done.
#[test]
fn failure_after_backup_reports_the_backup() {
    let Some(home) = TempGnupgHome::new() else {
        return eprintln!("SKIPPED: gpg is not installed");
    };
    let (tx, rx) = channel();
    let out = Emitter::for_test(tx, || {});
    let info = backup_info();
    let failed = Err(KringError::Gpg("passphrase change failed".into()));
    report_backed_up(&out, &home.runner, info.clone(), failed, "done".into());
    let events: Vec<Event> = rx.try_iter().collect();
    match &events[..] {
        [
            Event::BackupCreated(b),
            Event::Error(e),
            Event::GpgKeys(keys),
        ] => {
            assert_eq!(b, &info);
            assert!(e.contains("passphrase change failed"), "{e}");
            assert!(keys.is_empty());
        }
        other => panic!("{other:?}"),
    }
}

/// Without gpg the area is unavailable: a scan says so once, an action adds one error.
#[test]
fn gpg_missing_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_in(dir.path(), Some(dir.path().join("gnupg")));
    let (tx, rx) = channel();
    let out = Emitter::for_test(tx, || {});
    let locate = || GpgRunner::locate_in(None);
    handle_with(&out, &config, &Command::ScanGpgKeys, locate);
    let events: Vec<Event> = rx.try_iter().collect();
    assert!(
        matches!(&events[..], [Event::GpgUnavailable { reason, scan: true }] if reason == MSG_GPG_NOT_FOUND),
        "{events:?}"
    );
    let cmd = Command::ExportGpgPublic {
        fpr: "A".repeat(40),
    };
    handle_with(&out, &config, &cmd, locate);
    let events: Vec<Event> = rx.try_iter().collect();
    match &events[..] {
        [Event::GpgUnavailable { reason, scan }, Event::Error(e)] => {
            assert!(!scan, "not a scan result");
            assert_eq!(reason, MSG_GPG_NOT_FOUND);
            assert_eq!(e, MSG_GPG_NOT_FOUND);
        }
        other => panic!("{other:?}"),
    }
}

/// An agent refusing loopback makes the area unavailable with the explanation.
#[test]
fn loopback_refused_is_unavailable() {
    let mut env = env_or_skip!();
    let key = env.key(None);
    let home = env.home.dir.path().to_path_buf();
    kill_daemons(&env.home.gpgconf(), &home);
    std::fs::write(home.join("gpg-agent.conf"), "no-allow-loopback-pinentry\n").unwrap();

    let events = env.run(Command::ScanGpgKeys);
    assert!(
        matches!(&events[..], [Event::GpgUnavailable { reason, scan: true }] if reason == MSG_LOOPBACK_REFUSED),
        "{events:?}"
    );
    let events = env.run(Command::ExportGpgPublic {
        fpr: key.fingerprint.clone(),
    });
    match &events[..] {
        [Event::GpgUnavailable { reason, scan }, Event::Error(e)] => {
            assert!(!scan, "not a scan result");
            assert_eq!(reason, MSG_LOOPBACK_REFUSED);
            assert_eq!(e, MSG_LOOPBACK_REFUSED);
        }
        other => panic!("{other:?}"),
    }
}

/// The rescan error prefix is used when the listing fails after a change.
#[test]
fn rescan_failure_is_reported() {
    let Some(home) = TempGnupgHome::new() else {
        return eprintln!("SKIPPED: gpg is not installed");
    };
    let missing = home.dir.path().join("absent");
    let runner = home.runner.clone().with_homedir(missing.clone());
    let (tx, rx) = channel();
    let out = Emitter::for_test(tx, || {});
    report_backed_up(&out, &runner, backup_info(), Ok(()), "done".into());
    kill_daemons(&home.gpgconf(), &missing);
    remove_socket_dir(&home.gpgconf(), &missing);
    let events: Vec<Event> = rx.try_iter().collect();
    match &events[..] {
        [Event::BackupCreated(_), Event::Error(e), Event::Done(d)] => {
            assert!(e.starts_with(MSG_RESCAN_FAILED), "{e}");
            assert_eq!(d, "done");
        }
        other => panic!("{other:?}"),
    }
}

/// A placeholder backup for reporting tests.
fn backup_info() -> BackupInfo {
    BackupInfo {
        dir: PathBuf::from("/backups/y"),
        reason: "delete-gpg-key".into(),
        created: "2026-11-15T10:00:00Z".into(),
        files: Vec::new(),
        seq: 2,
        prune_warning: None,
        pruned: Vec::new(),
    }
}

/// Every GPG command is routed here; read-only ones and exports (new file only) keep plans, the others drop them.
#[test]
fn routing_and_plan_invalidation() {
    let fpr = || "A".repeat(40);
    let keeps = [
        Command::ScanGpgKeys,
        Command::ExportGpgPublic { fpr: fpr() },
        Command::ExportGpgSecret {
            fpr: fpr(),
            dest: PathBuf::from("/x"),
            passphrase: None,
        },
    ];
    let drops = [
        Command::CreateGpgKey {
            uid: TEST_UID.into(),
            algo: GpgAlgo::default(),
            expire: None,
            passphrase: None,
        },
        Command::ImportGpgKeys {
            path: PathBuf::from("/x"),
        },
        Command::ChangeGpgPassphrase {
            fpr: fpr(),
            old: None,
            new: None,
            backup_passphrase: None,
        },
        Command::DeleteGpgKey {
            fpr: fpr(),
            key_passphrase: None,
            backup_passphrase: None,
        },
    ];
    for cmd in &keeps {
        assert!(is_gpg(cmd) && !invalidates_plan(cmd), "{cmd:?}");
    }
    for cmd in &drops {
        assert!(is_gpg(cmd) && invalidates_plan(cmd), "{cmd:?}");
    }
    assert!(!is_gpg(&Command::ScanSshKeys));
}

/// The passphrase echo of GPG commands clears every passphrase.
#[test]
fn echo_clears_gpg_passphrases() {
    let commands = [
        Command::CreateGpgKey {
            uid: TEST_UID.into(),
            algo: GpgAlgo::Rsa3072,
            expire: Some("2y".into()),
            passphrase: Some(pw(KEY_PW)),
        },
        Command::ExportGpgSecret {
            fpr: "A".repeat(40),
            dest: PathBuf::from("/x"),
            passphrase: Some(pw(KEY_PW)),
        },
        Command::ChangeGpgPassphrase {
            fpr: "A".repeat(40),
            old: Some(pw(KEY_PW)),
            new: Some(pw(NEW_PW)),
            backup_passphrase: Some(pw(BACKUP_PW)),
        },
        Command::DeleteGpgKey {
            fpr: "A".repeat(40),
            key_passphrase: Some(pw(KEY_PW)),
            backup_passphrase: Some(pw(BACKUP_PW)),
        },
    ];
    for cmd in &commands {
        let echo = passphrase_echo(cmd);
        assert_secret_free(&echo);
        let Event::PassphraseNeeded(echoed) = &echo else {
            panic!("{echo:?}");
        };
        let cleared = matches!(
            echoed.as_ref(),
            Command::CreateGpgKey {
                passphrase: None,
                expire: Some(_),
                ..
            } | Command::ExportGpgSecret {
                passphrase: None,
                ..
            } | Command::ChangeGpgPassphrase {
                old: None,
                new: None,
                backup_passphrase: None,
                ..
            } | Command::DeleteGpgKey {
                key_passphrase: None,
                backup_passphrase: None,
                ..
            }
        );
        assert!(cleared, "{echoed:?}");
    }
}
