//! Unit tests of the SSH worker commands: temp copies of the committed key
//! fixtures and a private `ssh-agent` started per test (the user's `~/.ssh`
//! and `SSH_AUTH_SOCK` are never used).

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use kring_core::backup::{BACKUP_KEEP, BackupManager};
use kring_core::fake_store::FakeStore;
use kring_core::model::SecretValue;
use kring_core::ssh::{
    MSG_KEY_PASSPHRASE_REQUIRED, MSG_WRONG_KEY_PASSPHRASE, NewKey, SshAlgorithm, SshKeyInfo,
};

use super::{AgentStatus, MSG_NO_AGENT, MSG_NO_SSH_DIR, MSG_RESCAN_FAILED, finish};
use crate::worker::{Command, Event, WorkerConfig, WorkerHandle, passphrase_echo, spawn};
use crate::worker_transfer::invalidates_plan;

/// Directory of the SSH key fixtures.
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kring-core/tests/fixtures/ssh"
);
/// Passphrase of the encrypted fixture key.
const FIXTURE_PW: &str = "fixture-pw";
/// Backup passphrase used by the tests.
const BACKUP_PW: &str = "backup-pw-secret";
/// New key passphrase used by the tests.
const NEW_PW: &str = "new-key-pw-secret";
/// Every passphrase used here: none may appear in an event.
const SECRETS: [&str; 3] = [FIXTURE_PW, BACKUP_PW, NEW_PW];
/// Fixture files copied into the temp SSH directory.
const FIXTURE_FILES: [&str; 14] = [
    "id_ed25519",
    "id_ed25519.pub",
    "id_ed25519_enc",
    "id_ed25519_enc.pub",
    "id_rsa",
    "id_rsa.pub",
    "id_ecdsa",
    "id_ecdsa.pub",
    "id_legacy",
    "id_legacy.pub",
    "orphan.pub",
    "authorized_keys",
    "known_hosts",
    "config",
];

/// A private ssh-agent process, killed on drop.
struct PrivateAgent {
    child: Child,
    sock: PathBuf,
    _dir: tempfile::TempDir,
}

impl PrivateAgent {
    /// Starts `ssh-agent -D -a <tmp>/agent.sock`; `None` when ssh-agent is missing.
    fn start() -> Option<Self> {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let child = std::process::Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&sock)
            .env_remove("SSH_AUTH_SOCK")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let agent = Self {
            child,
            sock,
            _dir: dir,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while UnixStream::connect(&agent.sock).is_err() {
            assert!(
                Instant::now() < deadline,
                "ssh-agent did not accept connections"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Some(agent)
    }
}

impl Drop for PrivateAgent {
    /// Kills and reaps the agent.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Test environment: temp dirs and the worker handle.
struct Env {
    dir: tempfile::TempDir,
    ssh: PathBuf,
    handle: WorkerHandle,
    /// Number of the next command sent.
    seq: u64,
}

impl Env {
    /// Sends `cmd` and returns its events up to (excluding) its
    /// `CommandFinished`, asserting that no passphrase leaks in any event.
    fn run(&mut self, cmd: Command) -> Vec<Event> {
        self.handle.tx.send(cmd).unwrap();
        let mut events = Vec::new();
        loop {
            let event = self
                .handle
                .rx
                .recv_timeout(Duration::from_secs(20))
                .expect("event expected");
            let text = format!("{event:?}");
            for secret in SECRETS {
                assert!(!text.contains(secret), "secret leaked: {text}");
            }
            if let Event::CommandFinished(id) = event {
                assert_eq!(id, self.seq, "out of order CommandFinished");
                self.seq += 1;
                return events;
            }
            events.push(event);
        }
    }

    /// Path of `name` in the temp SSH directory.
    fn key_path(&self, name: &str) -> PathBuf {
        self.ssh.join(name)
    }
}

/// Starts a worker without a Secret Service over a temp SSH directory
/// seeded with the fixtures, using `agent` as its agent socket.
fn env_with(agent: Option<PathBuf>) -> Env {
    env_over(true, agent)
}

/// Builds the worker configuration over temp dir `dir`, with `ssh_dir`.
fn config_in(dir: &Path, ssh_dir: Option<PathBuf>, agent: Option<PathBuf>) -> WorkerConfig {
    WorkerConfig {
        backups: BackupManager {
            root: dir.join("backups"),
            keep: BACKUP_KEEP,
        },
        keyrings_dir: dir.join("keyrings"),
        pam_dir: dir.join("pam"),
        kwallet_dir: dir.join("kwalletd"),
        ssh_dir,
        ssh_agent_sock: agent,
        gnupg_home: Some(std::path::PathBuf::from(crate::worker::NO_GNUPG_HOME)),
    }
}

/// Starts a worker without a Secret Service; with `has_ssh_dir` its SSH
/// directory is a temp copy of the fixtures, otherwise it has none (HOME
/// unset).
fn env_over(has_ssh_dir: bool, agent: Option<PathBuf>) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join("ssh");
    std::fs::create_dir(&ssh).unwrap();
    for name in FIXTURE_FILES {
        std::fs::copy(Path::new(FIXTURES).join(name), ssh.join(name)).unwrap();
    }
    let ssh_dir = has_ssh_dir.then(|| ssh.clone());
    let config = config_in(dir.path(), ssh_dir, agent);
    let handle = spawn::<FakeStore>(None, None, config, || {});
    // Startup: ProviderUnavailable and Pam.
    for _ in 0..2 {
        let event = handle.rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(matches!(event, Event::ProviderUnavailable | Event::Pam(_)));
    }
    Env {
        dir,
        ssh,
        handle,
        seq: 0,
    }
}

/// Key names of an `SshKeys` event.
fn names(keys: &[SshKeyInfo]) -> Vec<&str> {
    keys.iter().map(|k| k.name.as_str()).collect()
}

/// The keys of the only `SshKeys` event in `events`.
fn keys_of(events: &[Event]) -> &[SshKeyInfo] {
    let found: Vec<&Vec<SshKeyInfo>> = events
        .iter()
        .filter_map(|e| match e {
            Event::SshKeys(keys) => Some(keys),
            _ => None,
        })
        .collect();
    assert_eq!(found.len(), 1, "{events:?}");
    found[0]
}

/// The agent status of the only `AgentIdentities` event in `events`.
fn agent_of(events: &[Event]) -> &AgentStatus {
    let found: Vec<&AgentStatus> = events
        .iter()
        .filter_map(|e| match e {
            Event::AgentIdentities(status) => Some(status),
            _ => None,
        })
        .collect();
    assert_eq!(found.len(), 1, "{events:?}");
    found[0]
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

/// A secret from text.
fn secret(text: &str) -> SecretValue {
    SecretValue::from_text(text)
}

/// The scan lists key pairs, legacy and orphan keys, never the decoys.
#[test]
fn scan_lists_keys_only() {
    let mut env = env_with(None);
    let events = env.run(Command::ScanSshKeys);
    assert_eq!(
        names(keys_of(&events)),
        [
            "id_ecdsa",
            "id_ed25519",
            "id_ed25519_enc",
            "id_legacy",
            "id_rsa",
            "orphan"
        ]
    );
    assert!(errors(&events).is_empty());
}

/// Generating writes the pair, rescans and reports Done; an existing name is refused.
#[test]
fn generate_key_rescans() {
    let mut env = env_with(None);
    let key = NewKey {
        name: "work".into(),
        algorithm: SshAlgorithm::Ed25519,
        rsa_bits: 0,
        comment: "me@work".into(),
        passphrase: Some(secret(NEW_PW)),
    };
    let events = env.run(Command::GenerateSshKey(key.clone()));
    let work = keys_of(&events).iter().find(|k| k.name == "work").unwrap();
    assert_eq!(work.encrypted, Some(true));
    assert!(has_done(&events));
    let mode = std::fs::metadata(env.key_path("work"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    let again = env.run(Command::GenerateSshKey(key));
    assert_eq!(errors(&again).len(), 1, "{again:?}");
    assert!(!has_done(&again));
}

/// Importing copies a key from outside the SSH directory under a new name.
#[test]
fn import_key_rescans() {
    let mut env = env_with(None);
    let outside = env.dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let source = outside.join("laptop");
    std::fs::copy(Path::new(FIXTURES).join("id_ed25519"), &source).unwrap();
    std::fs::remove_file(env.key_path("id_ed25519")).unwrap();
    std::fs::remove_file(env.key_path("id_ed25519.pub")).unwrap();
    let events = env.run(Command::ImportSshKey {
        source,
        name: Some("laptop".into()),
    });
    assert!(names(keys_of(&events)).contains(&"laptop"), "{events:?}");
    assert!(has_done(&events));
    assert!(env.key_path("laptop.pub").exists());
}

/// The public key text of a listed key; an unknown or decoy name is an error.
#[test]
fn public_key_text() {
    let mut env = env_with(None);
    let events = env.run(Command::ReadSshPublicKey {
        name: "id_ed25519".into(),
    });
    match &events[..] {
        [Event::SshPublicKey { name, text }] => {
            assert_eq!(name, "id_ed25519");
            assert!(text.starts_with("ssh-ed25519 "), "{text}");
            assert!(text.ends_with("fixture@kring"), "{text}");
        }
        other => panic!("{other:?}"),
    }
    for bad in ["nope", "authorized_keys", "../ssh/id_rsa", ""] {
        let events = env.run(Command::ReadSshPublicKey { name: bad.into() });
        assert_eq!(errors(&events).len(), 1, "{bad}: {events:?}");
    }
}

/// Deleting an unencrypted key asks for the backup passphrase first (echo
/// without secrets), then backs up, deletes and rescans.
#[test]
fn delete_unencrypted_key_needs_backup_passphrase() {
    let mut env = env_with(None);
    let events = env.run(Command::DeleteSshKey {
        name: "id_ed25519".into(),
        backup_passphrase: None,
    });
    match &events[..] {
        [Event::PassphraseNeeded(cmd)] => assert!(matches!(
            **cmd,
            Command::DeleteSshKey {
                backup_passphrase: None,
                ..
            }
        )),
        other => panic!("{other:?}"),
    }
    assert!(env.key_path("id_ed25519").exists());

    let events = env.run(Command::DeleteSshKey {
        name: "id_ed25519".into(),
        backup_passphrase: Some(secret(BACKUP_PW)),
    });
    assert!(matches!(events[0], Event::BackupCreated(_)), "{events:?}");
    assert!(!names(keys_of(&events)).contains(&"id_ed25519"));
    assert!(has_done(&events));
    assert!(!env.key_path("id_ed25519").exists());
    assert!(!env.key_path("id_ed25519.pub").exists());
}

/// An encrypted key is backed up as it is: no backup passphrase needed.
#[test]
fn delete_encrypted_key_without_passphrase() {
    let mut env = env_with(None);
    let events = env.run(Command::DeleteSshKey {
        name: "id_ed25519_enc".into(),
        backup_passphrase: None,
    });
    assert!(matches!(events[0], Event::BackupCreated(_)), "{events:?}");
    assert!(has_done(&events));
    assert!(!env.key_path("id_ed25519_enc").exists());
}

/// Changing a passphrase: missing and wrong old passphrases are errors with
/// the shared texts; the right one backs up, rewrites and rescans.
#[test]
fn change_passphrase_errors_and_success() {
    let mut env = env_with(None);
    let change = |old: Option<&str>| Command::ChangeSshPassphrase {
        name: "id_ed25519_enc".into(),
        old: old.map(secret),
        new: Some(secret(NEW_PW)),
        allow_unencrypted: false,
        backup_passphrase: None,
    };
    let before = std::fs::read(env.key_path("id_ed25519_enc")).unwrap();
    assert_eq!(
        errors(&env.run(change(None))),
        [MSG_KEY_PASSPHRASE_REQUIRED]
    );
    assert_eq!(
        errors(&env.run(change(Some("wrong")))),
        [MSG_WRONG_KEY_PASSPHRASE]
    );
    assert_eq!(
        std::fs::read(env.key_path("id_ed25519_enc")).unwrap(),
        before
    );

    let events = env.run(change(Some(FIXTURE_PW)));
    assert!(matches!(events[0], Event::BackupCreated(_)), "{events:?}");
    let key = keys_of(&events)
        .iter()
        .find(|k| k.name == "id_ed25519_enc")
        .unwrap();
    assert_eq!(key.encrypted, Some(true));
    assert!(has_done(&events));
    assert_ne!(
        std::fs::read(env.key_path("id_ed25519_enc")).unwrap(),
        before
    );
    // The old passphrase no longer works, the new one does.
    assert_eq!(
        errors(&env.run(change(Some(FIXTURE_PW)))),
        [MSG_WRONG_KEY_PASSPHRASE]
    );
}

/// Protecting an unencrypted key needs a backup passphrase: the echo clears
/// every passphrase (key passphrases included).
#[test]
fn change_passphrase_of_unencrypted_key_asks_backup_passphrase() {
    let mut env = env_with(None);
    let cmd = |backup: Option<&str>| Command::ChangeSshPassphrase {
        name: "id_rsa".into(),
        old: None,
        new: Some(secret(NEW_PW)),
        allow_unencrypted: false,
        backup_passphrase: backup.map(secret),
    };
    let events = env.run(cmd(None));
    match &events[..] {
        [Event::PassphraseNeeded(echo)] => match &**echo {
            Command::ChangeSshPassphrase {
                name,
                old,
                new,
                backup_passphrase,
                ..
            } => {
                assert_eq!(name, "id_rsa");
                assert!(old.is_none() && new.is_none() && backup_passphrase.is_none());
            }
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
    let events = env.run(cmd(Some(BACKUP_PW)));
    let key = keys_of(&events)
        .iter()
        .find(|k| k.name == "id_rsa")
        .unwrap();
    assert_eq!(key.encrypted, Some(true));
    assert!(has_done(&events));
}

/// Exporting the private key writes a new 0600 file and never overwrites.
#[test]
fn export_private_key() {
    let mut env = env_with(None);
    let dest = env.dir.path().join("exported");
    let cmd = Command::ExportSshPrivate {
        name: "id_ed25519_enc".into(),
        dest: dest.clone(),
        passphrase: None,
        new_passphrase: None,
    };
    let events = env.run(cmd.clone());
    assert!(has_done(&events), "{events:?}");
    let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        std::fs::read(env.key_path("id_ed25519_enc")).unwrap()
    );
    assert_eq!(errors(&env.run(cmd)).len(), 1);

    let reencrypt = Command::ExportSshPrivate {
        name: "id_ed25519_enc".into(),
        dest: env.dir.path().join("exported2"),
        passphrase: Some(secret("wrong")),
        new_passphrase: Some(secret(NEW_PW)),
    };
    assert_eq!(errors(&env.run(reencrypt)), [MSG_WRONG_KEY_PASSPHRASE]);
}

/// Without an agent socket the agent is reported unavailable, and a list
/// is no error toast.
#[test]
fn agent_without_socket_is_unavailable() {
    let mut env = env_with(None);
    let events = env.run(Command::AgentList);
    assert_eq!(
        agent_of(&events),
        &AgentStatus::Unavailable(MSG_NO_AGENT.into())
    );
    assert!(errors(&events).is_empty());

    let events = env.run(Command::AgentAdd {
        name: "id_ed25519".into(),
        passphrase: None,
        lifetime_secs: None,
    });
    assert!(matches!(agent_of(&events), AgentStatus::Unavailable(_)));
    assert_eq!(errors(&events), [MSG_NO_AGENT]);
}

/// A socket where no agent listens is unavailable too, with the reason.
#[test]
fn dead_agent_socket_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let mut env = env_with(Some(dir.path().join("none.sock")));
    let events = env.run(Command::AgentList);
    match agent_of(&events) {
        AgentStatus::Unavailable(reason) => assert!(!reason.is_empty()),
        other => panic!("{other:?}"),
    }
    assert!(errors(&events).is_empty());
}

/// Add, wrong passphrase, remove one and remove all against a private agent.
#[test]
fn agent_add_remove() {
    let Some(agent) = PrivateAgent::start() else {
        eprintln!("SKIPPED: ssh-agent is not installed");
        return;
    };
    let mut env = env_with(Some(agent.sock.clone()));
    let available = |events: &[Event]| match agent_of(events) {
        AgentStatus::Available(ids) => ids.iter().map(|i| i.fingerprint.clone()).collect(),
        other => panic!("{other:?}"),
    };
    let listed: Vec<String> = available(&env.run(Command::AgentList));
    assert!(listed.is_empty());

    let scan = env.run(Command::ScanSshKeys);
    let fp = |name: &str| {
        keys_of(&scan)
            .iter()
            .find(|k| k.name == name)
            .unwrap()
            .fingerprint
            .clone()
    };
    let add = |name: &str, pw: Option<&str>| Command::AgentAdd {
        name: name.into(),
        passphrase: pw.map(secret),
        lifetime_secs: None,
    };
    let events = env.run(add("id_ed25519", None));
    assert!(has_done(&events), "{events:?}");
    assert_eq!(available(&events), [fp("id_ed25519")]);

    let events = env.run(add("id_ed25519_enc", None));
    assert_eq!(errors(&events), [MSG_KEY_PASSPHRASE_REQUIRED]);
    let events = env.run(add("id_ed25519_enc", Some("wrong")));
    assert_eq!(errors(&events), [MSG_WRONG_KEY_PASSPHRASE]);
    let events = env.run(add("id_ed25519_enc", Some(FIXTURE_PW)));
    assert_eq!(available(&events).len(), 2);

    let events = env.run(Command::AgentRemove {
        fingerprint: fp("id_ed25519"),
    });
    assert!(has_done(&events));
    assert_eq!(available(&events), [fp("id_ed25519_enc")]);
    let events = env.run(Command::AgentRemove {
        fingerprint: fp("id_ed25519"),
    });
    assert_eq!(errors(&events).len(), 1);

    let events = env.run(Command::AgentRemoveAll);
    assert!(has_done(&events));
    assert!(available(&events).is_empty());
}

/// The passphrase echo of every SSH command carries no passphrase.
#[test]
fn echo_clears_ssh_passphrases() {
    let some = || Some(secret(NEW_PW));
    let cmds = [
        Command::GenerateSshKey(NewKey {
            name: "k".into(),
            algorithm: SshAlgorithm::Ed25519,
            rsa_bits: 0,
            comment: String::new(),
            passphrase: some(),
        }),
        Command::ExportSshPrivate {
            name: "k".into(),
            dest: PathBuf::from("/x"),
            passphrase: some(),
            new_passphrase: some(),
        },
        Command::ChangeSshPassphrase {
            name: "k".into(),
            old: some(),
            new: some(),
            allow_unencrypted: true,
            backup_passphrase: some(),
        },
        Command::DeleteSshKey {
            name: "k".into(),
            backup_passphrase: some(),
        },
        Command::AgentAdd {
            name: "k".into(),
            passphrase: some(),
            lifetime_secs: Some(60),
        },
    ];
    for cmd in cmds {
        let Event::PassphraseNeeded(echo) = passphrase_echo(&cmd) else {
            panic!("not an echo");
        };
        let ok = match *echo {
            Command::GenerateSshKey(key) => key.passphrase.is_none(),
            Command::ExportSshPrivate {
                passphrase,
                new_passphrase,
                ..
            } => passphrase.is_none() && new_passphrase.is_none(),
            Command::ChangeSshPassphrase {
                old,
                new,
                backup_passphrase,
                allow_unencrypted,
                ..
            } => old.is_none() && new.is_none() && backup_passphrase.is_none() && allow_unencrypted,
            Command::DeleteSshKey {
                backup_passphrase, ..
            } => backup_passphrase.is_none(),
            Command::AgentAdd {
                passphrase,
                lifetime_secs,
                ..
            } => passphrase.is_none() && lifetime_secs == Some(60),
            other => panic!("{other:?}"),
        };
        assert!(ok, "{cmd:?}");
    }
}

/// Read-only SSH commands keep a pending plan; mutating ones drop it.
#[test]
fn plan_invalidation() {
    let keep = [
        Command::ScanSshKeys,
        Command::ReadSshPublicKey { name: "k".into() },
        Command::AgentList,
        Command::ExportSshPrivate {
            name: "k".into(),
            dest: PathBuf::from("/x"),
            passphrase: None,
            new_passphrase: None,
        },
    ];
    for cmd in keep {
        assert!(!invalidates_plan(&cmd), "{cmd:?}");
    }
    let drop = [
        Command::ImportSshKey {
            source: PathBuf::from("/x"),
            name: None,
        },
        Command::DeleteSshKey {
            name: "k".into(),
            backup_passphrase: None,
        },
        Command::ChangeSshPassphrase {
            name: "k".into(),
            old: None,
            new: None,
            allow_unencrypted: false,
            backup_passphrase: None,
        },
        Command::AgentAdd {
            name: "k".into(),
            passphrase: None,
            lifetime_secs: None,
        },
        Command::AgentRemove {
            fingerprint: "f".into(),
        },
        Command::AgentRemoveAll,
    ];
    for cmd in drop {
        assert!(invalidates_plan(&cmd), "{cmd:?}");
    }
}

/// Without an SSH directory (HOME unset) a scan lists nothing without an
/// error, and key commands fail with the explicit message.
#[test]
fn no_ssh_dir_lists_nothing() {
    let mut env = env_over(false, None);
    let events = env.run(Command::ScanSshKeys);
    assert!(keys_of(&events).is_empty());
    assert!(errors(&events).is_empty(), "{events:?}");
    let events = env.run(Command::ReadSshPublicKey {
        name: "id_ed25519".into(),
    });
    assert_eq!(errors(&events), [MSG_NO_SSH_DIR]);
    let events = env.run(Command::DeleteSshKey {
        name: "id_ed25519".into(),
        backup_passphrase: Some(secret(BACKUP_PW)),
    });
    assert_eq!(errors(&events), [MSG_NO_SSH_DIR]);
    assert!(env.key_path("id_ed25519").exists(), "nothing deleted");
}

/// A finished change reports `Done` even when the rescan after it fails;
/// the scan error comes separately.
#[test]
fn finish_reports_done_when_rescan_fails() {
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join("ssh");
    std::fs::create_dir(&ssh).unwrap();
    // Listable only with read permission: the rescan's read_dir fails.
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o300)).unwrap();
    if std::fs::read_dir(&ssh).is_ok() {
        eprintln!("SKIPPED: running with permissions that bypass the mode");
        return;
    }
    let config = config_in(dir.path(), Some(ssh.clone()), None);
    let (tx, rx) = std::sync::mpsc::channel();
    let out = crate::worker::Emitter::for_test(tx, || {});
    finish(&out, &config, None, "Key 'k' created".into());
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
    let events: Vec<Event> = rx.try_iter().collect();
    assert!(
        matches!(events.last(), Some(Event::Done(m)) if m == "Key 'k' created"),
        "{events:?}"
    );
    let errs = errors(&events);
    assert_eq!(errs.len(), 1, "{events:?}");
    assert!(errs[0].starts_with(MSG_RESCAN_FAILED), "{errs:?}");
}
