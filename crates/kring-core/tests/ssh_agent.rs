//! ssh-agent client against a private `ssh-agent` started by the test.
//!
//! The agent listens on a socket in a temp dir and is killed at the end.
//! `SSH_AUTH_SOCK` is never read, so the user's real agent is never touched.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kring_core::KringError;
use kring_core::model::SecretValue;
use kring_core::ssh::{
    AgentIdentity, MSG_KEY_PASSPHRASE_REQUIRED, MSG_WRONG_KEY_PASSPHRASE, SshAlgorithm, SshKeyInfo,
    add_identity, list_identities, remove_all, remove_identity, scan_keys,
};

/// Passphrase of the encrypted fixture.
const FIXTURE_PW: &str = "fixture-pw";

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
        let child = Command::new("ssh-agent")
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
        while !agent.sock.exists() {
            assert!(Instant::now() < deadline, "ssh-agent socket did not appear");
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

/// Directory with the SSH fixtures.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ssh")
}

/// The scanned fixture key `name`.
fn key(name: &str) -> SshKeyInfo {
    scan_keys(&fixtures())
        .unwrap()
        .into_iter()
        .find(|k| k.name == name)
        .unwrap()
}

/// Fingerprints currently listed by the agent.
fn fingerprints(sock: &Path) -> Vec<String> {
    list_identities(sock)
        .unwrap()
        .into_iter()
        .map(|i| i.fingerprint)
        .collect()
}

/// Add, list, remove one and remove all against a real agent.
#[test]
fn add_list_remove_with_real_agent() {
    let Some(agent) = PrivateAgent::start() else {
        eprintln!("SKIPPED: ssh-agent is not installed");
        return;
    };
    let sock = &agent.sock;
    assert!(list_identities(sock).unwrap().is_empty());

    let pw = SecretValue::from_text(FIXTURE_PW);
    let names = ["id_ed25519", "id_rsa", "id_ecdsa"];
    for name in names {
        add_identity(sock, &key(name), None, None).unwrap();
    }
    add_identity(sock, &key("id_ed25519_enc"), Some(&pw), None).unwrap();

    let listed = list_identities(sock).unwrap();
    assert_eq!(listed.len(), 4);
    for name in names.into_iter().chain(["id_ed25519_enc"]) {
        let info = key(name);
        let found: &AgentIdentity = listed
            .iter()
            .find(|i| i.fingerprint == info.fingerprint)
            .unwrap_or_else(|| panic!("{name} not listed"));
        assert_eq!(found.algorithm, info.algorithm, "{name}");
        assert_eq!(found.comment, info.comment, "{name}");
    }
    assert_eq!(key("id_rsa").algorithm, SshAlgorithm::Rsa);

    remove_identity(sock, &key("id_rsa").fingerprint).unwrap();
    let left = fingerprints(sock);
    assert_eq!(left.len(), 3);
    assert!(!left.contains(&key("id_rsa").fingerprint));
    assert!(matches!(
        remove_identity(sock, &key("id_rsa").fingerprint),
        Err(KringError::NotFound(_))
    ));

    remove_all(sock).unwrap();
    assert!(list_identities(sock).unwrap().is_empty());
}

/// Passphrase errors, legacy keys and lifetimes.
#[test]
fn add_identity_errors_and_lifetime() {
    let Some(agent) = PrivateAgent::start() else {
        eprintln!("SKIPPED: ssh-agent is not installed");
        return;
    };
    let sock = &agent.sock;
    let enc = key("id_ed25519_enc");
    let wrong = SecretValue::from_text("nope");
    let msg = |r: kring_core::Result<()>| match r {
        Err(KringError::InvalidInput(m)) => m,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        msg(add_identity(sock, &enc, None, None)),
        MSG_KEY_PASSPHRASE_REQUIRED
    );
    assert_eq!(
        msg(add_identity(sock, &enc, Some(&wrong), None)),
        MSG_WRONG_KEY_PASSPHRASE
    );
    assert!(add_identity(sock, &key("id_legacy"), None, None).is_err());
    assert!(add_identity(sock, &key("id_ed25519"), None, Some(0)).is_err());
    assert!(list_identities(sock).unwrap().is_empty());

    // A constrained add is accepted and the key expires.
    add_identity(sock, &key("id_ed25519"), None, Some(1)).unwrap();
    assert_eq!(fingerprints(sock), [key("id_ed25519").fingerprint]);
    std::thread::sleep(Duration::from_millis(2500));
    assert!(list_identities(sock).unwrap().is_empty());
}

/// A missing socket is an error, not a panic.
#[test]
fn missing_socket_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("none.sock");
    assert!(list_identities(&sock).is_err());
    assert!(remove_all(&sock).is_err());
}

/// A fake agent sending garbage yields errors, never panics or hangs.
#[test]
fn malformed_agent_replies_are_errors() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("fake.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let replies: Vec<Vec<u8>> = vec![
        vec![0, 0, 0, 0],
        vec![0xff, 0xff, 0xff, 0xff],
        vec![0, 0, 0, 5, 12, 0xff, 0xff, 0xff, 0xff],
        vec![0, 0, 0, 1, 5],
        vec![0, 0, 0, 9, 6],
    ];
    let count = replies.len();
    let server = std::thread::spawn(move || {
        for reply in replies {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let _ = conn.read(&mut buf);
            let _ = conn.write_all(&reply);
        }
    });
    for _ in 0..count {
        assert!(list_identities(&sock).is_err());
    }
    server.join().unwrap();
}
