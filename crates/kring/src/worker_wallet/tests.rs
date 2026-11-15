//! Unit tests of the KWallet worker commands (FakeStore + tempdir copies of
//! the committed fixture wallet; the user's real wallets are never read).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kring_core::SecretStore;
use kring_core::backup::{BACKUP_KEEP, BackupManager};
use kring_core::fake_store::FakeStore;
use kring_core::model::{Attributes, CollectionId, NewItem, SecretValue};
use kring_core::provider::{ProviderInfo, ProviderKind};
use kring_core::transfer::plan::Choice;

use super::{MSG_KWALLET_COMPETITOR, OfflineItemView, WalletEntryKind, WalletInfo};
use crate::worker::{Command, Event, WorkerConfig, WorkerHandle, spawn};

/// Directory of the KWallet fixtures (written by a real `ksecretd`).
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kring-core/tests/fixtures/kwallet"
);
/// Name of the fixture wallet.
const FIXTURE: &str = "fixture";
/// Password of the fixture wallet.
const PASSWORD: &str = "fixture-pw";
/// Prefix shared by every secret of the fixture wallet.
const SECRET_PREFIX: &str = "fixture-secret";
/// Number of entries of the fixture wallet.
const ENTRY_COUNT: usize = 7;
/// Bus name of a running KWallet compat daemon.
const KWALLETD6: &str = "org.kde.kwalletd6";

/// Test environment: temp dirs, a shared FakeStore and the worker handle.
struct Env {
    _dir: tempfile::TempDir,
    kwallet: PathBuf,
    store: Arc<FakeStore>,
    handle: WorkerHandle,
    main: CollectionId,
}

/// Builds a gnome-keyring provider with the given competitors.
fn provider(competitors: &[&str]) -> Option<ProviderInfo> {
    Some(ProviderInfo {
        kind: ProviderKind::GnomeKeyring,
        pid: None,
        process_name: None,
        competitors: competitors.iter().map(|c| c.to_string()).collect(),
        has_master_password_iface: true,
    })
}

/// Runs a store future to completion on a private runtime.
fn block<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(fut)
}

/// Builds attributes from pairs.
fn attrs(pairs: &[(&str, &str)]) -> Attributes {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Copies the three fixture files into `dir` as wallet `name`.
fn copy_fixture(dir: &Path, name: &str) {
    let files = [
        ("fixture.kwl", format!("{name}.kwl")),
        ("fixture.salt", format!("{name}.salt")),
        ("fixture_attributes.json", format!("{name}_attributes.json")),
    ];
    for (src, dst) in files {
        std::fs::copy(Path::new(FIXTURES).join(src), dir.join(dst)).unwrap();
    }
}

/// Starts a worker over a FakeStore with an unlocked `Main` and the fixture
/// wallet in a temp `kwalletd` dir, skipping the startup events.
fn env_with(competitors: &[&str]) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let keyrings = dir.path().join("keyrings");
    let pam = dir.path().join("pam");
    let kwallet = dir.path().join("kwalletd");
    for d in [&keyrings, &pam, &kwallet] {
        std::fs::create_dir_all(d).unwrap();
    }
    copy_fixture(&kwallet, FIXTURE);
    let config = WorkerConfig {
        backups: BackupManager {
            root: dir.path().join("backups"),
            keep: BACKUP_KEEP,
        },
        keyrings_dir: keyrings,
        pam_dir: pam,
        kwallet_dir: kwallet.clone(),
        ssh_dir: None,
        ssh_agent_sock: None,
        gnupg_home: Some(std::path::PathBuf::from(crate::worker::NO_GNUPG_HOME)),
    };
    let store = Arc::new(FakeStore::new());
    let main = store.add_collection("Main", "pw", false);
    let handle = spawn(Some(store.clone()), provider(competitors), config, || {});
    let env = Env {
        _dir: dir,
        kwallet,
        store,
        handle,
        main,
    };
    for _ in 0..3 {
        env.next();
    }
    env
}

/// Starts the default environment (no competitors).
fn env() -> Env {
    env_with(&[])
}

impl Env {
    /// Receives the next event (failing after 10 seconds); only
    /// `WalletItems` may carry wallet secrets, and no event ever carries
    /// the wallet password.
    fn next(&self) -> Event {
        let event = crate::worker::next_event(&self.handle, Duration::from_secs(10));
        let text = format!("{event:?}");
        assert!(!text.contains(PASSWORD), "password leaked: {text}");
        if !matches!(event, Event::WalletItems { .. }) {
            assert!(!text.contains(SECRET_PREFIX), "secret leaked: {text}");
        }
        event
    }

    /// Receives events up to and including the end of the current command.
    fn rest(&self) -> Vec<Event> {
        let mut events = Vec::new();
        loop {
            let event = self
                .handle
                .rx
                .recv_timeout(Duration::from_secs(10))
                .expect("event expected");
            if matches!(event, Event::CommandFinished(_)) {
                return events;
            }
            events.push(event);
        }
    }

    /// Sends a command.
    fn send(&self, cmd: Command) {
        self.handle.tx.send(cmd).unwrap();
    }

    /// Asserts the next event is an error and returns its message.
    fn expect_error(&self) -> String {
        match self.next() {
            Event::Error(m) => m,
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Asserts the next event is a wallet list and returns it.
    fn expect_wallets(&self) -> Vec<WalletInfo> {
        match self.next() {
            Event::Wallets(list) => list,
            other => panic!("expected Wallets, got {other:?}"),
        }
    }

    /// Opens the fixture wallet and returns its items.
    fn open(&self) -> Vec<OfflineItemView> {
        self.send(Command::OpenWallet {
            name: FIXTURE.into(),
            password: SecretValue::from_text(PASSWORD),
        });
        match self.next() {
            Event::WalletItems { name, items } => {
                assert_eq!(name, FIXTURE);
                items
            }
            other => panic!("expected WalletItems, got {other:?}"),
        }
    }

    /// Sends a wallet import of the fixture into `target`.
    fn import(&self, target: &CollectionId, password: &str) {
        self.send(Command::PlanWalletImport {
            name: FIXTURE.into(),
            password: SecretValue::from_text(password),
            target: target.clone(),
        });
    }

    /// Adds an item directly to the store.
    fn add_item(&self, c: &CollectionId, label: &str, pairs: &[(&str, &str)], secret: &str) {
        let item = NewItem {
            label: label.into(),
            attributes: attrs(pairs),
            secret: SecretValue::from_text(secret),
            replace: false,
        };
        block(self.store.create_item(c, item)).unwrap();
    }

    /// Returns the `(label, secret)` pairs of collection `c`, sorted by label.
    fn contents(&self, c: &CollectionId) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for info in block(self.store.list_items(c)).unwrap() {
            let secret = block(self.store.read_secret(&info.id)).unwrap();
            out.push((info.label, secret.as_bytes().to_vec()));
        }
        out.sort();
        out
    }
}

/// Returns the item labelled `label`.
fn by_label<'a>(items: &'a [OfflineItemView], label: &str) -> &'a OfflineItemView {
    items
        .iter()
        .find(|i| i.label == label)
        .unwrap_or_else(|| panic!("no item {label}"))
}

/// Scanning lists the `*.kwl` files with header, size and attribute file;
/// a non-wallet file has no header, other files are not listed.
#[test]
fn scan_lists_wallets() {
    let e = env();
    std::fs::write(e.kwallet.join("junk.kwl"), b"not a wallet").unwrap();
    std::fs::write(e.kwallet.join("notes.txt"), b"x").unwrap();
    e.send(Command::ScanWallets);
    let list = e.expect_wallets();
    let names: Vec<&str> = list.iter().map(|w| w.name.as_str()).collect();
    assert_eq!(names, [FIXTURE, "junk"]);
    let fixture = &list[0];
    assert_eq!(fixture.path, e.kwallet.join("fixture.kwl"));
    let size = std::fs::metadata(&fixture.path).unwrap().len();
    assert_eq!(fixture.size, size);
    assert!(fixture.modified > 0);
    assert!(fixture.header.expect("header").is_supported());
    assert!(fixture.has_attributes);
    assert_eq!(fixture.suggested_target, None);
    assert_eq!(list[1].header, None);
    assert!(!list[1].has_attributes);
}

/// A collection labelled like the wallet is the suggested import target.
#[test]
fn scan_suggests_same_label_collection() {
    let e = env();
    let kdewallet = e.store.add_collection(FIXTURE, "pw", false);
    e.send(Command::ScanWallets);
    let list = e.expect_wallets();
    assert_eq!(list[0].suggested_target, Some(kdewallet));
}

/// A missing KWallet directory is an empty list, not an error.
#[test]
fn scan_missing_dir_is_empty() {
    let e = env();
    std::fs::remove_dir_all(&e.kwallet).unwrap();
    e.send(Command::ScanWallets);
    assert!(e.expect_wallets().is_empty());
}

/// Opening yields every entry with label, attributes, folder, key, kind and secret.
#[test]
fn open_wallet_yields_items() {
    let e = env();
    let items = e.open();
    assert_eq!(items.len(), ENTRY_COUNT);
    let bob = by_label(&items, "Fixture bob");
    assert_eq!(
        bob.attributes,
        attrs(&[("service", "fixture"), ("user", "bob")])
    );
    assert_eq!(
        (bob.folder.as_str(), bob.key.as_str()),
        ("Secret Service", "Fixture bob")
    );
    assert_eq!(bob.kind, WalletEntryKind::Password);
    assert!(bob.app_entry);
    assert_eq!(bob.secret.as_text(), Some("fixture-secret-3"));
    let site = by_label(&items, "Passwords/site");
    assert!(!site.app_entry);
    assert_eq!(
        site.attributes.get("kwallet-folder").map(String::as_str),
        Some("Passwords")
    );
    assert_eq!(site.secret.as_text(), Some("fixture-secret-1"));
    let form = by_label(&items, "Maps/form");
    assert_eq!(form.kind, WalletEntryKind::Map);
    assert_eq!(
        form.secret.as_text(),
        Some(r#"{"pass":"fixture-secret-2","user":"alice"}"#)
    );
    let blob = by_label(&items, "Streams/blob");
    assert_eq!(blob.kind, WalletEntryKind::Stream);
    assert!(!blob.app_entry, "synthesized record is not an app entry");
    assert_eq!(blob.secret.as_bytes(), [0x00, 0xff, 0x10]);
}

/// A wrong password is a plain error, never items or a passphrase request.
#[test]
fn open_wrong_password_is_error() {
    let e = env();
    e.send(Command::OpenWallet {
        name: FIXTURE.into(),
        password: SecretValue::from_text("nope"),
    });
    assert_eq!(e.expect_error(), "Wrong wallet password");
    assert!(e.rest().is_empty());
}

/// Names that are not a scanned wallet are refused.
#[test]
fn open_unknown_or_bad_name() {
    let e = env();
    for name in ["missing", "../fixture", "", "."] {
        e.send(Command::OpenWallet {
            name: name.into(),
            password: SecretValue::from_text(PASSWORD),
        });
        let message = e.expect_error();
        assert!(message.contains("wallet"), "{message}");
        assert!(e.rest().is_empty());
    }
    std::os::unix::fs::symlink(e.kwallet.join("fixture.kwl"), e.kwallet.join("link.kwl")).unwrap();
    std::os::unix::fs::symlink(e.kwallet.join("fixture.salt"), e.kwallet.join("link.salt"))
        .unwrap();
    e.send(Command::OpenWallet {
        name: "link".into(),
        password: SecretValue::from_text(PASSWORD),
    });
    assert!(e.expect_error().contains("No wallet named"));
}

/// Without conflicts the import is applied directly; re-running it only
/// finds duplicates. No notice without a KWallet competitor.
#[test]
fn import_without_conflicts_then_idempotent() {
    let e = env();
    e.import(&e.main, PASSWORD);
    match e.next() {
        Event::ImportDone(r) => assert_eq!((r.created, r.duplicates), (ENTRY_COUNT, 0)),
        other => panic!("expected ImportDone, got {other:?}"),
    }
    assert!(
        matches!(e.next(), Event::Items(id, items) if id == e.main && items.len() == ENTRY_COUNT)
    );
    assert!(matches!(e.next(), Event::Collections(_)));
    assert!(e.rest().is_empty(), "no notice expected");
    let contents = e.contents(&e.main);
    let bob = contents.iter().find(|(l, _)| l == "Fixture bob").unwrap();
    assert_eq!(bob.1, b"fixture-secret-3");
    e.import(&e.main, PASSWORD);
    match e.next() {
        Event::ImportDone(r) => assert_eq!((r.created, r.duplicates), (0, ENTRY_COUNT)),
        other => panic!("expected ImportDone, got {other:?}"),
    }
}

/// With a KWallet competitor running, a successful import ends with the notice.
#[test]
fn import_emits_competitor_notice() {
    let e = env_with(&[KWALLETD6]);
    e.import(&e.main, PASSWORD);
    let events = e.rest();
    assert!(matches!(events[0], Event::ImportDone(_)), "{events:?}");
    let notices: Vec<&String> = events
        .iter()
        .filter_map(|ev| match ev {
            Event::Notice(text) => Some(text),
            _ => None,
        })
        .collect();
    assert_eq!(notices, [MSG_KWALLET_COMPETITOR]);
    assert_eq!(
        MSG_KWALLET_COMPETITOR,
        "KWallet is still running and may claim org.freedesktop.secrets; disable KWallet's Secret Service integration after migrating"
    );
}

/// Conflicts are previewed with the offline side revealable from the wallet
/// items, applied later; the notice follows the transfer.
#[test]
fn import_with_conflicts_previews() {
    let e = env_with(&["org.kde.secretservicecompat"]);
    e.add_item(
        &e.main,
        "mine",
        &[("service", "fixture"), ("user", "bob")],
        "other",
    );
    let items = e.open();
    e.import(&e.main, PASSWORD);
    let (plan_id, conflicts) = match e.next() {
        Event::TransferPreview {
            plan_id,
            counts,
            conflicts,
            ..
        } => {
            assert_eq!((counts.create, counts.conflict), (ENTRY_COUNT - 1, 1));
            (plan_id, conflicts)
        }
        other => panic!("expected TransferPreview, got {other:?}"),
    };
    let view = &conflicts[0];
    assert_eq!(view.incoming_item, None);
    assert!(view.incoming_revealable);
    let index = view.offline_index.expect("offline index");
    assert_eq!(items[index].label, view.label_incoming);
    assert_eq!(items[index].secret.as_text(), Some("fixture-secret-3"));
    assert!(e.rest().is_empty());
    e.send(Command::ApplyTransfer {
        plan_id,
        choices: vec![Choice::KeepTarget],
        backup_passphrase: None,
    });
    let events = e.rest();
    match &events[0] {
        Event::TransferDone(r) => assert_eq!((r.created, r.kept_target), (ENTRY_COUNT - 1, 1)),
        other => panic!("expected TransferDone, got {other:?}"),
    }
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Event::Notice(t) if t == MSG_KWALLET_COMPETITOR))
    );
}

/// A wrong password on import is an error and leaves no plan behind.
#[test]
fn import_wrong_password_has_no_plan() {
    let e = env();
    e.import(&e.main, "nope");
    assert_eq!(e.expect_error(), "Wrong wallet password");
    assert!(e.rest().is_empty());
    e.send(Command::ApplyTransfer {
        plan_id: 1,
        choices: vec![],
        backup_passphrase: None,
    });
    assert_eq!(e.expect_error(), "Plan is out of date, preview again");
    assert!(e.contents(&e.main).is_empty());
}

/// The wallet keyring is created with the wallet name as label and becomes
/// the suggested target; a second one is refused.
#[test]
fn create_wallet_collection() {
    let e = env();
    let create = || Command::CreateWalletCollection {
        name: FIXTURE.into(),
        password: SecretValue::from_text("new-pw"),
    };
    e.send(create());
    let events = e.rest();
    let created = events
        .iter()
        .find_map(|ev| match ev {
            Event::Collections(list) => list.iter().find(|c| c.label == FIXTURE).cloned(),
            _ => None,
        })
        .expect("collection listed");
    let wallets = events
        .iter()
        .find_map(|ev| match ev {
            Event::Wallets(list) => Some(list.clone()),
            _ => None,
        })
        .expect("wallets listed");
    assert_eq!(wallets[0].suggested_target, Some(created.id));
    assert!(matches!(events.last(), Some(Event::Done(m)) if m.contains(FIXTURE)));
    e.send(create());
    assert!(e.expect_error().contains("already exists"));
    e.send(Command::CreateWalletCollection {
        name: "missing".into(),
        password: SecretValue::from_text("new-pw"),
    });
    assert!(e.expect_error().contains("No wallet named"));
}

/// Without the master password interface the keyring cannot be created.
#[test]
fn create_wallet_collection_gated() {
    let dir = tempfile::tempdir().unwrap();
    let kwallet = dir.path().join("kwalletd");
    std::fs::create_dir_all(&kwallet).unwrap();
    copy_fixture(&kwallet, FIXTURE);
    let config = WorkerConfig {
        backups: BackupManager {
            root: dir.path().join("backups"),
            keep: BACKUP_KEEP,
        },
        keyrings_dir: dir.path().join("keyrings"),
        pam_dir: dir.path().join("pam"),
        kwallet_dir: kwallet,
        ssh_dir: None,
        ssh_agent_sock: None,
        gnupg_home: Some(std::path::PathBuf::from(crate::worker::NO_GNUPG_HOME)),
    };
    let mut info = provider(&[]).unwrap();
    info.has_master_password_iface = false;
    let store = Arc::new(FakeStore::new());
    let handle = spawn(Some(store), Some(info), config, || {});
    let next = || crate::worker::next_event(&handle, Duration::from_secs(10));
    for _ in 0..3 {
        next();
    }
    handle
        .tx
        .send(Command::CreateWalletCollection {
            name: FIXTURE.into(),
            password: SecretValue::from_text("new-pw"),
        })
        .unwrap();
    assert!(matches!(next(), Event::Error(m) if m == "Not supported on this provider"));
}

/// ksecretd (the daemon owning the wallets) also triggers the notice.
#[test]
fn import_notice_for_ksecretd() {
    let e = env_with(&["org.kde.ksecretd"]);
    e.import(&e.main, PASSWORD);
    let events = e.rest();
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Event::Notice(t) if t == MSG_KWALLET_COMPETITOR)),
        "{events:?}"
    );
}

/// A symlinked salt or attributes file is refused when opening, and a
/// symlinked attributes file does not count as app attributes.
#[test]
fn open_refuses_symlinked_companions() {
    let e = env();
    let link = |src: &str, dst: &str| {
        std::os::unix::fs::symlink(e.kwallet.join(src), e.kwallet.join(dst)).unwrap();
    };
    std::fs::copy(e.kwallet.join("fixture.kwl"), e.kwallet.join("salty.kwl")).unwrap();
    link("fixture.salt", "salty.salt");
    std::fs::copy(e.kwallet.join("fixture.kwl"), e.kwallet.join("attrs.kwl")).unwrap();
    std::fs::copy(e.kwallet.join("fixture.salt"), e.kwallet.join("attrs.salt")).unwrap();
    link("fixture_attributes.json", "attrs_attributes.json");
    for name in ["salty", "attrs"] {
        e.send(Command::OpenWallet {
            name: name.into(),
            password: SecretValue::from_text(PASSWORD),
        });
        let message = e.expect_error();
        assert!(message.contains("not a regular file"), "{message}");
        assert!(e.rest().is_empty());
    }
    e.send(Command::ScanWallets);
    let list = e.expect_wallets();
    let attrs = list.iter().find(|w| w.name == "attrs").unwrap();
    assert!(!attrs.has_attributes);
}

/// Previews a conflicting import of the fixture into `Main` and returns the plan id.
fn conflict_preview(e: &Env) -> u64 {
    e.add_item(
        &e.main,
        "mine",
        &[("service", "fixture"), ("user", "bob")],
        "other",
    );
    e.import(&e.main, PASSWORD);
    let plan_id = match e.next() {
        Event::TransferPreview { plan_id, .. } => plan_id,
        other => panic!("expected TransferPreview, got {other:?}"),
    };
    assert!(e.rest().is_empty());
    plan_id
}

/// Applies plan `plan_id` keeping the target and returns the first event.
fn apply_keep(e: &Env, plan_id: u64) -> Event {
    e.send(Command::ApplyTransfer {
        plan_id,
        choices: vec![Choice::KeepTarget],
        backup_passphrase: None,
    });
    let events = e.rest();
    events.into_iter().next().expect("an event")
}

/// Scanning or opening wallets keeps a pending plan; creating the wallet
/// keyring drops it.
#[test]
fn wallet_reads_keep_plan_create_drops_it() {
    let e = env();
    let plan_id = conflict_preview(&e);
    e.send(Command::ScanWallets);
    e.expect_wallets();
    assert!(e.rest().is_empty());
    e.open();
    assert!(e.rest().is_empty());
    assert!(matches!(apply_keep(&e, plan_id), Event::TransferDone(_)));

    let e = env();
    let plan_id = conflict_preview(&e);
    e.send(Command::CreateWalletCollection {
        name: FIXTURE.into(),
        password: SecretValue::from_text("new-pw"),
    });
    assert!(e.rest().iter().any(|ev| matches!(ev, Event::Done(_))));
    assert!(matches!(
        apply_keep(&e, plan_id),
        Event::Error(m) if m == "Plan is out of date, preview again"
    ));
}

/// A failed rescan after creating the wallet keyring is reported on its
/// own and the creation is still reported done.
#[test]
fn created_keyring_done_despite_rescan_error() {
    let dir = tempfile::tempdir().unwrap();
    let not_a_dir = dir.path().join("kwalletd");
    std::fs::write(&not_a_dir, b"file").unwrap();
    let config = WorkerConfig {
        backups: BackupManager {
            root: dir.path().join("backups"),
            keep: BACKUP_KEEP,
        },
        keyrings_dir: dir.path().join("keyrings"),
        pam_dir: dir.path().join("pam"),
        kwallet_dir: not_a_dir,
        ssh_dir: None,
        ssh_agent_sock: None,
        gnupg_home: Some(std::path::PathBuf::from(crate::worker::NO_GNUPG_HOME)),
    };
    let store = FakeStore::new();
    store.add_collection(FIXTURE, "pw", false);
    let (tx, rx) = std::sync::mpsc::channel();
    let out = crate::worker::Emitter::for_test(tx, || {});
    block(super::finish_create(&out, &store, &config, FIXTURE));
    let events: Vec<Event> = rx.try_iter().collect();
    assert!(matches!(&events[0], Event::Collections(_)), "{events:?}");
    assert!(
        matches!(&events[1], Event::Error(m) if m.starts_with("Cannot rescan the wallets")),
        "{events:?}"
    );
    assert!(matches!(&events[2], Event::Done(m) if m == "Keyring 'fixture' created"));
}
