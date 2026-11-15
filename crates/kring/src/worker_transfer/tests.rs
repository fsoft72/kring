//! Unit tests of the transfer and consolidation worker commands
//! (FakeStore + tempdir keyrings with synthetic fixtures).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kring_core::SecretStore;
use kring_core::backup::{BACKUP_KEEP, BackupManager, KEYRING_MAGIC};
use kring_core::fake_store::FakeStore;
use kring_core::keyring_file::textual::OfflineItem;
use kring_core::model::{
    Attributes, CollectionId, ItemId, ItemInfo, ItemUpdate, NewItem, SecretValue,
};
use kring_core::provider::{ProviderInfo, ProviderKind};
use kring_core::transfer::apply::TransferMode;
use kring_core::transfer::archive::{ExportedItem, write_archive};
use kring_core::transfer::consolidate::SkipReason;
use kring_core::transfer::plan::{Choice, TransferCounts};

use super::{MSG_MOVE_INTO_SELF, MSG_SOURCES_CHANGED, MSG_STALE_PLAN, MSG_TARGET_CHANGED};
use crate::worker::{Command, ConflictView, Event, WorkerConfig, WorkerHandle, spawn};

/// Directory of the synthetic keyring fixtures.
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kring-core/tests/fixtures/keyrings"
);
/// Textual fixture with two items (`user=alice` and `port=8080`).
const TEXTUAL: &str = "textual_two_items";
/// Textual fixture without items.
const EMPTY_TEXTUAL: &str = "empty_textual";
/// Schema attribute the textual parser derives from `item-type`.
const SCHEMA: &str = "xdg:schema";
/// Schema of the fixture's first item (`item-type=0`).
const GENERIC: &str = "org.freedesktop.Secret.Generic";
/// Passphrase used for backups and archives.
const PASSPHRASE: &str = "backup-pass";
/// Message of the write gate.
const MSG_UNSUPPORTED: &str = "Not supported on this provider";

/// Test environment: temp dirs, a shared FakeStore and the worker handle.
struct Env {
    dir: tempfile::TempDir,
    keyrings: PathBuf,
    backups: PathBuf,
    store: Arc<FakeStore>,
    handle: WorkerHandle,
    main: CollectionId,
    other: CollectionId,
}

/// Builds a provider of the given kind.
fn provider(kind: ProviderKind) -> Option<ProviderInfo> {
    Some(ProviderInfo {
        kind,
        pid: None,
        process_name: None,
        competitors: vec![],
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

/// Starts a worker with unlocked `Main` and `Other`, skipping the startup events.
fn env(kind: ProviderKind) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let keyrings = dir.path().join("keyrings");
    let pam = dir.path().join("pam");
    for d in [&keyrings, &pam] {
        std::fs::create_dir_all(d).unwrap();
    }
    let backups = dir.path().join("backups");
    let config = WorkerConfig {
        backups: BackupManager {
            root: backups.clone(),
            keep: BACKUP_KEEP,
        },
        keyrings_dir: keyrings.clone(),
        pam_dir: pam,
        kwallet_dir: keyrings.join("kwalletd-unused"),
        ssh_dir: None,
        ssh_agent_sock: None,
        gnupg_home: Some(std::path::PathBuf::from(crate::worker::NO_GNUPG_HOME)),
    };
    let store = Arc::new(FakeStore::new());
    let main = store.add_collection("Main", "pw", false);
    let other = store.add_collection("Other", "pw", false);
    let handle = spawn(Some(store.clone()), provider(kind), config, || {});
    let env = Env {
        dir,
        keyrings,
        backups,
        store,
        handle,
        main,
        other,
    };
    for _ in 0..3 {
        env.next();
    }
    env
}

/// Starts a gnome-keyring worker (writes allowed).
fn gnome() -> Env {
    env(ProviderKind::GnomeKeyring)
}

impl Env {
    /// Receives the next event, failing after 10 seconds; every event goes
    /// through [`assert_secret_free`].
    fn next(&self) -> Event {
        let event = crate::worker::next_event(&self.handle, Duration::from_secs(10));
        assert_secret_free(&event);
        event
    }

    /// Sends a command.
    fn send(&self, cmd: Command) {
        self.handle.tx.send(cmd).unwrap();
    }

    /// Receives events until one matches `stop` and returns all of them.
    fn until(&self, stop: impl Fn(&Event) -> bool) -> Vec<Event> {
        let mut events = Vec::new();
        loop {
            let event = self.next();
            let last = stop(&event);
            events.push(event);
            if last {
                return events;
            }
        }
    }

    /// Asserts the next event is an error and returns its message.
    fn expect_error(&self) -> String {
        match self.next() {
            Event::Error(m) => m,
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Asserts the next event is a transfer preview and returns its parts.
    fn expect_preview(&self) -> (u64, TransferMode, TransferCounts, Vec<ConflictView>) {
        match self.next() {
            Event::TransferPreview {
                plan_id,
                mode,
                counts,
                conflicts,
                ..
            } => (plan_id, mode, counts, conflicts),
            other => panic!("expected TransferPreview, got {other:?}"),
        }
    }

    /// Adds an item directly to the store and returns its id.
    fn add_item(
        &self,
        c: &CollectionId,
        label: &str,
        pairs: &[(&str, &str)],
        secret: &str,
    ) -> ItemId {
        let item = NewItem {
            label: label.into(),
            attributes: attrs(pairs),
            secret: SecretValue::from_text(secret),
            replace: false,
        };
        block(self.store.create_item(c, item)).unwrap()
    }

    /// Lists the items of a collection directly from the store.
    fn items(&self, c: &CollectionId) -> Vec<ItemInfo> {
        block(self.store.list_items(c)).unwrap()
    }

    /// Reads a secret directly from the store as text.
    fn secret(&self, id: &ItemId) -> String {
        let secret = block(self.store.read_secret(id)).unwrap();
        secret.as_text().unwrap().to_string()
    }

    /// Returns true when the store still lists collection `c`.
    fn has_collection(&self, c: &CollectionId) -> bool {
        let list = block(self.store.list_collections()).unwrap();
        list.iter().any(|i| &i.id == c)
    }

    /// Writes a binary-looking `<name>.keyring`.
    fn binary_keyring(&self, name: &str) {
        let mut bytes = KEYRING_MAGIC.to_vec();
        bytes.extend_from_slice(b"payload");
        std::fs::write(self.keyring(name), bytes).unwrap();
    }

    /// Copies fixture `fixture` to `<name>.keyring`.
    fn fixture_keyring(&self, fixture: &str, name: &str) {
        let src = Path::new(FIXTURES).join(format!("{fixture}.keyring"));
        std::fs::copy(src, self.keyring(name)).unwrap();
    }

    /// Returns the path of `<name>.keyring` in the keyrings dir.
    fn keyring(&self, name: &str) -> PathBuf {
        self.keyrings.join(format!("{name}.keyring"))
    }

    /// Counts the backups written so far.
    fn backup_count(&self) -> usize {
        std::fs::read_dir(&self.backups).map_or(0, |d| d.count())
    }

    /// Plans a live transfer and returns its preview.
    fn plan(
        &self,
        items: &[&ItemId],
        target: &CollectionId,
        mode: TransferMode,
    ) -> (u64, Vec<ConflictView>) {
        self.send(Command::PlanTransfer {
            items: items.iter().map(|i| (*i).clone()).collect(),
            target: target.clone(),
            mode,
        });
        let (plan_id, got_mode, _, conflicts) = self.expect_preview();
        assert_eq!(got_mode, mode);
        (plan_id, conflicts)
    }

    /// Sends `ApplyTransfer` with `choices` and the given backup passphrase.
    fn apply(&self, plan_id: u64, choices: Vec<Choice>, passphrase: Option<&str>) {
        self.send(Command::ApplyTransfer {
            plan_id,
            choices,
            backup_passphrase: passphrase.map(SecretValue::from_text),
        });
    }

    /// Plans a consolidation into `Main` and returns the plan id and summary.
    fn plan_consolidation(&self, orphans: bool) -> (u64, crate::worker::ConsolidationSummary) {
        self.send(Command::PlanConsolidation {
            target: self.main.clone(),
            include_orphan_files: orphans,
        });
        match self.next() {
            Event::ConsolidationPreview { plan_id, summary } => (plan_id, summary),
            other => panic!("expected ConsolidationPreview, got {other:?}"),
        }
    }
}

/// Returns true for the events whose payload can hold a `SecretValue`.
///
/// Exhaustive on purpose: a new variant must be classified here.
fn may_carry_secret(event: &Event) -> bool {
    match event {
        Event::Secret(..)
        | Event::FileItems { .. }
        | Event::WalletItems { .. }
        | Event::PassphraseNeeded(_) => true,
        Event::Provider(_)
        | Event::ProviderUnavailable
        | Event::Pam(_)
        | Event::Collections(_)
        | Event::Items(..)
        | Event::BackupCreated(_)
        | Event::ApplyPassphrasesNeeded { .. }
        | Event::Files(_)
        | Event::PasswordNeeded(_)
        | Event::ImportDone(_)
        | Event::Backups(_)
        | Event::RestoreDone(_)
        | Event::Wallets(_)
        | Event::SshKeys(_)
        | Event::AgentIdentities(_)
        | Event::SshPublicKey { .. }
        | Event::GpgKeys(_)
        | Event::GpgUnavailable { .. }
        | Event::GpgPublicKey { .. }
        | Event::Notice(_)
        | Event::TransferPreview { .. }
        | Event::TransferDone(_)
        | Event::ConsolidationPreview { .. }
        | Event::ConsolidationProgress { .. }
        | Event::ConsolidationDone(..)
        | Event::Done(_)
        | Event::Error(_)
        | Event::CommandFinished(_) => false,
    }
}

/// Fails on any event that can carry a secret: these tests never reveal
/// secrets or open files, and transfer handlers must never echo a command
/// (in particular an apply command) in `PassphraseNeeded`.
fn assert_secret_free(event: &Event) {
    if !may_carry_secret(event) {
        return;
    }
    panic!("event that can carry a secret: {event:?}");
}

/// Returns the transfer report of the first `TransferDone` among `events`.
fn transfer_done(events: &[Event]) -> kring_core::transfer::apply::TransferReport {
    events
        .iter()
        .find_map(|e| match e {
            Event::TransferDone(r) => Some(r.clone()),
            _ => None,
        })
        .expect("TransferDone expected")
}

/// A copy is previewed, then applied without any backup.
#[test]
fn plan_then_apply_copy() {
    let e = gnome();
    let item = e.add_item(&e.other, "site", &[("k", "1")], "s1");
    let (plan_id, conflicts) = e.plan(&[&item], &e.main, TransferMode::Copy);
    assert!(conflicts.is_empty());
    e.apply(plan_id, vec![], None);
    let report = match e.next() {
        Event::TransferDone(r) => r,
        other => panic!("expected TransferDone, got {other:?}"),
    };
    assert_eq!((report.created, report.source_deleted), (1, 0));
    assert!(matches!(e.next(), Event::Items(id, items) if id == e.main && items.len() == 1));
    assert!(matches!(e.next(), Event::Collections(_)));
    assert_eq!(e.items(&e.other).len(), 1);
    assert_eq!(e.backup_count(), 0);
}

/// An apply after any other mutation, with a wrong id, twice or after a
/// discard is refused and changes nothing.
#[test]
fn stale_plan_rejected() {
    let e = gnome();
    let item = e.add_item(&e.other, "site", &[("k", "1")], "s1");
    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Copy);
    e.send(Command::SetDefault(e.other.clone()));
    assert!(matches!(e.next(), Event::Collections(_)));
    assert!(matches!(e.next(), Event::Done(_)));
    e.apply(plan_id, vec![], None);
    assert_eq!(e.expect_error(), MSG_STALE_PLAN);

    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Copy);
    e.apply(plan_id + 1, vec![], None);
    assert_eq!(e.expect_error(), MSG_STALE_PLAN);

    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Copy);
    e.send(Command::DiscardPlan);
    e.apply(plan_id, vec![], None);
    assert_eq!(e.expect_error(), MSG_STALE_PLAN);

    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Copy);
    e.send(Command::LoadItems(e.main.clone()));
    assert!(matches!(e.next(), Event::Items(_, _)));
    e.apply(plan_id, vec![], None);
    e.until(|ev| matches!(ev, Event::Collections(_)));
    e.apply(plan_id, vec![], None);
    assert_eq!(e.expect_error(), MSG_STALE_PLAN);
    assert_eq!(e.items(&e.main).len(), 1);
}

/// Review Focus 2: `UseIncoming` overwrites only after the backup succeeded;
/// a passphrase request keeps the plan valid for the resent command.
#[test]
fn use_incoming_requires_backup_first() {
    let e = gnome();
    let existing = e.add_item(&e.main, "site", &[("k", "1")], "old");
    let item = e.add_item(&e.other, "site", &[("k", "1")], "new");
    let (plan_id, conflicts) = e.plan(&[&item], &e.main, TransferMode::Copy);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].existing_item, Some(existing.clone()));
    assert_eq!(conflicts[0].incoming_item, Some(item.clone()));
    e.apply(plan_id, vec![Choice::UseIncoming], None);
    let m = e.expect_error();
    assert!(m.starts_with("No keyring file found for 'Main'"), "{m}");
    assert!(m.ends_with("refusing to change without a backup"), "{m}");
    assert_eq!(e.secret(&existing), "old");
    assert_eq!(e.backup_count(), 0);

    e.fixture_keyring(EMPTY_TEXTUAL, "Main");
    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Copy);
    e.apply(plan_id, vec![Choice::UseIncoming], None);
    match e.next() {
        Event::ApplyPassphrasesNeeded {
            plan_id: p,
            backup,
            orphan_files,
        } => assert_eq!((p, backup, orphan_files), (plan_id, true, false)),
        other => panic!("expected ApplyPassphrasesNeeded, got {other:?}"),
    }
    assert_eq!(e.secret(&existing), "old");
    e.apply(plan_id, vec![Choice::UseIncoming], Some(PASSPHRASE));
    assert!(matches!(e.next(), Event::BackupCreated(_)));
    let events = e.until(|ev| matches!(ev, Event::Collections(_)));
    assert_eq!(transfer_done(&events).replaced, 1);
    assert_eq!(e.secret(&existing), "new");
    assert_eq!(e.backup_count(), 1);
}

/// A move backs up target and source in ONE backup, then deletes the source;
/// a missing source keyring file refuses the move with nothing changed.
#[test]
fn move_backs_up_source_and_target() {
    let e = gnome();
    e.binary_keyring("Main");
    e.binary_keyring("Other");
    let item = e.add_item(&e.other, "site", &[("k", "1")], "s1");
    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Move);
    e.apply(plan_id, vec![], None);
    let files = match e.next() {
        Event::BackupCreated(info) => info.files,
        other => panic!("expected BackupCreated, got {other:?}"),
    };
    for name in ["Main", "Other"] {
        assert!(
            files.iter().any(|f| f.original == e.keyring(name)),
            "{name}"
        );
    }
    let events = e.until(|ev| matches!(ev, Event::Collections(_)));
    assert_eq!(transfer_done(&events).source_deleted, 1);
    let lists: Vec<_> = events
        .iter()
        .filter_map(|ev| match ev {
            Event::Items(id, _) => Some(id.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(lists, [e.main.clone(), e.other.clone()]);
    assert!(e.items(&e.other).is_empty());
    assert_eq!(e.items(&e.main).len(), 1);
    assert_eq!(e.backup_count(), 1);

    std::fs::remove_file(e.keyring("Other")).unwrap();
    let second = e.add_item(&e.other, "two", &[("k", "2")], "s2");
    let (plan_id, _) = e.plan(&[&second], &e.main, TransferMode::Move);
    e.apply(plan_id, vec![], None);
    assert!(
        e.expect_error()
            .starts_with("No keyring file found for 'Other'")
    );
    assert_eq!(e.items(&e.other).len(), 1);
    assert_eq!(e.items(&e.main).len(), 1);
    assert_eq!(e.backup_count(), 1);
}

/// Move into the items' own collection is refused at plan time; Move and
/// `UseIncoming` need writes, copy-only works on any provider.
#[test]
fn move_gated_and_never_into_own_collection() {
    let e = gnome();
    let item = e.add_item(&e.main, "site", &[("k", "1")], "s1");
    e.send(Command::PlanTransfer {
        items: vec![item.clone()],
        target: e.main.clone(),
        mode: TransferMode::Move,
    });
    assert_eq!(e.expect_error(), MSG_MOVE_INTO_SELF);

    let k = env(ProviderKind::KWallet);
    let a = k.add_item(&k.other, "site", &[("k", "1")], "new");
    k.add_item(&k.main, "site", &[("k", "1")], "old");
    k.send(Command::PlanTransfer {
        items: vec![a.clone()],
        target: k.main.clone(),
        mode: TransferMode::Move,
    });
    assert_eq!(k.expect_error(), MSG_UNSUPPORTED);
    let (plan_id, conflicts) = k.plan(&[&a], &k.main, TransferMode::Copy);
    assert_eq!(conflicts.len(), 1);
    k.apply(plan_id, vec![Choice::UseIncoming], None);
    assert_eq!(k.expect_error(), MSG_UNSUPPORTED);
    let (plan_id, _) = k.plan(&[&a], &k.main, TransferMode::Copy);
    k.apply(plan_id, vec![Choice::KeepTarget], None);
    let events = k.until(|ev| matches!(ev, Event::Collections(_)));
    assert_eq!(transfer_done(&events).kept_target, 1);
    k.send(Command::PlanConsolidation {
        target: k.main.clone(),
        include_orphan_files: false,
    });
    assert_eq!(k.expect_error(), MSG_UNSUPPORTED);
}

/// A live source changed after the preview stops the apply before any change.
#[test]
fn changed_source_refused() {
    let e = gnome();
    let item = e.add_item(&e.other, "site", &[("k", "1")], "s1");
    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Copy);
    let update = ItemUpdate {
        label: None,
        attributes: None,
        secret: Some(SecretValue::from_text("changed")),
    };
    block(e.store.update_item(&item, update)).unwrap();
    e.apply(plan_id, vec![], None);
    assert_eq!(e.expect_error(), MSG_SOURCES_CHANGED);

    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Copy);
    let rename = ItemUpdate {
        label: Some("renamed".into()),
        attributes: None,
        secret: None,
    };
    block(e.store.update_item(&item, rename)).unwrap();
    e.apply(plan_id, vec![], None);
    assert_eq!(e.expect_error(), MSG_SOURCES_CHANGED);
    assert!(e.items(&e.main).is_empty());
}

/// A live source that only gained the generic `xdg:schema` since the preview
/// (gnome-keyring adds it on reload) is still applied.
#[test]
fn generic_schema_added_to_source_still_applies() {
    let e = gnome();
    let item = e.add_item(&e.other, "site", &[("k", "1")], "s1");
    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Copy);
    let update = ItemUpdate {
        label: None,
        attributes: Some(attrs(&[("k", "1"), (SCHEMA, GENERIC)])),
        secret: None,
    };
    block(e.store.update_item(&item, update)).unwrap();
    e.apply(plan_id, vec![], None);
    let events = e.until(|ev| matches!(ev, Event::Collections(_)));
    assert_eq!(transfer_done(&events).created, 1);
    assert_eq!(e.items(&e.main).len(), 1);
}

/// A target that changed since the preview (a duplicate deleted, a conflict
/// turned into a duplicate) refuses the apply; the source stays untouched.
#[test]
fn changed_target_refused() {
    let e = gnome();
    e.binary_keyring("Main");
    e.binary_keyring("Other");
    let dup = e.add_item(&e.main, "dup", &[("k", "1")], "same");
    let item = e.add_item(&e.other, "site", &[("k", "1")], "same");
    let (plan_id, conflicts) = e.plan(&[&item], &e.main, TransferMode::Move);
    assert!(conflicts.is_empty());
    block(e.store.delete_item(&dup)).unwrap();
    e.apply(plan_id, vec![], Some(PASSPHRASE));
    assert_eq!(e.expect_error(), MSG_TARGET_CHANGED);
    assert!(e.items(&e.main).is_empty());
    assert_eq!(e.items(&e.other).len(), 1);
    assert_eq!(e.backup_count(), 0);

    let clash = e.add_item(&e.main, "clash", &[("k", "1")], "theirs");
    let (plan_id, conflicts) = e.plan(&[&item], &e.main, TransferMode::Move);
    assert_eq!(conflicts.len(), 1);
    let same = ItemUpdate {
        label: None,
        attributes: None,
        secret: Some(SecretValue::from_text("same")),
    };
    block(e.store.update_item(&clash, same)).unwrap();
    e.apply(plan_id, vec![Choice::UseIncoming], Some(PASSPHRASE));
    assert_eq!(e.expect_error(), MSG_TARGET_CHANGED);
    assert_eq!(e.items(&e.other).len(), 1);
    assert_eq!(e.secret(&item), "same");
    assert_eq!(e.backup_count(), 0);
}

/// Plan 1 and Plan 2 mutations (DeleteItem, RetireFile, DeleteFile,
/// RestoreBackup) also make the pending plan stale.
#[test]
fn stale_plan_after_plan_1_and_2_mutations() {
    let e = gnome();
    e.binary_keyring("Other");
    let item = e.add_item(&e.other, "site", &[("k", "1")], "s1");
    let unrelated = e.add_item(&e.other, "old", &[("k", "9")], "s9");

    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Copy);
    e.send(Command::DeleteItem {
        item: unrelated,
        backup_passphrase: None,
    });
    let backup_dir = match e.next() {
        Event::BackupCreated(info) => info.dir,
        other => panic!("expected BackupCreated, got {other:?}"),
    };
    e.until(|ev| matches!(ev, Event::Done(_)));
    e.apply(plan_id, vec![], None);
    assert_eq!(e.expect_error(), MSG_STALE_PLAN);

    e.fixture_keyring(EMPTY_TEXTUAL, "loose");
    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Copy);
    e.send(Command::RetireFile {
        name: "loose".into(),
        backup_passphrase: SecretValue::from_text(PASSPHRASE),
    });
    e.until(|ev| matches!(ev, Event::Files(_)));
    assert!(!e.keyring("loose").exists());
    e.apply(plan_id, vec![], None);
    assert_eq!(e.expect_error(), MSG_STALE_PLAN);

    e.fixture_keyring(EMPTY_TEXTUAL, "gone");
    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Copy);
    e.send(Command::DeleteFile {
        name: "gone".into(),
        backup: false,
        backup_passphrase: None,
    });
    e.until(|ev| matches!(ev, Event::Files(_)));
    assert!(!e.keyring("gone").exists());
    e.apply(plan_id, vec![], None);
    assert_eq!(e.expect_error(), MSG_STALE_PLAN);

    let (plan_id, _) = e.plan(&[&item], &e.main, TransferMode::Copy);
    e.send(Command::RestoreBackup {
        dir: backup_dir,
        files: vec![e.keyring("Other")],
        passphrase: None,
    });
    e.until(|ev| matches!(ev, Event::Done(_)));
    e.apply(plan_id, vec![], None);
    assert_eq!(e.expect_error(), MSG_STALE_PLAN);
    assert!(e.items(&e.main).is_empty());
}

/// Without conflicts a file import (old and new command) is applied directly.
#[test]
fn file_import_without_conflicts_applies_directly() {
    let e = gnome();
    e.fixture_keyring(TEXTUAL, TEXTUAL);
    e.send(Command::ImportFile {
        name: TEXTUAL.into(),
        password: None,
        target: e.main.clone(),
    });
    match e.next() {
        Event::ImportDone(r) => assert_eq!((r.created, r.duplicates), (2, 0)),
        other => panic!("expected ImportDone, got {other:?}"),
    }
    assert!(matches!(e.next(), Event::Items(id, items) if id == e.main && items.len() == 2));
    assert!(matches!(e.next(), Event::Collections(_)));
    e.send(Command::PlanFileImport {
        name: TEXTUAL.into(),
        password: None,
        target: e.main.clone(),
    });
    match e.next() {
        Event::ImportDone(r) => assert_eq!((r.created, r.duplicates), (0, 2)),
        other => panic!("expected ImportDone, got {other:?}"),
    }
    assert_eq!(e.backup_count(), 0);
}

/// A file import with a conflict is previewed (offline index, revealable)
/// and applied later with the user's choice.
#[test]
fn file_import_with_conflicts_previews() {
    let e = gnome();
    e.fixture_keyring(TEXTUAL, TEXTUAL);
    let existing = e.add_item(
        &e.main,
        "mine",
        &[("user", "alice"), (SCHEMA, GENERIC)],
        "other",
    );
    e.send(Command::PlanFileImport {
        name: TEXTUAL.into(),
        password: None,
        target: e.main.clone(),
    });
    let (plan_id, mode, counts, conflicts) = e.expect_preview();
    assert_eq!(mode, TransferMode::Copy);
    assert_eq!((counts.create, counts.conflict), (1, 1));
    let view = &conflicts[0];
    assert_eq!(view.incoming_item, None);
    assert_eq!(view.offline_index, Some(0));
    assert!(view.incoming_revealable);
    assert_eq!(view.existing_item, Some(existing.clone()));
    assert!(!view.existing_planned);
    assert_eq!(view.default_choice, Choice::KeepTarget);
    assert_eq!(e.items(&e.main).len(), 1);
    e.apply(plan_id, vec![Choice::KeepTarget], None);
    let events = e.until(|ev| matches!(ev, Event::Collections(_)));
    let report = transfer_done(&events);
    assert_eq!((report.created, report.kept_target), (1, 1));
    assert_eq!(e.secret(&existing), "other");
    assert_eq!(e.backup_count(), 0);
}

/// Archive items in a conflict are never revealable in the UI.
#[test]
fn archive_conflicts_not_revealable() {
    let e = gnome();
    e.add_item(&e.main, "mine", &[("user", "alice")], "other");
    let archive = e.dir.path().join("in.age");
    let item = OfflineItem {
        label: "arch".into(),
        attributes: attrs(&[("user", "alice")]),
        secret: SecretValue::from_text("archived"),
        created: 0,
        modified: 0,
        secret_missing: false,
    };
    let exported = ExportedItem {
        collection: "X".into(),
        item,
    };
    write_archive(&archive, &[exported], &SecretValue::from_text(PASSPHRASE)).unwrap();
    e.send(Command::ImportArchive {
        path: archive,
        passphrase: SecretValue::from_text(PASSPHRASE),
        target: e.main.clone(),
    });
    let (_, _, counts, conflicts) = e.expect_preview();
    assert_eq!(counts.conflict, 1);
    assert_eq!(conflicts[0].incoming_item, None);
    assert_eq!(conflicts[0].offline_index, None);
    assert!(!conflicts[0].incoming_revealable);
}

/// The consolidation preview lists steps, deletes and skips; the apply takes
/// one backup, reports progress and leaves only the target.
#[test]
fn consolidation_preview_then_apply_with_progress() {
    let e = gnome();
    e.add_item(&e.main, "a", &[("k", "1")], "x");
    e.add_item(&e.other, "b", &[("k", "2")], "y");
    let empty = e.store.add_collection("Empty", "pw", false);
    let vault = e.store.add_collection("Vault", "pw", true);
    for name in ["Main", "Other", "Empty"] {
        e.binary_keyring(name);
    }
    let (plan_id, summary) = e.plan_consolidation(false);
    assert_eq!(summary.steps.len(), 1);
    assert_eq!(summary.steps[0].label, "Other");
    assert_eq!(summary.steps[0].counts.create, 1);
    assert_eq!(summary.delete_empty, [(empty.clone(), "Empty".to_string())]);
    assert!(
        summary
            .skipped
            .contains(&(vault.clone(), "Vault".to_string(), SkipReason::Locked))
    );
    assert!(
        summary
            .skipped
            .contains(&(e.main.clone(), "Main".to_string(), SkipReason::Target))
    );
    assert_eq!(summary.locked_count, 1);
    assert!(summary.set_default);
    assert!(summary.orphan_files.is_empty());
    assert!(!summary.backup_needs_passphrase, "binary keyrings only");

    e.send(Command::ApplyConsolidation {
        plan_id,
        choices: vec![vec![]],
        backup_passphrase: None,
        orphan_files_passphrase: None,
    });
    let files = match e.next() {
        Event::BackupCreated(info) => info.files,
        other => panic!("expected BackupCreated, got {other:?}"),
    };
    for name in ["Main", "Other", "Empty"] {
        assert!(
            files.iter().any(|f| f.original == e.keyring(name)),
            "{name}"
        );
    }
    let events = e.until(|ev| matches!(ev, Event::ConsolidationDone(_, _)));
    let progress: Vec<(usize, usize)> = events
        .iter()
        .filter_map(|ev| match ev {
            Event::ConsolidationProgress { done, total } => Some((*done, *total)),
            _ => None,
        })
        .collect();
    let total = progress[0].1;
    assert_eq!(progress.first(), Some(&(0, total)));
    assert_eq!(progress.last(), Some(&(total, total)));
    match events.last() {
        Some(Event::ConsolidationDone(report, None)) => assert!(report.completed),
        other => panic!("expected ConsolidationDone, got {other:?}"),
    }
    assert!(!e.has_collection(&e.other) && !e.has_collection(&empty));
    assert!(e.has_collection(&vault));
    assert_eq!(e.items(&e.main).len(), 2);
    assert_eq!(
        block(e.store.read_alias("default")).unwrap(),
        Some(e.main.clone())
    );
    assert_eq!(e.backup_count(), 1);
}

/// A conflict against an item planned by an earlier step has no target id,
/// and planned ids are never revealed.
#[test]
fn planned_conflict_hidden_and_never_revealed() {
    let e = gnome();
    e.add_item(&e.other, "a", &[("k", "1")], "first");
    let third = e.store.add_collection("Third", "pw", false);
    let clash = e.add_item(&third, "a", &[("k", "1")], "second");
    let (_, summary) = e.plan_consolidation(false);
    let step = summary.steps.iter().find(|s| s.label == "Third").unwrap();
    let view = &step.conflicts[0];
    assert_eq!(view.existing_item, None);
    assert!(view.existing_planned);
    assert_eq!(view.incoming_item, Some(clash));
    e.send(Command::RevealSecret(ItemId("planned:0:0".into())));
    assert!(e.expect_error().contains("does not exist yet"));
}

/// Review Focus 2 for consolidation: a missing keyring file or a failing
/// backup aborts with nothing changed.
#[test]
fn consolidation_backup_failure_changes_nothing() {
    let e = gnome();
    e.add_item(&e.other, "b", &[("k", "2")], "y");
    let empty = e.store.add_collection("Empty", "pw", false);
    e.binary_keyring("Main");
    e.binary_keyring("Other");
    let apply = |plan_id| Command::ApplyConsolidation {
        plan_id,
        choices: vec![vec![]],
        backup_passphrase: None,
        orphan_files_passphrase: None,
    };
    let (plan_id, _) = e.plan_consolidation(false);
    e.send(apply(plan_id));
    let m = e.expect_error();
    assert!(m.starts_with("No keyring file found for 'Empty'"), "{m}");

    e.binary_keyring("Empty");
    std::fs::write(&e.backups, b"not a directory").unwrap();
    let (plan_id, _) = e.plan_consolidation(false);
    e.send(apply(plan_id));
    let m = e.expect_error();
    assert!(m.starts_with("Backup failed, nothing was changed"), "{m}");

    assert!(e.has_collection(&e.other) && e.has_collection(&empty));
    assert_eq!(e.items(&e.other).len(), 1);
    assert!(e.items(&e.main).is_empty());
    assert_eq!(block(e.store.read_alias("default")).unwrap(), None);
}

/// Empty plaintext orphan files are retired in one batch after a completed
/// consolidation; both passphrases are asked for first with the plan kept.
#[test]
fn orphan_batch_runs_after_consolidation() {
    let e = gnome();
    e.add_item(&e.other, "b", &[("k", "2")], "y");
    e.binary_keyring("Main");
    e.binary_keyring("Other");
    e.fixture_keyring(EMPTY_TEXTUAL, "orphan");
    e.fixture_keyring(TEXTUAL, "full");
    let (plan_id, summary) = e.plan_consolidation(true);
    assert_eq!(summary.orphan_files, ["orphan"]);
    assert!(
        summary.backup_needs_passphrase,
        "plaintext files in the set"
    );
    let apply = |backup: Option<&str>, orphan: Option<&str>| Command::ApplyConsolidation {
        plan_id,
        choices: vec![vec![]],
        backup_passphrase: backup.map(SecretValue::from_text),
        orphan_files_passphrase: orphan.map(SecretValue::from_text),
    };
    let asked = |e: &Env| match e.next() {
        Event::ApplyPassphrasesNeeded {
            plan_id: p,
            backup,
            orphan_files,
        } => {
            assert_eq!(p, plan_id);
            (backup, orphan_files)
        }
        other => panic!("expected ApplyPassphrasesNeeded, got {other:?}"),
    };
    e.send(apply(None, None));
    assert_eq!(asked(&e), (true, true));
    e.send(apply(Some(PASSPHRASE), None));
    assert_eq!(asked(&e), (false, true));
    e.send(apply(None, Some(PASSPHRASE)));
    assert_eq!(asked(&e), (true, false));
    assert!(e.has_collection(&e.other));
    assert_eq!(e.backup_count(), 0);

    e.send(apply(Some(PASSPHRASE), Some(PASSPHRASE)));
    let events = e.until(|ev| matches!(ev, Event::ConsolidationDone(_, _)));
    let backups = events
        .iter()
        .filter(|ev| matches!(ev, Event::BackupCreated(_)))
        .count();
    assert_eq!(backups, 2);
    match events.last() {
        Some(Event::ConsolidationDone(report, Some(retired))) => {
            assert!(report.completed);
            assert_eq!(retired.removed, ["orphan"]);
            assert!(retired.backup.is_some());
        }
        other => panic!("expected ConsolidationDone with a retire report, got {other:?}"),
    }
    assert!(!e.keyring("orphan").exists());
    assert!(e.keyring("full").exists());
    assert!(!e.has_collection(&e.other));
    assert_eq!(e.backup_count(), 2);
}

/// A consolidation that stops (an empty collection got an item after the
/// preview) reports `completed == false` and retires no orphan file.
#[test]
fn failed_consolidation_keeps_orphan_files() {
    let e = gnome();
    e.add_item(&e.other, "b", &[("k", "2")], "y");
    let empty = e.store.add_collection("Empty", "pw", false);
    for name in ["Main", "Other", "Empty"] {
        e.binary_keyring(name);
    }
    e.fixture_keyring(EMPTY_TEXTUAL, "orphan");
    let (plan_id, summary) = e.plan_consolidation(true);
    assert_eq!(summary.orphan_files, ["orphan"]);
    assert!(
        summary.backup_needs_passphrase,
        "plaintext files in the set"
    );
    e.add_item(&empty, "late", &[("k", "3")], "z");
    e.send(Command::ApplyConsolidation {
        plan_id,
        choices: vec![vec![]],
        backup_passphrase: Some(SecretValue::from_text(PASSPHRASE)),
        orphan_files_passphrase: Some(SecretValue::from_text(PASSPHRASE)),
    });
    let events = e.until(|ev| matches!(ev, Event::ConsolidationDone(_, _)));
    match events.last() {
        Some(Event::ConsolidationDone(report, None)) => assert!(!report.completed),
        other => panic!("expected ConsolidationDone without retire, got {other:?}"),
    }
    assert!(e.keyring("orphan").exists());
    assert!(e.has_collection(&empty));
    assert_eq!(e.backup_count(), 1);
}

/// Review Focus 5 (compile time): the apply commands carry only a plan id,
/// choices and passphrases; an extra field breaks these exhaustive patterns.
#[test]
fn apply_commands_carry_no_secrets() {
    let transfer = Command::ApplyTransfer {
        plan_id: 1,
        choices: vec![Choice::KeepTarget],
        backup_passphrase: None,
    };
    let Command::ApplyTransfer {
        plan_id,
        choices,
        backup_passphrase,
    } = transfer
    else {
        panic!("not ApplyTransfer");
    };
    let _: (u64, Vec<Choice>, Option<SecretValue>) = (plan_id, choices, backup_passphrase);
    let consolidation = Command::ApplyConsolidation {
        plan_id: 2,
        choices: vec![vec![Choice::UseIncoming]],
        backup_passphrase: None,
        orphan_files_passphrase: None,
    };
    let Command::ApplyConsolidation {
        plan_id,
        choices,
        backup_passphrase,
        orphan_files_passphrase,
    } = consolidation
    else {
        panic!("not ApplyConsolidation");
    };
    let _: (
        u64,
        Vec<Vec<Choice>>,
        Option<SecretValue>,
        Option<SecretValue>,
    ) = (plan_id, choices, backup_passphrase, orphan_files_passphrase);
}
