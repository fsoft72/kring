//! Progress of the destructive operation in flight, shown by a modal.
//!
//! Correlation: the worker handles one command at a time, in order, and
//! ends each one with [`Event::CommandFinished`] carrying its number (the
//! UI numbers its sent commands the same way). An operation only looks at
//! the events of its own command (those arriving while its number is the
//! running one) and decides on its `CommandFinished`: a `Done` (or
//! `TransferDone`) means success, errors after it (e.g. the refresh that
//! follows a delete) become warning lines; otherwise an error means
//! failure; otherwise a passphrase request means waiting for the resend,
//! which is a new command with a new number. While the modal is open every
//! destructive action is disabled, so no second one can be queued.

use kring_core::model::CollectionId;
use kring_core::transfer::plan::Choice;

use crate::app_state::{AppState, transfer_summary};
use crate::views::collection::shown_name;
use crate::views::transfer::apply_is_destructive;
use crate::worker::{Command, Event};

/// Title of the modal while the operation runs.
pub const TITLE_RUNNING: &str = "Working...";
/// Title of the modal once it finished.
pub const TITLE_FINISHED: &str = "Finished";
/// Title of the modal once it finished with warnings.
pub const TITLE_WARNINGS: &str = "Finished with warnings";
/// Title of the modal after a failure.
pub const TITLE_FAILED: &str = "Failed";
/// Failure text when the worker thread is gone.
pub const MSG_WORKER_STOPPED: &str = "Background worker stopped";
/// Text of the backup step while it runs.
const MSG_BACKUP_RUNNING: &str = "Creating backup...";
/// Text of a backup step ended without a backup (none was needed).
const MSG_BACKUP_NOT_NEEDED: &str = "No backup was needed";
/// Text of a backup step ended by an error before any backup.
const MSG_BACKUP_NOT_CREATED: &str = "No backup was created";
/// Text of a command that ended without a result or an error.
const MSG_NO_REPORT: &str = "Finished without a report";

/// State of one step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepStatus {
    /// In progress (spinner).
    Running,
    /// Finished well (OK colour).
    Ok,
    /// Failed (ERROR colour).
    Failed,
    /// Did not happen (muted).
    Skipped,
    /// A problem after the operation succeeded (muted text, TERTIARY dot).
    Warning,
}

/// One line of the modal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// Text shown.
    pub text: String,
    /// State shown by its marker and colour.
    pub status: StepStatus,
}

impl Step {
    /// A step with text and status.
    fn new(text: impl Into<String>, status: StepStatus) -> Self {
        Self {
            text: text.into(),
            status,
        }
    }

    /// Sets text and status.
    fn set(&mut self, text: impl Into<String>, status: StepStatus) {
        self.text = text.into();
        self.status = status;
    }
}

/// What the events of the current command reported so far.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Window {
    /// Text of the first success event.
    done: Option<String>,
    /// Error messages, in order.
    errors: Vec<String>,
    /// A passphrase was asked for.
    asked: bool,
}

/// A destructive operation and its steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    /// Backup step, `None` when the command takes no backup.
    backup: Option<Step>,
    /// The operation itself.
    action: Step,
    /// Warning lines after the action.
    warnings: Vec<Step>,
    /// Number of the command whose events are followed; `None` while waiting.
    id: Option<u64>,
    /// Events of that command so far.
    window: Window,
}

impl Operation {
    /// Starts an operation for command number `id`: `running` is the action
    /// step text (e.g. `Deleting "Work"...`); `backup` adds the backup step.
    pub fn start(running: impl Into<String>, backup: bool, id: u64) -> Self {
        Self {
            backup: backup.then(|| Step::new(MSG_BACKUP_RUNNING, StepStatus::Running)),
            action: Step::new(running, StepStatus::Running),
            warnings: Vec::new(),
            id: Some(id),
            window: Window::default(),
        }
    }

    /// Returns the steps in display order.
    pub fn steps(&self) -> Vec<&Step> {
        self.backup
            .iter()
            .chain([&self.action])
            .chain(&self.warnings)
            .collect()
    }

    /// Returns true once the worker answered (done or failed).
    pub fn is_finished(&self) -> bool {
        self.action.status != StepStatus::Running
    }

    /// Returns true when the operation failed.
    pub fn is_failed(&self) -> bool {
        self.action.status == StepStatus::Failed
    }

    /// Returns true while the worker waits for a passphrase (the modal
    /// steps aside until the command is resent or the request cancelled).
    pub fn is_waiting(&self) -> bool {
        !self.is_finished() && self.id.is_none()
    }

    /// Returns the modal title.
    pub fn title(&self) -> &'static str {
        match self.action.status {
            StepStatus::Running => TITLE_RUNNING,
            StepStatus::Failed => TITLE_FAILED,
            _ if !self.warnings.is_empty() => TITLE_WARNINGS,
            _ => TITLE_FINISHED,
        }
    }

    /// The command was resent with its passphrase as command number `id`:
    /// its events are followed and the modal shows again.
    pub fn resume(&mut self, id: u64) {
        self.id = Some(id);
        self.window = Window::default();
    }

    /// Ends a running operation as failed with `message` (e.g. the worker stopped).
    pub fn fail(&mut self, message: &str) {
        if self.is_finished() {
            return;
        }
        self._finish(message, StepStatus::Failed);
    }

    /// Ends the action step; a backup step still running did not happen.
    fn _finish(&mut self, text: &str, status: StepStatus) {
        self.action.set(text, status);
        self.id = None;
        let Some(backup) = &mut self.backup else {
            return;
        };
        if backup.status != StepStatus::Running {
            return;
        }
        let why = match status {
            StepStatus::Failed => MSG_BACKUP_NOT_CREATED,
            _ => MSG_BACKUP_NOT_NEEDED,
        };
        backup.set(why, StepStatus::Skipped);
    }

    /// Decides the outcome of the followed command once it finished.
    fn _decide(&mut self) {
        let window = std::mem::take(&mut self.window);
        let mut errors = window.errors.into_iter();
        if let Some(done) = window.done {
            self._finish(&done, StepStatus::Ok);
        } else if let Some(first) = errors.next() {
            self._finish(&first, StepStatus::Failed);
        } else if window.asked {
            self.id = None;
            return;
        } else {
            self._finish(MSG_NO_REPORT, StepStatus::Skipped);
        }
        self.warnings = errors.map(|e| Step::new(e, StepStatus::Warning)).collect();
    }

    /// Updates the steps from a worker event while command number
    /// `running` is handled; only the followed command counts, and nothing
    /// changes once finished.
    pub fn observe(&mut self, event: &Event, running: u64) {
        if self.is_finished() {
            return;
        }
        if let Event::CommandFinished(id) = event {
            if self.id == Some(*id) {
                self._decide();
            }
            return;
        }
        if self.id != Some(running) {
            return;
        }
        match event {
            Event::BackupCreated(info) => {
                let text = format!("Backup created in {}", info.dir.display());
                match &mut self.backup {
                    Some(step) => step.set(text, StepStatus::Ok),
                    None => self.backup = Some(Step::new(text, StepStatus::Ok)),
                }
            }
            Event::PassphraseNeeded(_) | Event::ApplyPassphrasesNeeded { .. } => {
                self.window.asked = true;
            }
            Event::Done(msg) => {
                self.window.done.get_or_insert_with(|| msg.clone());
            }
            Event::TransferDone(report) => {
                self.window
                    .done
                    .get_or_insert_with(|| transfer_summary(report));
            }
            Event::Error(msg) => self.window.errors.push(msg.clone()),
            _ => {}
        }
    }
}

/// Returns the shown name of collection `id` (its path when unknown).
fn _collection_name(state: &AppState, id: &CollectionId) -> String {
    state
        .collections
        .iter()
        .find(|c| &c.id == id)
        .map_or_else(|| id.0.clone(), |c| shown_name(&state.collections, c))
}

/// Returns true when the apply of the open transfer preview changes data.
fn _transfer_destructive(state: &AppState, plan_id: u64, choices: &[Choice]) -> bool {
    state
        .transfer_preview
        .as_ref()
        .is_some_and(|p| p.plan_id == plan_id && apply_is_destructive(p.mode, choices))
}

/// Builds the operation of destructive command number `id`, `None` for any other.
pub fn describe(cmd: &Command, state: &AppState, id: u64) -> Option<Operation> {
    let op = match cmd {
        Command::DeleteItem { item, .. } => {
            let label = state
                .items
                .iter()
                .find(|i| &i.id == item)
                .map_or_else(|| item.0.clone(), |i| i.label.clone());
            Operation::start(format!("Deleting \"{label}\"..."), true, id)
        }
        Command::DeleteCollection { collection, .. } => {
            let name = _collection_name(state, collection);
            Operation::start(format!("Deleting \"{name}\"..."), true, id)
        }
        Command::DeleteFile { name, backup, .. } => {
            Operation::start(format!("Deleting {name}.keyring..."), *backup, id)
        }
        Command::RetireFile { name, .. } => {
            Operation::start(format!("Retiring {name}.keyring..."), true, id)
        }
        Command::RestoreBackup { dir, files, .. } => {
            let from = dir.file_name().map_or_else(
                || dir.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            let what = crate::app_state::count_noun(files.len(), "file");
            Operation::start(format!("Restoring {what} from {from}..."), true, id)
        }
        Command::ApplyTransfer {
            plan_id, choices, ..
        } if _transfer_destructive(state, *plan_id, choices) => {
            let target = state
                .transfer_preview
                .as_ref()
                .map(|p| _collection_name(state, &p.target))
                .unwrap_or_default();
            Operation::start(
                format!("Applying the transfer to \"{target}\"..."),
                true,
                id,
            )
        }
        Command::DeleteSshKey { name, .. } => {
            Operation::start(format!("Deleting SSH key \"{name}\"..."), true, id)
        }
        Command::ChangeSshPassphrase { name, new, .. } => {
            let verb = match new {
                Some(_) => "Changing",
                None => "Removing",
            };
            Operation::start(format!("{verb} the passphrase of \"{name}\"..."), true, id)
        }
        _ => return None,
    };
    Some(op)
}

/// Records a sent command in `current`: a destructive command resumes the
/// operation waiting for its passphrase (following the new command number),
/// or starts a new one.
pub fn track(current: &mut Option<Operation>, started: Option<Operation>) {
    let Some(started) = started else {
        return;
    };
    let resumed = started.id.unwrap_or_default();
    if let Some(op) = current.as_mut().filter(|op| op.is_waiting()) {
        op.resume(resumed);
        return;
    }
    *current = Some(started);
}

#[cfg(test)]
mod tests {
    use super::*;
    use kring_core::backup::BackupInfo;
    use kring_core::model::{CollectionInfo, ItemId, ItemInfo};
    use kring_core::transfer::apply::TransferMode;
    use std::path::PathBuf;

    /// A backup event for directory `dir`.
    fn backup_created(dir: &str) -> Event {
        Event::BackupCreated(BackupInfo {
            dir: PathBuf::from(dir),
            reason: "delete-item".into(),
            created: String::new(),
            files: vec![],
            seq: 0,
            pruned: vec![],
            prune_warning: None,
        })
    }

    /// Statuses of the steps in order.
    fn statuses(op: &Operation) -> Vec<StepStatus> {
        op.steps().iter().map(|s| s.status).collect()
    }

    /// Feeds `events` handled as command `running`.
    fn feed(op: &mut Operation, running: u64, events: &[Event]) {
        for e in events {
            op.observe(e, running);
        }
    }

    /// Backup then done: both steps OK once the command finished.
    #[test]
    fn backup_then_done() {
        let mut op = Operation::start("Deleting \"a\"...", true, 4);
        assert_eq!(op.title(), TITLE_RUNNING);
        assert_eq!(statuses(&op), [StepStatus::Running, StepStatus::Running]);
        op.observe(&backup_created("/b/20261115-delete-item"), 4);
        assert_eq!(statuses(&op), [StepStatus::Ok, StepStatus::Running]);
        feed(
            &mut op,
            4,
            &[
                Event::Collections(vec![]),
                Event::Done("Item deleted, backup in /b/x".into()),
            ],
        );
        assert!(!op.is_finished(), "decided on CommandFinished");
        op.observe(&Event::CommandFinished(4), 4);
        assert!(op.is_finished() && !op.is_failed());
        assert_eq!(op.title(), TITLE_FINISHED);
        let steps = op.steps();
        assert_eq!(steps[0].text, "Backup created in /b/20261115-delete-item");
        assert_eq!(steps[1].text, "Item deleted, backup in /b/x");
    }

    /// Without a backup only the action step is shown.
    #[test]
    fn no_backup_then_done() {
        let mut op = Operation::start("Deleting x.keyring...", false, 0);
        assert_eq!(op.steps().len(), 1);
        feed(
            &mut op,
            0,
            &[
                Event::Done("File x deleted".into()),
                Event::CommandFinished(0),
            ],
        );
        assert_eq!(statuses(&op), [StepStatus::Ok]);
    }

    /// A backup expected but not taken (nothing to back up) is skipped.
    #[test]
    fn expected_backup_not_needed() {
        let mut op = Operation::start("Deleting \"s\"...", true, 1);
        feed(
            &mut op,
            1,
            &[
                Event::Done("Item deleted".into()),
                Event::CommandFinished(1),
            ],
        );
        assert_eq!(statuses(&op), [StepStatus::Skipped, StepStatus::Ok]);
        assert_eq!(op.steps()[0].text, MSG_BACKUP_NOT_NEEDED);
    }

    /// An error before the backup fails the action; no backup was created.
    #[test]
    fn error_before_backup() {
        let mut op = Operation::start("Retiring p.keyring...", true, 2);
        feed(
            &mut op,
            2,
            &[
                Event::Error("Backup failed, nothing was deleted".into()),
                Event::CommandFinished(2),
            ],
        );
        assert!(op.is_failed());
        assert_eq!(op.title(), TITLE_FAILED);
        assert_eq!(statuses(&op), [StepStatus::Skipped, StepStatus::Failed]);
        assert_eq!(op.steps()[0].text, MSG_BACKUP_NOT_CREATED);
        assert_eq!(op.steps()[1].text, "Backup failed, nothing was deleted");
    }

    /// An error after the backup keeps the backup OK; later events change nothing.
    #[test]
    fn error_after_backup() {
        let mut op = Operation::start("Deleting \"a\"...", true, 0);
        feed(
            &mut op,
            0,
            &[
                backup_created("/b/1"),
                Event::Error("not found: /c/a".into()),
                Event::CommandFinished(0),
            ],
        );
        assert_eq!(statuses(&op), [StepStatus::Ok, StepStatus::Failed]);
        feed(
            &mut op,
            1,
            &[Event::Done("late".into()), Event::CommandFinished(1)],
        );
        assert_eq!(op.steps()[1].text, "not found: /c/a");
    }

    /// (a) A refresh error after a successful delete is a warning, not a failure.
    #[test]
    fn refresh_error_after_done_is_warning() {
        let mut op = Operation::start("Deleting \"a\"...", true, 5);
        feed(
            &mut op,
            5,
            &[
                backup_created("/b/1"),
                Event::Done("Item deleted, backup in /b/1".into()),
                Event::Error("Cannot list collections".into()),
                Event::CommandFinished(5),
            ],
        );
        assert!(!op.is_failed());
        assert_eq!(op.title(), TITLE_WARNINGS);
        assert_eq!(
            statuses(&op),
            [StepStatus::Ok, StepStatus::Ok, StepStatus::Warning]
        );
        assert_eq!(op.steps()[2].text, "Cannot list collections");
    }

    /// (b) A stray Done or Error of an earlier command is not attributed.
    #[test]
    fn stray_events_of_earlier_command_ignored() {
        let mut op = Operation::start("Deleting \"a\"...", true, 3);
        feed(
            &mut op,
            2,
            &[
                Event::Done("Collection locked".into()),
                Event::Error("earlier failure".into()),
                Event::CommandFinished(2),
            ],
        );
        assert!(!op.is_finished());
        assert_eq!(statuses(&op), [StepStatus::Running, StepStatus::Running]);
        feed(
            &mut op,
            3,
            &[
                Event::Done("Item deleted".into()),
                Event::CommandFinished(3),
            ],
        );
        assert_eq!(op.steps()[1].text, "Item deleted");
    }

    /// A command ending with neither result nor error is reported as such.
    #[test]
    fn no_report() {
        let mut op = Operation::start("Deleting x.keyring...", false, 0);
        feed(
            &mut op,
            0,
            &[Event::Files(vec![]), Event::CommandFinished(0)],
        );
        assert!(op.is_finished() && !op.is_failed());
        assert_eq!(op.steps()[0].text, MSG_NO_REPORT);
    }

    /// A passphrase request makes the modal step aside; the resend (a new
    /// command number) resumes the same operation, which then finishes.
    #[test]
    fn passphrase_interruption() {
        let mut current = Some(Operation::start("Deleting \"a\"...", true, 0));
        let echo = Command::DeleteItem {
            item: ItemId("/c/a/1".into()),
            backup_passphrase: None,
        };
        let op = current.as_mut().unwrap();
        feed(
            op,
            0,
            &[
                Event::PassphraseNeeded(Box::new(echo)),
                Event::CommandFinished(0),
            ],
        );
        assert!(op.is_waiting() && !op.is_finished());
        track(&mut current, Some(Operation::start("other", false, 1)));
        let op = current.as_mut().unwrap();
        assert!(!op.is_waiting());
        assert_eq!(op.steps().len(), 2, "same operation resumed");
        feed(
            op,
            1,
            &[
                backup_created("/b/2"),
                Event::Done("Item deleted".into()),
                Event::CommandFinished(1),
            ],
        );
        assert_eq!(statuses(op), [StepStatus::Ok, StepStatus::Ok]);
    }

    /// A stopped worker fails a running operation; a finished one stays.
    #[test]
    fn worker_stopped_fails() {
        let mut op = Operation::start("Deleting \"a\"...", true, 0);
        op.fail(MSG_WORKER_STOPPED);
        assert!(op.is_failed());
        assert_eq!(op.steps()[1].text, MSG_WORKER_STOPPED);
        let mut done = Operation::start("x", false, 0);
        feed(
            &mut done,
            0,
            &[Event::Done("ok".into()), Event::CommandFinished(0)],
        );
        done.fail(MSG_WORKER_STOPPED);
        assert!(!done.is_failed());
    }

    /// A destructive command after a finished operation starts a new one;
    /// a non-destructive one changes nothing.
    #[test]
    fn track_replaces_finished() {
        let mut first = Operation::start("a", false, 0);
        feed(
            &mut first,
            0,
            &[Event::Done("ok".into()), Event::CommandFinished(0)],
        );
        let mut current = Some(first);
        track(&mut current, None);
        assert!(current.as_ref().unwrap().is_finished());
        track(&mut current, Some(Operation::start("b", true, 1)));
        assert!(!current.as_ref().unwrap().is_finished());
        assert_eq!(current.unwrap().steps().len(), 2);
    }

    /// Destructive commands are described with their names; others are not.
    #[test]
    fn describe_destructive_commands() {
        let mut state = AppState::default();
        state.apply(Event::Collections(vec![CollectionInfo {
            id: CollectionId("/c/work".into()),
            label: "Work".into(),
            locked: false,
            item_count: 1,
            aliases: vec![],
            is_login: false,
            created: 0,
            modified: 0,
        }]));
        state.select_collection(CollectionId("/c/work".into()));
        state.apply(Event::Items(
            CollectionId("/c/work".into()),
            vec![ItemInfo {
                id: ItemId("/c/work/1".into()),
                collection: CollectionId("/c/work".into()),
                label: "GitHub".into(),
                attributes: Default::default(),
                locked: false,
                created: 0,
                modified: 0,
            }],
        ));
        let text_in = |state: &AppState, cmd: Command| {
            describe(&cmd, state, 3)
                .map(|op| (op.steps().len(), op.steps().last().unwrap().text.clone()))
        };
        let text = |cmd: Command| text_in(&state, cmd);
        assert_eq!(
            text(Command::DeleteItem {
                item: ItemId("/c/work/1".into()),
                backup_passphrase: None,
            }),
            Some((2, "Deleting \"GitHub\"...".into()))
        );
        assert_eq!(
            text(Command::DeleteCollection {
                collection: CollectionId("/c/work".into()),
                backup_passphrase: None,
            }),
            Some((2, "Deleting \"Work\"...".into()))
        );
        assert_eq!(
            text(Command::DeleteFile {
                name: "old".into(),
                backup: false,
                backup_passphrase: None,
            }),
            Some((1, "Deleting old.keyring...".into()))
        );
        assert_eq!(
            text(Command::RestoreBackup {
                dir: PathBuf::from("/b/20261115-120000-manual"),
                files: vec![PathBuf::from("/k/a.keyring")],
                passphrase: None,
            }),
            Some((2, "Restoring 1 file from 20261115-120000-manual...".into()))
        );
        assert!(text(Command::Refresh).is_none());
        assert!(text(Command::Lock(CollectionId("/c/work".into()))).is_none());
        // No open preview: an apply is not tracked.
        let apply = Command::ApplyTransfer {
            plan_id: 1,
            choices: vec![],
            backup_passphrase: None,
        };
        assert!(text(apply.clone()).is_none());
        state.apply(Event::TransferPreview {
            plan_id: 1,
            target: CollectionId("/c/work".into()),
            mode: TransferMode::Move,
            counts: Default::default(),
            conflicts: vec![],
        });
        assert_eq!(
            text_in(&state, apply),
            Some((2, "Applying the transfer to \"Work\"...".into()))
        );
    }

    /// Deleting an SSH key and changing its passphrase show the progress
    /// modal with a backup step; agent and export commands do not.
    #[test]
    fn ssh_operations() {
        let state = AppState::default();
        let delete = Command::DeleteSshKey {
            name: "id_rsa".into(),
            backup_passphrase: None,
        };
        let op = describe(&delete, &state, 3).expect("delete is destructive");
        assert_eq!(op.steps().len(), 2, "backup and action");
        assert_eq!(op.steps()[1].text, "Deleting SSH key \"id_rsa\"...");
        let change = |new: bool| Command::ChangeSshPassphrase {
            name: "k".into(),
            old: None,
            new: new.then(|| kring_core::model::SecretValue::from_text("n")),
            allow_unencrypted: !new,
            backup_passphrase: None,
        };
        let op = describe(&change(true), &state, 4).expect("change is destructive");
        assert_eq!(op.steps()[1].text, "Changing the passphrase of \"k\"...");
        let op = describe(&change(false), &state, 5).expect("removal is destructive");
        assert_eq!(op.steps()[1].text, "Removing the passphrase of \"k\"...");
        let agent = Command::AgentRemove {
            fingerprint: "SHA256:x".into(),
        };
        assert!(describe(&agent, &state, 6).is_none());
        assert!(describe(&Command::AgentRemoveAll, &state, 7).is_none());
    }
}
