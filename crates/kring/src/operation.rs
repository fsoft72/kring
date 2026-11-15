//! Progress of the destructive operation in flight, shown by a modal.
//!
//! Correlation assumption: the worker handles one command at a time, in
//! order, so the first [`Event::Done`] (or [`Event::TransferDone`]) or
//! [`Event::Error`] after a destructive command is its answer. While the
//! modal is open every destructive action is disabled, so no second one
//! can be queued. Residual risk: a non-destructive command sent just before
//! (e.g. a refresh) that fails would end the step with its error, and an
//! error of the refresh that follows a successful delete ends it as failed
//! (the worker reports the delete before that refresh only by its `Done`).

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
/// Title of the modal after a failure.
pub const TITLE_FAILED: &str = "Failed";
/// Text of the backup step while it runs.
const MSG_BACKUP_RUNNING: &str = "Creating backup...";
/// Text of a backup step ended without a backup (none was needed).
const MSG_BACKUP_NOT_NEEDED: &str = "No backup was needed";
/// Text of a backup step ended by an error before any backup.
const MSG_BACKUP_NOT_CREATED: &str = "No backup was created";

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
    /// A running step.
    fn running(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            status: StepStatus::Running,
        }
    }

    /// Sets text and status.
    fn set(&mut self, text: impl Into<String>, status: StepStatus) {
        self.text = text.into();
        self.status = status;
    }
}

/// A destructive operation and its steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    /// Backup step, `None` when the command takes no backup.
    backup: Option<Step>,
    /// The operation itself.
    action: Step,
    /// The worker asked for a passphrase: the modal steps aside until the
    /// command is resent (or the request is cancelled).
    waiting: bool,
}

impl Operation {
    /// Starts an operation: `running` is the action step text (e.g.
    /// `Deleting "Work"...`); `backup` adds the backup step.
    pub fn start(running: impl Into<String>, backup: bool) -> Self {
        Self {
            backup: backup.then(|| Step::running(MSG_BACKUP_RUNNING)),
            action: Step::running(running),
            waiting: false,
        }
    }

    /// Returns the steps in display order.
    pub fn steps(&self) -> Vec<&Step> {
        self.backup.iter().chain([&self.action]).collect()
    }

    /// Returns true once the worker answered (done or failed).
    pub fn is_finished(&self) -> bool {
        self.action.status != StepStatus::Running
    }

    /// Returns true when the operation failed.
    pub fn is_failed(&self) -> bool {
        self.action.status == StepStatus::Failed
    }

    /// Returns true while the worker waits for a passphrase.
    pub fn is_waiting(&self) -> bool {
        self.waiting
    }

    /// Returns the modal title.
    pub fn title(&self) -> &'static str {
        match self.action.status {
            StepStatus::Running => TITLE_RUNNING,
            StepStatus::Failed => TITLE_FAILED,
            StepStatus::Ok | StepStatus::Skipped => TITLE_FINISHED,
        }
    }

    /// The command was resent with its passphrase: the modal shows again.
    pub fn resume(&mut self) {
        self.waiting = false;
    }

    /// Ends the action step; a backup step still running did not happen.
    fn _finish(&mut self, text: &str, status: StepStatus) {
        self.action.set(text, status);
        self.waiting = false;
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

    /// Updates the steps from a worker event; ignored once finished.
    pub fn observe(&mut self, event: &Event) {
        if self.is_finished() {
            return;
        }
        match event {
            Event::BackupCreated(info) => {
                let text = format!("Backup created in {}", info.dir.display());
                match &mut self.backup {
                    Some(step) => step.set(text, StepStatus::Ok),
                    None => {
                        self.backup = Some(Step {
                            text,
                            status: StepStatus::Ok,
                        })
                    }
                }
            }
            Event::PassphraseNeeded(_) | Event::ApplyPassphrasesNeeded { .. } => {
                self.waiting = true;
            }
            Event::Done(msg) => self._finish(msg, StepStatus::Ok),
            Event::TransferDone(report) => self._finish(&transfer_summary(report), StepStatus::Ok),
            Event::Error(msg) => self._finish(msg, StepStatus::Failed),
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

/// Builds the operation of a destructive command, `None` for any other.
pub fn describe(cmd: &Command, state: &AppState) -> Option<Operation> {
    let op = match cmd {
        Command::DeleteItem { item, .. } => {
            let label = state
                .items
                .iter()
                .find(|i| &i.id == item)
                .map_or_else(|| item.0.clone(), |i| i.label.clone());
            Operation::start(format!("Deleting \"{label}\"..."), true)
        }
        Command::DeleteCollection { collection, .. } => {
            let name = _collection_name(state, collection);
            Operation::start(format!("Deleting \"{name}\"..."), true)
        }
        Command::DeleteFile { name, backup, .. } => {
            Operation::start(format!("Deleting {name}.keyring..."), *backup)
        }
        Command::RetireFile { name, .. } => {
            Operation::start(format!("Retiring {name}.keyring..."), true)
        }
        Command::RestoreBackup { dir, files, .. } => {
            let from = dir.file_name().map_or_else(
                || dir.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            let what = crate::app_state::count_noun(files.len(), "file");
            Operation::start(format!("Restoring {what} from {from}..."), true)
        }
        Command::ApplyTransfer {
            plan_id, choices, ..
        } if _transfer_destructive(state, *plan_id, choices) => {
            let target = state
                .transfer_preview
                .as_ref()
                .map(|p| _collection_name(state, &p.target))
                .unwrap_or_default();
            Operation::start(format!("Applying the transfer to \"{target}\"..."), true)
        }
        _ => return None,
    };
    Some(op)
}

/// Records a sent command in `current`: a destructive command resumes the
/// operation waiting for its passphrase, or starts a new one.
pub fn track(current: &mut Option<Operation>, started: Option<Operation>) {
    let Some(started) = started else {
        return;
    };
    if let Some(op) = current
        .as_mut()
        .filter(|op| op.is_waiting() && !op.is_finished())
    {
        op.resume();
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

    /// Backup then done: both steps OK, the backup names its directory.
    #[test]
    fn backup_then_done() {
        let mut op = Operation::start("Deleting \"a\"...", true);
        assert_eq!(op.title(), TITLE_RUNNING);
        assert_eq!(statuses(&op), [StepStatus::Running, StepStatus::Running]);
        op.observe(&backup_created("/b/20261115-delete-item"));
        assert_eq!(statuses(&op), [StepStatus::Ok, StepStatus::Running]);
        assert!(!op.is_finished());
        op.observe(&Event::Collections(vec![]));
        op.observe(&Event::Done("Item deleted, backup in /b/x".into()));
        assert!(op.is_finished() && !op.is_failed());
        assert_eq!(op.title(), TITLE_FINISHED);
        let steps = op.steps();
        assert_eq!(steps[0].text, "Backup created in /b/20261115-delete-item");
        assert_eq!(steps[1].text, "Item deleted, backup in /b/x");
    }

    /// Without a backup only the action step is shown.
    #[test]
    fn no_backup_then_done() {
        let mut op = Operation::start("Deleting x.keyring...", false);
        assert_eq!(op.steps().len(), 1);
        op.observe(&Event::Done("File x deleted".into()));
        assert_eq!(statuses(&op), [StepStatus::Ok]);
    }

    /// A backup expected but not taken (nothing to back up) is skipped.
    #[test]
    fn expected_backup_not_needed() {
        let mut op = Operation::start("Deleting \"s\"...", true);
        op.observe(&Event::Done("Item deleted".into()));
        assert_eq!(statuses(&op), [StepStatus::Skipped, StepStatus::Ok]);
        assert_eq!(op.steps()[0].text, MSG_BACKUP_NOT_NEEDED);
    }

    /// An error before the backup fails the action; no backup was created.
    #[test]
    fn error_before_backup() {
        let mut op = Operation::start("Retiring p.keyring...", true);
        op.observe(&Event::Error("Backup failed, nothing was deleted".into()));
        assert!(op.is_failed());
        assert_eq!(op.title(), TITLE_FAILED);
        assert_eq!(statuses(&op), [StepStatus::Skipped, StepStatus::Failed]);
        assert_eq!(op.steps()[0].text, MSG_BACKUP_NOT_CREATED);
        assert_eq!(op.steps()[1].text, "Backup failed, nothing was deleted");
    }

    /// An error after the backup keeps the backup OK.
    #[test]
    fn error_after_backup() {
        let mut op = Operation::start("Deleting \"a\"...", true);
        op.observe(&backup_created("/b/1"));
        op.observe(&Event::Error("not found: /c/a".into()));
        assert_eq!(statuses(&op), [StepStatus::Ok, StepStatus::Failed]);
        // Later events no longer change it.
        op.observe(&Event::Done("late".into()));
        assert_eq!(op.steps()[1].text, "not found: /c/a");
    }

    /// A passphrase request makes the modal step aside; the resend resumes
    /// the same operation, which then finishes.
    #[test]
    fn passphrase_interruption() {
        let mut current = Some(Operation::start("Deleting \"a\"...", true));
        let echo = Command::DeleteItem {
            item: ItemId("/c/a/1".into()),
            backup_passphrase: None,
        };
        current
            .as_mut()
            .unwrap()
            .observe(&Event::PassphraseNeeded(Box::new(echo)));
        assert!(current.as_ref().unwrap().is_waiting());
        track(&mut current, Some(Operation::start("other", false)));
        let op = current.as_mut().unwrap();
        assert!(!op.is_waiting());
        assert_eq!(op.steps().len(), 2, "same operation resumed");
        op.observe(&backup_created("/b/2"));
        op.observe(&Event::Done("Item deleted".into()));
        assert_eq!(statuses(op), [StepStatus::Ok, StepStatus::Ok]);
    }

    /// A destructive command after a finished operation starts a new one;
    /// a non-destructive one changes nothing.
    #[test]
    fn track_replaces_finished() {
        let mut first = Operation::start("a", false);
        first.observe(&Event::Done("ok".into()));
        let mut current = Some(first);
        track(&mut current, None);
        assert!(current.as_ref().unwrap().is_finished());
        track(&mut current, Some(Operation::start("b", true)));
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
            describe(&cmd, state)
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
}
