//! Passphrase remembered for the session (memory only, opt-in per dialog).
//!
//! The value lives in a [`SecretValue`] (zeroized when forgotten or when
//! kring exits). It is never written to disk, logged or sent in an event,
//! and the `Debug` output only says whether one is remembered.
//!
//! When remembered it answers worker passphrase requests automatically, at
//! most once per request: a second request for the same command opens the
//! dialog. Each automatic use records the number of the command that
//! carries it and judges only that command's events, decided on its
//! [`Event::CommandFinished`] (see [`crate::operation`] for the numbering):
//! a wrong passphrase reopens the dialog with its fields, a failed unlock
//! opens the password dialog, a successful unlock is announced.

use kring_core::model::{CollectionId, SecretValue};

use crate::views::dialog_submit::with_backup_passphrase;
use crate::views::dialogs::DialogKind;
use crate::worker::{Command, Event};

/// Text of the checkbox of passphrase dialogs.
pub const MSG_REMEMBER: &str = "Remember for this session";
/// Warning under the checkbox (TERTIARY).
pub const MSG_REMEMBER_WARNING: &str =
    "Kept in memory until kring closes: anyone using this session can use it.";
/// Info toast after an automatic answer.
pub const MSG_USED_REMEMBERED: &str = "Used the remembered passphrase";
/// Tooltip of the rail indicator.
pub const MSG_REMEMBERED_TIP: &str = "A passphrase is remembered for this session";
/// Question of the forget confirmation.
pub const MSG_FORGET_QUESTION: &str = "Forget the remembered passphrase?";
/// Error line of a dialog reopened after a wrong remembered passphrase.
pub const MSG_WRONG_TRY_AGAIN: &str = "Wrong passphrase, try again";
/// Part of the worker errors of a wrong passphrase (backup restore:
/// "Wrong passphrase for backup", archive: "Wrong passphrase or corrupted archive").
const WRONG_PASSPHRASE: &str = "Wrong passphrase";

/// Returns true when a worker error says the passphrase or password was
/// wrong: backups and archives, KWallet wallets
/// ([`kring_core::kwallet_file::MSG_WRONG_PASSWORD`]) and binary keyring
/// files ([`kring_core::keyring_file::binary::MSG_WRONG_PASSWORD_PREFIX`]).
pub fn is_wrong_passphrase(msg: &str) -> bool {
    use kring_core::keyring_file::binary::MSG_WRONG_PASSWORD_PREFIX;
    use kring_core::kwallet_file::MSG_WRONG_PASSWORD;
    [
        WRONG_PASSPHRASE,
        MSG_WRONG_PASSWORD,
        MSG_WRONG_PASSWORD_PREFIX,
    ]
    .iter()
    .any(|part| msg.contains(part))
}

/// What the remembered passphrase was used for.
#[derive(Clone)]
enum AutoKind {
    /// A [`Event::PassphraseNeeded`] answered by resending `echo` with it.
    Resend {
        /// The echo (passphrase fields cleared) that was answered.
        echo: Command,
        /// Comparable form of `echo` (its `Debug` text, which has no secret).
        key: String,
    },
    /// An [`Event::ApplyPassphrasesNeeded`] of plan `0` answered with it.
    Apply(u64),
    /// An unlock of `collection` (shown as `label`) sent with it.
    Unlock {
        /// Collection being unlocked.
        collection: CollectionId,
        /// Display name, for the password dialog opened on failure.
        label: String,
    },
    /// A dialog opened by the user submitted with it; the dialog with
    /// empty passphrase fields, to reopen after a wrong passphrase.
    Dialog(Box<DialogKind>),
}

/// What the events of the command carrying the remembered passphrase reported.
#[derive(Clone, Copy, Default)]
struct Window {
    /// A success event arrived.
    done: bool,
    /// An error arrived.
    error: bool,
    /// An error said the passphrase is wrong.
    wrong: bool,
    /// A passphrase was asked for again.
    asked: bool,
}

/// The last automatic use of the remembered passphrase.
#[derive(Clone)]
struct AutoUse {
    /// Number of the command carrying it.
    id: u64,
    /// What it was used for.
    kind: AutoKind,
    /// Events of that command so far.
    window: Window,
    /// The command finished (record kept only to refuse a repeated request).
    finished: bool,
}

/// What the app must do after an automatic use was judged.
pub enum FollowUp {
    /// Reopen this dialog with its fields (wrong passphrase).
    Dialog(Box<DialogKind>),
    /// Open the password dialog of this collection.
    Unlock {
        /// Collection to unlock.
        collection: CollectionId,
        /// Display name.
        label: String,
    },
    /// Say that the remembered passphrase was used (successful unlock).
    UsedRemembered,
}

/// A typed passphrase waiting for its command to prove it right.
struct Candidate {
    /// Number of the command carrying it.
    id: u64,
    /// The typed passphrase.
    value: SecretValue,
    /// An error said the passphrase is wrong.
    wrong: bool,
}

/// The passphrase remembered for the session and its last automatic use.
#[derive(Default)]
pub struct SessionSecret {
    value: Option<SecretValue>,
    auto: Option<AutoUse>,
    candidate: Option<Candidate>,
}

impl std::fmt::Debug for SessionSecret {
    /// Prints only whether a passphrase is remembered (not even its length).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSecret")
            .field("remembered", &self.value.is_some())
            .finish()
    }
}

/// Returns the comparable key of an echoed command.
fn _key(echo: &Command) -> String {
    format!("{echo:?}")
}

impl SessionSecret {
    /// Remembers `value` for the session, replacing an earlier one.
    pub fn remember(&mut self, value: SecretValue) {
        self.value = Some(value);
    }

    /// Keeps `value`, typed in a dialog that reopens when wrong and sent as
    /// command number `id`, to remember it only when that command finishes
    /// without a wrong-passphrase error (see [`Self::observe`]).
    pub fn remember_if_correct(&mut self, value: SecretValue, id: u64) {
        self.candidate = Some(Candidate {
            id,
            value,
            wrong: false,
        });
    }

    /// Forgets the remembered passphrase and any candidate (zeroized on drop).
    pub fn forget(&mut self) {
        self.value = None;
        self.auto = None;
        self.candidate = None;
    }

    /// Follows the events of the candidate's command; remembers it when the
    /// command finished without a wrong-passphrase error, drops it otherwise.
    fn _observe_candidate(&mut self, event: &Event, running: u64) {
        let Some(c) = self.candidate.as_mut() else {
            return;
        };
        match event {
            Event::CommandFinished(id) if *id == c.id => {
                let Some(c) = self.candidate.take() else {
                    return;
                };
                if !c.wrong {
                    self.value = Some(c.value);
                }
            }
            Event::Error(msg) if running == c.id => c.wrong |= is_wrong_passphrase(msg),
            _ => {}
        }
    }

    /// Returns true when a passphrase is remembered.
    pub fn is_remembered(&self) -> bool {
        self.value.is_some()
    }

    /// Returns the remembered passphrase.
    pub fn value(&self) -> Option<&SecretValue> {
        self.value.as_ref()
    }

    /// Records an automatic use by command number `id`.
    fn _record(&mut self, id: u64, kind: AutoKind) {
        self.auto = Some(AutoUse {
            id,
            kind,
            window: Window::default(),
            finished: false,
        });
    }

    /// Answers a [`Event::PassphraseNeeded`] echo: returns the command to
    /// resend (it will be command number `id`) with the remembered
    /// passphrase, or `None` when the dialog must open (nothing remembered,
    /// or this echo was already answered automatically).
    pub fn resend(&mut self, echo: &Command, id: u64) -> Option<Command> {
        let value = self.value.clone()?;
        let key = _key(echo);
        let repeated = matches!(
            &self.auto,
            Some(AutoUse { kind: AutoKind::Resend { key: k, .. }, .. }) if *k == key
        );
        if repeated {
            self.auto = None;
            return None;
        }
        let resent = with_backup_passphrase(echo.clone(), value);
        let echo = echo.clone();
        self._record(id, AutoKind::Resend { echo, key });
        Some(resent)
    }

    /// Answers an [`Event::ApplyPassphrasesNeeded`] of `plan_id` (the apply
    /// will be command number `id`): returns the remembered passphrase, or
    /// `None` when the dialog must open (nothing remembered, or this plan
    /// was already answered automatically).
    pub fn apply_passphrase(&mut self, plan_id: u64, id: u64) -> Option<SecretValue> {
        let value = self.value.clone()?;
        let repeated = matches!(
            &self.auto,
            Some(AutoUse { kind: AutoKind::Apply(p), .. }) if *p == plan_id
        );
        if repeated {
            self.auto = None;
            return None;
        }
        self._record(id, AutoKind::Apply(plan_id));
        Some(value)
    }

    /// Returns the unlock command of `collection` with the remembered
    /// passphrase (it will be command number `id`; see [`Self::observe`]),
    /// or `None` when nothing is remembered.
    pub fn unlock(&mut self, collection: &CollectionId, label: &str, id: u64) -> Option<Command> {
        let password = self.value.clone()?;
        let kind = AutoKind::Unlock {
            collection: collection.clone(),
            label: label.to_string(),
        };
        self._record(id, kind);
        Some(Command::Unlock {
            collection: collection.clone(),
            password,
        })
    }

    /// Records that a dialog was submitted as command number `id`, either
    /// with the remembered passphrase or as a password dialog typed by the
    /// user (see `Dialog::retry_kind`); `kind` (fields empty) reopens if the
    /// passphrase is wrong.
    pub fn used_in_dialog(&mut self, kind: DialogKind, id: u64) {
        self._record(id, AutoKind::Dialog(Box::new(kind)));
    }

    /// Follows the events of the command carrying the remembered passphrase
    /// (`running` is the number of the command the event belongs to) and
    /// judges it on its [`Event::CommandFinished`].
    pub fn observe(&mut self, event: &Event, running: u64) -> Option<FollowUp> {
        self._observe_candidate(event, running);
        let auto = self.auto.as_mut().filter(|a| !a.finished)?;
        if let Event::CommandFinished(id) = event {
            if *id != auto.id {
                return None;
            }
            return self._decide();
        }
        if running != auto.id {
            return None;
        }
        let window = &mut auto.window;
        match event {
            Event::Done(_)
            | Event::TransferDone(_)
            | Event::ConsolidationDone(..)
            | Event::ImportDone(_) => window.done = true,
            Event::Error(msg) => {
                window.error = true;
                window.wrong |= is_wrong_passphrase(msg);
            }
            Event::PassphraseNeeded(_) | Event::ApplyPassphrasesNeeded { .. } => {
                window.asked = true;
            }
            _ => {}
        }
        None
    }

    /// Judges the finished command of the recorded automatic use.
    fn _decide(&mut self) -> Option<FollowUp> {
        let auto = self.auto.take()?;
        let w = auto.window;
        match auto.kind {
            AutoKind::Unlock { collection, label } if w.error && !w.done => {
                Some(FollowUp::Unlock { collection, label })
            }
            AutoKind::Unlock { .. } if w.done => Some(FollowUp::UsedRemembered),
            AutoKind::Resend { echo, .. } if w.wrong && !w.done => {
                Some(FollowUp::Dialog(Box::new(DialogKind::passphrase(echo))))
            }
            AutoKind::Dialog(kind) if w.wrong && !w.done => Some(FollowUp::Dialog(kind)),
            kind @ (AutoKind::Resend { .. } | AutoKind::Apply(_)) if w.asked => {
                // Asked again: kept so the repeated request opens its dialog.
                self.auto = Some(AutoUse {
                    kind,
                    finished: true,
                    ..auto
                });
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kring_core::model::ItemId;
    use std::path::PathBuf;

    /// Remembered test value.
    const PASS: &str = "hunter2-session";

    /// A session with `PASS` remembered.
    fn remembered() -> SessionSecret {
        let mut s = SessionSecret::default();
        s.remember(SecretValue::from_text(PASS));
        s
    }

    /// Echo of a delete waiting for its backup passphrase.
    fn delete_echo() -> Command {
        Command::DeleteItem {
            item: ItemId("/c/a/1".into()),
            backup_passphrase: None,
        }
    }

    /// Echo of a restore waiting for its passphrase.
    fn restore_echo() -> Command {
        Command::RestoreBackup {
            dir: PathBuf::from("/b/1"),
            files: vec![PathBuf::from("/k/a.keyring")],
            passphrase: None,
        }
    }

    /// A typed candidate is remembered only after a clean command window.
    #[test]
    fn candidate_remembered_only_when_correct() {
        let wrong = Event::Error(kring_core::kwallet_file::MSG_WRONG_PASSWORD.into());
        let mut s = remembered();
        s.remember_if_correct(SecretValue::from_text("bad"), 7);
        feed(&mut s, 7, &[wrong, Event::CommandFinished(7)]);
        assert_eq!(s.value().and_then(|v| v.as_text()), Some(PASS));
        s.remember_if_correct(SecretValue::from_text("good"), 8);
        feed(
            &mut s,
            8,
            &[Event::Done(Default::default()), Event::CommandFinished(8)],
        );
        assert_eq!(s.value().and_then(|v| v.as_text()), Some("good"));
    }

    /// Feeds `events` handled as command `running`, returning the last follow-up.
    fn feed(s: &mut SessionSecret, running: u64, events: &[Event]) -> Option<FollowUp> {
        let mut last = None;
        for e in events {
            if let Some(f) = s.observe(e, running) {
                last = Some(f);
            }
        }
        last
    }

    /// Wrong backup, archive, wallet and binary keyring passwords all count
    /// as a wrong passphrase (shared constants); other errors do not.
    #[test]
    fn wrong_passphrase_messages() {
        use kring_core::keyring_file::binary::MSG_WRONG_PASSWORD_PREFIX;
        use kring_core::kwallet_file::MSG_WRONG_PASSWORD;
        assert!(is_wrong_passphrase("Wrong passphrase for backup"));
        assert!(is_wrong_passphrase(MSG_WRONG_PASSWORD));
        let file = format!("invalid input: {MSG_WRONG_PASSWORD_PREFIX}a.keyring");
        assert!(is_wrong_passphrase(&file));
        assert!(!is_wrong_passphrase("No wallet named 'x'"));
        assert!(!is_wrong_passphrase("Cannot read a.keyring: io"));
    }

    /// A wallet password dialog (typed or remembered) reopens after a wrong
    /// wallet password, and not after a success.
    #[test]
    fn wallet_dialog_reopens_when_wrong() {
        let mut s = SessionSecret::default();
        s.used_in_dialog(DialogKind::wallet_password("w".into()), 5);
        let wrong = Event::Error(kring_core::kwallet_file::MSG_WRONG_PASSWORD.into());
        let follow = feed(&mut s, 5, &[wrong, Event::CommandFinished(5)]);
        assert!(matches!(
            follow,
            Some(FollowUp::Dialog(k)) if matches!(*k, DialogKind::WalletPassword { .. })
        ));
        s.used_in_dialog(DialogKind::wallet_password("w".into()), 6);
        let items = Event::WalletItems {
            name: "w".into(),
            items: vec![],
        };
        assert!(feed(&mut s, 6, &[items, Event::CommandFinished(6)]).is_none());
    }

    /// Debug shows neither the value nor its length.
    #[test]
    fn debug_hides_value() {
        let s = remembered();
        let text = format!("{s:?}");
        assert!(!text.contains(PASS));
        assert!(!text.contains("bytes"));
        assert!(text.contains("remembered: true"));
    }

    /// Nothing remembered: every request opens its dialog.
    #[test]
    fn nothing_remembered_never_answers() {
        let mut s = SessionSecret::default();
        assert!(s.resend(&delete_echo(), 0).is_none());
        assert!(s.apply_passphrase(1, 0).is_none());
        assert!(s.unlock(&CollectionId("/c/a".into()), "a", 0).is_none());
    }

    /// A passphrase request is answered with the remembered value; asked
    /// again by that command, the repeated request opens the dialog.
    #[test]
    fn resend_at_most_once() {
        let mut s = remembered();
        let Some(Command::DeleteItem {
            backup_passphrase: Some(p),
            ..
        }) = s.resend(&delete_echo(), 1)
        else {
            panic!("expected an automatic resend");
        };
        assert_eq!(p.as_text(), Some(PASS));
        let asked = Event::PassphraseNeeded(Box::new(delete_echo()));
        assert!(feed(&mut s, 1, &[asked, Event::CommandFinished(1)]).is_none());
        assert!(s.resend(&delete_echo(), 2).is_none());
        // Cleared by the dialog: a later request is answered again.
        assert!(s.resend(&delete_echo(), 3).is_some());
    }

    /// A finished command clears the record: the next same request is answered.
    #[test]
    fn done_clears_record() {
        let mut s = remembered();
        assert!(s.resend(&delete_echo(), 0).is_some());
        let done = [
            Event::Done("Item deleted".into()),
            Event::CommandFinished(0),
        ];
        assert!(feed(&mut s, 0, &done).is_none());
        assert!(s.resend(&delete_echo(), 1).is_some());
    }

    /// A wrong passphrase after a resend reopens the passphrase dialog.
    #[test]
    fn wrong_passphrase_reopens_dialog() {
        let mut s = remembered();
        assert!(s.resend(&restore_echo(), 4).is_some());
        let err = Event::Error("invalid input: Wrong passphrase for backup".into());
        assert!(s.observe(&err, 4).is_none(), "decided on CommandFinished");
        let Some(FollowUp::Dialog(kind)) = s.observe(&Event::CommandFinished(4), 4) else {
            panic!("expected the passphrase dialog");
        };
        let DialogKind::Passphrase { command, .. } = *kind else {
            panic!("expected a passphrase dialog");
        };
        assert!(matches!(
            *command,
            Command::RestoreBackup {
                passphrase: None,
                ..
            }
        ));
    }

    /// A wrong passphrase in a dialog submitted with the remembered value
    /// reopens that dialog.
    #[test]
    fn wrong_passphrase_in_dialog_reopens_it() {
        let mut s = remembered();
        let kind = DialogKind::restore_backup(
            PathBuf::from("/b/1"),
            vec![],
            vec![],
            crate::views::dialogs::RestorePassphrase::Existing,
        );
        s.used_in_dialog(kind, 2);
        let events = [
            Event::Error("invalid input: Wrong passphrase for backup".into()),
            Event::CommandFinished(2),
        ];
        let Some(FollowUp::Dialog(kind)) = feed(&mut s, 2, &events) else {
            panic!("expected the dialog again");
        };
        assert!(matches!(*kind, DialogKind::RestoreBackup { .. }));
        // An archive error counts too; another error does not.
        s.used_in_dialog(DialogKind::create_collection(), 3);
        let archive = [
            Event::Error("invalid input: Wrong passphrase or corrupted archive".into()),
            Event::CommandFinished(3),
        ];
        assert!(matches!(
            feed(&mut s, 3, &archive),
            Some(FollowUp::Dialog(_))
        ));
        s.used_in_dialog(DialogKind::create_collection(), 4);
        let other = [
            Event::Error("Backup failed".into()),
            Event::CommandFinished(4),
        ];
        assert!(feed(&mut s, 4, &other).is_none());
    }

    /// Events of other commands are never attributed.
    #[test]
    fn other_command_events_ignored() {
        let mut s = remembered();
        assert!(s.resend(&restore_echo(), 5).is_some());
        let stray = [
            Event::Error("Wrong passphrase or corrupted archive".into()),
            Event::CommandFinished(4),
        ];
        assert!(feed(&mut s, 4, &stray).is_none());
        let own = [
            Event::Done("Restore complete".into()),
            Event::CommandFinished(5),
        ];
        assert!(feed(&mut s, 5, &own).is_none());
    }

    /// Apply requests are answered once per plan.
    #[test]
    fn apply_once_per_plan() {
        let mut s = remembered();
        assert_eq!(s.apply_passphrase(7, 0).unwrap().as_text(), Some(PASS));
        assert!(s.apply_passphrase(7, 1).is_none());
        assert!(s.apply_passphrase(8, 2).is_some());
    }

    /// An unlock whose own command fails opens the password dialog; success
    /// is announced.
    #[test]
    fn unlock_failure_opens_dialog() {
        let mut s = remembered();
        let id = CollectionId("/c/work".into());
        let Some(Command::Unlock { password, .. }) = s.unlock(&id, "Work", 0) else {
            panic!("expected an unlock");
        };
        assert_eq!(password.as_text(), Some(PASS));
        let failed = [
            Event::Error("Wrong password".into()),
            Event::CommandFinished(0),
        ];
        let Some(FollowUp::Unlock { collection, label }) = feed(&mut s, 0, &failed) else {
            panic!("expected the unlock dialog");
        };
        assert_eq!((collection, label.as_str()), (id.clone(), "Work"));
        s.unlock(&id, "Work", 1);
        let ok = [
            Event::Done("Collection unlocked".into()),
            Event::CommandFinished(1),
        ];
        assert!(matches!(
            feed(&mut s, 1, &ok),
            Some(FollowUp::UsedRemembered)
        ));
        assert!(feed(&mut s, 2, &[Event::Error("later".into())]).is_none());
    }

    /// (c) An unlock followed by a refresh error (Done first) is a success.
    #[test]
    fn unlock_then_refresh_error_is_success() {
        let mut s = remembered();
        s.unlock(&CollectionId("/c/work".into()), "Work", 3);
        let events = [
            Event::Error("Cannot list collections".into()),
            Event::Done("Collection unlocked".into()),
            Event::CommandFinished(3),
        ];
        assert!(matches!(
            feed(&mut s, 3, &events),
            Some(FollowUp::UsedRemembered)
        ));
        // A stray error of an earlier command does not open the dialog either.
        s.unlock(&CollectionId("/c/work".into()), "Work", 5);
        assert!(
            feed(
                &mut s,
                4,
                &[Event::Error("x".into()), Event::CommandFinished(4)]
            )
            .is_none()
        );
    }

    /// Forget drops the value and the record.
    #[test]
    fn forget_clears() {
        let mut s = remembered();
        assert!(s.resend(&delete_echo(), 0).is_some());
        s.forget();
        assert!(!s.is_remembered());
        assert!(s.value().is_none());
        assert!(s.resend(&delete_echo(), 1).is_none());
    }
}
