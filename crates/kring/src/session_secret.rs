//! Passphrase remembered for the session (memory only, opt-in per dialog).
//!
//! The value lives in a [`SecretValue`] (zeroized when forgotten or when
//! kring exits). It is never written to disk, logged or sent in an event,
//! and the `Debug` output only says whether one is remembered.
//!
//! When remembered it answers worker passphrase requests automatically, at
//! most once per request: a second request for the same command (or a
//! wrong passphrase error after the automatic answer) opens the dialog.

use kring_core::model::{CollectionId, SecretValue};

use crate::views::dialog_submit::with_backup_passphrase;
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
/// Part of the worker errors of a wrong passphrase (backup restore, archive).
const WRONG_PASSPHRASE: &str = "Wrong passphrase";

/// The last automatic use of the remembered passphrase.
#[derive(Clone, Debug)]
enum AutoUse {
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
}

/// What the app must open after an automatic use failed.
#[derive(Clone, Debug)]
pub enum FollowUp {
    /// Ask the passphrase of this echo with the dialog (no automatic answer).
    Passphrase(Command),
    /// Open the password dialog of this collection.
    Unlock {
        /// Collection to unlock.
        collection: CollectionId,
        /// Display name.
        label: String,
    },
}

/// The passphrase remembered for the session and its last automatic use.
#[derive(Default)]
pub struct SessionSecret {
    value: Option<SecretValue>,
    auto: Option<AutoUse>,
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

    /// Forgets the remembered passphrase (zeroized on drop).
    pub fn forget(&mut self) {
        self.value = None;
        self.auto = None;
    }

    /// Returns true when a passphrase is remembered.
    pub fn is_remembered(&self) -> bool {
        self.value.is_some()
    }

    /// Returns the remembered passphrase.
    pub fn value(&self) -> Option<&SecretValue> {
        self.value.as_ref()
    }

    /// Answers a [`Event::PassphraseNeeded`] echo: returns the command to
    /// resend with the remembered passphrase, or `None` when the dialog must
    /// open (nothing remembered, or this echo was already answered once).
    pub fn resend(&mut self, echo: &Command) -> Option<Command> {
        let value = self.value.clone()?;
        let key = _key(echo);
        let repeated = matches!(&self.auto, Some(AutoUse::Resend { key: k, .. }) if *k == key);
        if repeated {
            self.auto = None;
            return None;
        }
        self.auto = Some(AutoUse::Resend {
            echo: echo.clone(),
            key,
        });
        Some(with_backup_passphrase(echo.clone(), value))
    }

    /// Answers an [`Event::ApplyPassphrasesNeeded`] of `plan_id`: returns the
    /// remembered passphrase, or `None` when the dialog must open (nothing
    /// remembered, or this plan was already answered once).
    pub fn apply_passphrase(&mut self, plan_id: u64) -> Option<SecretValue> {
        let value = self.value.clone()?;
        if matches!(self.auto, Some(AutoUse::Apply(id)) if id == plan_id) {
            self.auto = None;
            return None;
        }
        self.auto = Some(AutoUse::Apply(plan_id));
        Some(value)
    }

    /// Returns the unlock command of `collection` with the remembered
    /// passphrase (a failure then opens its password dialog, see
    /// [`Self::observe`]), or `None` when nothing is remembered.
    pub fn unlock(&mut self, collection: &CollectionId, label: &str) -> Option<Command> {
        let password = self.value.clone()?;
        self.auto = Some(AutoUse::Unlock {
            collection: collection.clone(),
            label: label.to_string(),
        });
        Some(Command::Unlock {
            collection: collection.clone(),
            password,
        })
    }

    /// Follows the worker answers to an automatic use: an unlock error opens
    /// the password dialog, a wrong passphrase after a resend opens the
    /// passphrase dialog of that command; any other end of an operation
    /// clears the record.
    pub fn observe(&mut self, event: &Event) -> Option<FollowUp> {
        match event {
            Event::Error(msg) => match self.auto.take()? {
                AutoUse::Unlock { collection, label } => {
                    Some(FollowUp::Unlock { collection, label })
                }
                AutoUse::Resend { echo, key } if msg.contains(WRONG_PASSPHRASE) => {
                    // Kept: the dialog of this echo must not be answered again.
                    self.auto = Some(AutoUse::Resend {
                        echo: echo.clone(),
                        key,
                    });
                    Some(FollowUp::Passphrase(echo))
                }
                _ => None,
            },
            Event::Done(_)
            | Event::TransferDone(_)
            | Event::ConsolidationDone(..)
            | Event::ImportDone(_) => {
                self.auto = None;
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
        assert!(s.resend(&delete_echo()).is_none());
        assert!(s.apply_passphrase(1).is_none());
        assert!(s.unlock(&CollectionId("/c/a".into()), "a").is_none());
    }

    /// A passphrase request is answered once with the remembered value; the
    /// same request again opens the dialog.
    #[test]
    fn resend_at_most_once() {
        let mut s = remembered();
        let Some(Command::DeleteItem {
            backup_passphrase: Some(p),
            ..
        }) = s.resend(&delete_echo())
        else {
            panic!("expected an automatic resend");
        };
        assert_eq!(p.as_text(), Some(PASS));
        assert!(s.resend(&delete_echo()).is_none());
        // Cleared by the dialog: a later request is answered again.
        assert!(s.resend(&delete_echo()).is_some());
    }

    /// A finished operation clears the record: the next same request is answered.
    #[test]
    fn done_clears_record() {
        let mut s = remembered();
        assert!(s.resend(&delete_echo()).is_some());
        assert!(s.observe(&Event::Done("Item deleted".into())).is_none());
        assert!(s.resend(&delete_echo()).is_some());
    }

    /// A wrong passphrase after a resend opens the dialog of that command,
    /// which is then not answered automatically.
    #[test]
    fn wrong_passphrase_opens_dialog_once() {
        let mut s = remembered();
        assert!(s.resend(&restore_echo()).is_some());
        let err = Event::Error("invalid input: Wrong passphrase for backup".into());
        let Some(FollowUp::Passphrase(echo)) = s.observe(&err) else {
            panic!("expected the passphrase dialog");
        };
        assert!(matches!(
            echo,
            Command::RestoreBackup {
                passphrase: None,
                ..
            }
        ));
        assert!(s.resend(&echo).is_none());
    }

    /// Any other error just ends the automatic use.
    #[test]
    fn other_error_no_follow_up() {
        let mut s = remembered();
        assert!(s.resend(&delete_echo()).is_some());
        assert!(s.observe(&Event::Error("Backup failed".into())).is_none());
        assert!(
            s.observe(&Event::Error("Wrong passphrase".into()))
                .is_none()
        );
    }

    /// Apply requests are answered once per plan.
    #[test]
    fn apply_once_per_plan() {
        let mut s = remembered();
        assert_eq!(s.apply_passphrase(7).unwrap().as_text(), Some(PASS));
        assert!(s.apply_passphrase(7).is_none());
        assert!(s.apply_passphrase(8).is_some());
    }

    /// An unlock with the remembered value that fails opens the password
    /// dialog once; success clears it.
    #[test]
    fn unlock_failure_opens_dialog() {
        let mut s = remembered();
        let id = CollectionId("/c/work".into());
        let Some(Command::Unlock { password, .. }) = s.unlock(&id, "Work") else {
            panic!("expected an unlock");
        };
        assert_eq!(password.as_text(), Some(PASS));
        let Some(FollowUp::Unlock { collection, label }) =
            s.observe(&Event::Error("Wrong password".into()))
        else {
            panic!("expected the unlock dialog");
        };
        assert_eq!((collection, label.as_str()), (id.clone(), "Work"));
        assert!(s.observe(&Event::Error("again".into())).is_none());
        s.unlock(&id, "Work");
        assert!(
            s.observe(&Event::Done("Collection unlocked".into()))
                .is_none()
        );
        assert!(s.observe(&Event::Error("later".into())).is_none());
    }

    /// Forget drops the value and the record.
    #[test]
    fn forget_clears() {
        let mut s = remembered();
        assert!(s.resend(&delete_echo()).is_some());
        s.forget();
        assert!(!s.is_remembered());
        assert!(s.value().is_none());
        assert!(s.resend(&delete_echo()).is_none());
    }
}
