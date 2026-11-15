//! Backups of keyring files, with age encryption for plaintext keyrings, and restore.

mod create;
mod restore;

pub use create::{
    BACKUP_KEEP, BackupFile, BackupInfo, BackupManager, KEYRING_MAGIC, is_plaintext_keyring,
    keyring_backup_set,
};
pub(crate) use create::{age_identity, encrypt_age, io_err};
pub use restore::{RESTART_HINT, RestoreReport, read_backup_file, restore};
