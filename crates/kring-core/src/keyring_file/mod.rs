//! Offline access to keyring files on disk (no daemon involved).

pub mod binary;
pub mod delete;
pub mod empty;
pub mod retire;
pub mod scan;
pub mod summary;
pub mod textual;

pub use delete::{DeleteBackup, DeleteReport, MSG_DELETE_LIVE, delete_file};
pub use empty::{MSG_NOT_EMPTY, is_empty_textual, remove_empty_file, scanned_empty};
pub use retire::{
    MSG_BATCH_NEEDS_PASSPHRASE, RetireBatchReport, RetireMode, retire_file, retire_files_batch,
    retire_mode,
};
pub use scan::{KeyringFileInfo, KeyringFormat, detect_format, scan_dir};
pub use summary::{FileSummary, summarize_bytes, summarize_dir};
