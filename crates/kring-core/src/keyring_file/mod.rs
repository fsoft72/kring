//! Offline access to keyring files on disk (no daemon involved).

pub mod binary;
pub mod delete;
pub mod retire;
pub mod scan;
pub mod summary;
pub mod textual;

pub use delete::{DeleteBackup, DeleteReport, MSG_DELETE_LIVE, delete_file};
pub use retire::{RetireBatchReport, RetireMode, retire_file, retire_files_batch, retire_mode};
pub use scan::{KeyringFileInfo, KeyringFormat, detect_format, scan_dir};
pub use summary::{FileSummary, summarize_bytes, summarize_dir};
