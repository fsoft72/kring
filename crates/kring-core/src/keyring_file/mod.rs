//! Offline access to keyring files on disk (no daemon involved).

pub mod scan;
pub mod textual;

pub use scan::{KeyringFileInfo, KeyringFormat, detect_format, scan_dir};
