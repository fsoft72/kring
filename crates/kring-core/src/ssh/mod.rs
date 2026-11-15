//! SSH key files in a directory such as `~/.ssh`: scanning and inspection.
//!
//! Only files recognised as SSH keys are ever listed (see [`scan_keys`]);
//! `authorized_keys`, `known_hosts`, `config` and similar files are ignored.

mod scan;

pub use scan::{SshAlgorithm, SshKeyInfo, scan_keys};
