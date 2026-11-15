//! SSH key files in a directory such as `~/.ssh`: scanning, inspection and operations.
//!
//! Only files recognised as SSH keys are ever listed (see [`scan_keys`]) or
//! modified (see the operations in `ops`); `authorized_keys`, `known_hosts`,
//! `config` and similar files are ignored and never touched.

mod agent;
mod ops;
mod scan;

pub use agent::{AgentIdentity, add_identity, list_identities, remove_all, remove_identity};
pub use ops::{
    MSG_KEY_PASSPHRASE_REQUIRED, MSG_WRONG_KEY_PASSPHRASE, NewKey, RESERVED_NAMES, RSA_BITS,
    change_passphrase, delete_key, export_private, export_public, generate_key, import_key,
    valid_key_name,
};
pub use scan::{SshAlgorithm, SshKeyInfo, scan_keys};
