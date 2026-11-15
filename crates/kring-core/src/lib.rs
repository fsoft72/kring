//! Core library for kring: Secret Service keyring management.

pub mod backup;
pub mod dev_guard;
pub mod error;
#[cfg(any(test, feature = "fake"))]
pub mod fake_store;
pub mod keyring_file;
pub mod model;
pub mod pam;
pub mod paths;
pub mod provider;
pub mod secret_service;
pub mod store;
pub mod transfer;
pub mod validate;

pub use error::{KringError, Result};
pub use store::{MasterPasswordStore, SecretStore};
