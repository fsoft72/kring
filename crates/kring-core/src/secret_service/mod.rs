//! Secret Service backend using the standard D-Bus API (via oo7).

mod backend;
pub mod errors;
mod master_password;

pub use backend::SecretServiceBackend;
