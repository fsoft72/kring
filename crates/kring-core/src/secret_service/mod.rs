//! Secret Service backend using the standard D-Bus API (via oo7).

mod backend;
pub mod errors;

pub use backend::SecretServiceBackend;
