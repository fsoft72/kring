//! Helpers shared by the integration tests.

use kring_core::dev_guard::private_session_violation;

/// Guards integration tests so they can only touch the private session.
///
/// Returns false (skip) when `KRING_IT` is unset. When it is set, panics unless the
/// process runs inside `scripts/it-session.sh` (see [`private_session_violation`]).
pub fn it_guard() -> bool {
    if std::env::var_os("KRING_IT").is_none() {
        eprintln!("KRING_IT not set: skipping (run via scripts/it-session.sh)");
        return false;
    }
    if let Some(reason) = private_session_violation() {
        panic!("KRING_IT set but not in the private session: {reason}: refusing to run");
    }
    true
}
