//! Helpers shared by the integration tests.

use std::future::Future;
use std::time::Duration;

use kring_core::dev_guard::private_session_violation;

/// Maximum time a bus call may take before the test fails (an unexpected prompt would hang).
const BUS_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Awaits a bus call, failing the test if it takes longer than [`BUS_TIMEOUT`].
pub async fn within<F: Future>(fut: F) -> F::Output {
    tokio::time::timeout(BUS_TIMEOUT, fut)
        .await
        .expect("bus call timed out (unexpected prompt?)")
}
