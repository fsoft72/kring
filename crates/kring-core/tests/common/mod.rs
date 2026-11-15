//! Helpers shared by the integration tests.

use std::future::Future;
use std::time::Duration;

/// Maximum time a bus call may take before the test fails (an unexpected prompt would hang).
const BUS_TIMEOUT: Duration = Duration::from_secs(10);

/// Guards integration tests so they can only touch the private session.
///
/// Returns false (skip) when `KRING_IT` is unset. When it is set, panics unless the
/// process runs inside `scripts/it-session.sh`: `XDG_RUNTIME_DIR` must equal
/// `KRING_IT_RUNTIME` and the session bus must not be the real user bus.
pub fn it_guard() -> bool {
    if std::env::var_os("KRING_IT").is_none() {
        eprintln!("KRING_IT not set: skipping (run via scripts/it-session.sh)");
        return false;
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
    let expected = std::env::var("KRING_IT_RUNTIME").unwrap_or_default();
    assert!(
        !runtime.is_empty() && runtime == expected,
        "KRING_IT set but XDG_RUNTIME_DIR ({runtime:?}) != KRING_IT_RUNTIME ({expected:?}): refusing to run"
    );
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .expect("KRING_IT set but DBUS_SESSION_BUS_ADDRESS is unset: refusing to run");
    // Drop transport options such as `,guid=...` before inspecting the path.
    let transport = address.split(',').next().unwrap_or("");
    assert!(
        !transport.ends_with("/bus") && !address.contains("/run/user/"),
        "DBUS_SESSION_BUS_ADDRESS looks like the real user bus ({address}): refusing to run"
    );
    true
}

/// Awaits a bus call, failing the test if it takes longer than [`BUS_TIMEOUT`].
pub async fn within<F: Future>(fut: F) -> F::Output {
    tokio::time::timeout(BUS_TIMEOUT, fut)
        .await
        .expect("bus call timed out (unexpected prompt?)")
}
