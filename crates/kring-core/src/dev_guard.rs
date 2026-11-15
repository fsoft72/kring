//! Guard that keeps tests and dev tools away from the user's real keyring.
//!
//! Integration tests and the `seed_dev` example may only talk to the private
//! session started by `scripts/it-session.sh` or `scripts/dev-session.sh`.

/// Variable set by the session scripts to their private runtime dir.
pub const IT_RUNTIME_VAR: &str = "KRING_IT_RUNTIME";

/// Returns why the given environment is not the isolated session, or `None` when it is.
///
/// Requires `it_runtime == runtime_dir` (non-empty) and a bus address that is set,
/// not under `/run/user/` and (without its `,guid=...` options) not ending in `/bus`.
pub fn violation_from(
    it_runtime: Option<&str>,
    runtime_dir: Option<&str>,
    bus_addr: Option<&str>,
) -> Option<String> {
    let runtime = runtime_dir.unwrap_or_default();
    let expected = it_runtime.unwrap_or_default();
    if runtime.is_empty() || runtime != expected {
        return Some(format!(
            "XDG_RUNTIME_DIR ({runtime:?}) != {IT_RUNTIME_VAR} ({expected:?})"
        ));
    }
    let Some(address) = bus_addr else {
        return Some("DBUS_SESSION_BUS_ADDRESS is unset".into());
    };
    // Drop transport options such as `,guid=...` before inspecting the path.
    let transport = address.split(',').next().unwrap_or("");
    if transport.ends_with("/bus") || address.contains("/run/user/") {
        return Some(format!(
            "DBUS_SESSION_BUS_ADDRESS looks like the real user bus ({address})"
        ));
    }
    None
}

/// Checks the current process environment; `Some(reason)` means "do not touch the bus".
pub fn private_session_violation() -> Option<String> {
    let it_runtime = std::env::var(IT_RUNTIME_VAR).ok();
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").ok();
    let bus_addr = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
    violation_from(
        it_runtime.as_deref(),
        runtime_dir.as_deref(),
        bus_addr.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Private runtime dir used by the tests.
    const RUN: &str = "/tmp/kring-it.abc/run";
    /// Private bus address as printed by dbus-run-session.
    const PRIVATE_BUS: &str = "unix:path=/tmp/dbus-XyZ,guid=0123";

    /// The isolated session passes.
    #[test]
    fn private_session_ok() {
        assert_eq!(
            violation_from(Some(RUN), Some(RUN), Some(PRIVATE_BUS)),
            None
        );
    }

    /// Missing or different runtime dirs are rejected.
    #[test]
    fn runtime_mismatch_rejected() {
        assert!(violation_from(None, Some(RUN), Some(PRIVATE_BUS)).is_some());
        assert!(violation_from(Some(""), Some(""), Some(PRIVATE_BUS)).is_some());
        assert!(violation_from(Some(RUN), Some("/run/user/1000"), Some(PRIVATE_BUS)).is_some());
        assert!(violation_from(Some(RUN), None, Some(PRIVATE_BUS)).is_some());
    }

    /// A missing bus address or the real user bus is rejected.
    #[test]
    fn real_bus_rejected() {
        assert!(violation_from(Some(RUN), Some(RUN), None).is_some());
        assert!(
            violation_from(Some(RUN), Some(RUN), Some("unix:path=/run/user/1000/bus")).is_some()
        );
        assert!(
            violation_from(Some(RUN), Some(RUN), Some("unix:path=/tmp/x/bus,guid=1")).is_some()
        );
        assert!(
            violation_from(Some(RUN), Some(RUN), Some("unix:path=/x,dir=/run/user/1")).is_some()
        );
    }
}
