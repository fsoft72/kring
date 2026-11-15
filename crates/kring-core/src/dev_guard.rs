//! Guard that keeps tests and dev tools away from the user's real keyring.
//!
//! Integration tests and the `seed_dev` example may only talk to the private
//! session started by `scripts/it-session.sh` or `scripts/dev-session.sh`.
//!
//! `violation_from` is pure and always compiled (the app's debug-only dev
//! presets use it); the environment reader stays behind the `dev` feature.

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

/// Returns why `data_home` is not strictly inside the session temp root (the
/// parent of the private runtime dir `it_runtime`), or `None` when it is.
///
/// Fails closed: a missing, relative or rootless runtime dir, a root of `/`
/// and any `..` component in either path are violations.
pub fn data_home_violation(
    data_home: &std::path::Path,
    it_runtime: Option<&std::path::Path>,
) -> Option<String> {
    use std::path::Component;
    let Some(runtime) = it_runtime.filter(|r| r.is_absolute()) else {
        return Some(format!("{IT_RUNTIME_VAR} is unset or not absolute"));
    };
    let dotted = |p: &std::path::Path| p.components().any(|c| c == Component::ParentDir);
    if dotted(runtime) || dotted(data_home) {
        return Some("paths must not contain '..'".into());
    }
    let root = match runtime.parent() {
        Some(root) if root.parent().is_some() => root,
        _ => return Some(format!("{} has no temp root", runtime.display())),
    };
    if data_home == root || !data_home.starts_with(root) {
        return Some(format!(
            "data home {} is not inside {}",
            data_home.display(),
            root.display()
        ));
    }
    None
}

/// Checks the current process environment; `Some(reason)` means "do not touch the bus".
#[cfg(any(test, feature = "dev"))]
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

    /// The data home must sit strictly inside the parent of the runtime dir,
    /// without `..`; a missing or rootless runtime dir fails closed.
    #[test]
    fn data_home_inside_temp_root() {
        use std::path::Path;
        let run = Some(Path::new(RUN));
        let inside = Path::new("/tmp/kring-it.abc/data");
        assert_eq!(data_home_violation(inside, run), None);
        assert!(data_home_violation(inside, None).is_some());
        assert!(data_home_violation(inside, Some(Path::new(""))).is_some());
        assert!(data_home_violation(inside, Some(Path::new("/"))).is_some());
        assert!(data_home_violation(inside, Some(Path::new("/run"))).is_some());
        assert!(data_home_violation(inside, Some(Path::new("run"))).is_some());
        let home = Path::new("/home/me/.local/share");
        assert!(data_home_violation(home, run).is_some());
        let escape = Path::new("/tmp/kring-it.abc/../../home/me/.local/share");
        assert!(data_home_violation(escape, run).is_some());
        let dotted_run = Some(Path::new("/tmp/kring-it.abc/x/../run"));
        assert!(data_home_violation(inside, dotted_run).is_some());
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
