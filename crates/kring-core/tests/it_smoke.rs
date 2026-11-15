//! Smoke test for the isolated integration session.
//!
//! Run only through `scripts/it-session.sh`, which provides a private session
//! bus with a throwaway gnome-keyring. Without `KRING_IT` the test is skipped
//! so it can never reach the real Secret Service.

mod common;

/// Checks that the private Secret Service is reachable and exposes `login`.
#[tokio::test]
#[ignore]
async fn service_reachable() {
    if !common::it_guard() {
        return;
    }
    let service = common::within(oo7::dbus::Service::new())
        .await
        .expect("connect to Secret Service");
    let collections = common::within(service.collections())
        .await
        .expect("list collections");
    let paths: Vec<String> = collections.iter().map(|c| c.path().to_string()).collect();
    assert!(
        paths.iter().any(|p| p.ends_with("/login")),
        "no login collection in {paths:?}"
    );
}
