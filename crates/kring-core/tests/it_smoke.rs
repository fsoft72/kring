//! Smoke test for the isolated integration session.
//!
//! Run only through `scripts/it-session.sh`, which provides a private session
//! bus with a throwaway gnome-keyring. Without `KRING_IT` the test is skipped
//! so it can never reach the real Secret Service.

/// Checks that the private Secret Service is reachable and exposes `login`.
#[tokio::test]
#[ignore]
async fn service_reachable() {
    if std::env::var_os("KRING_IT").is_none() {
        eprintln!("KRING_IT not set: skipping (run via scripts/it-session.sh)");
        return;
    }
    let service = oo7::dbus::Service::new()
        .await
        .expect("connect to Secret Service");
    let collections = service.collections().await.expect("list collections");
    let paths: Vec<String> = collections.iter().map(|c| c.path().to_string()).collect();
    assert!(
        paths.iter().any(|p| p.ends_with("/login")),
        "no login collection in {paths:?}"
    );
}
