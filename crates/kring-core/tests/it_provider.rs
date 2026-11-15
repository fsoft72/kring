//! Integration test for provider detection.
//!
//! Run only through `scripts/it-session.sh`:
//! `bash scripts/it-session.sh cargo test -p kring-core --test it_provider -- --ignored`

mod common;

use kring_core::provider::{ProviderKind, detect};
use oo7::zbus;

/// The private session runs gnome-keyring with the master password interface.
#[tokio::test]
#[ignore]
async fn detect_in_session() {
    if !common::it_guard() {
        return;
    }
    let conn = common::within(zbus::Connection::session()).await.unwrap();
    let info = common::within(detect(&conn)).await.unwrap();
    assert_eq!(info.kind, ProviderKind::GnomeKeyring, "{info:?}");
    assert!(info.has_master_password_iface, "{info:?}");
    assert!(info.pid.is_some());
    assert!(info.competitors.is_empty(), "{info:?}");
}
