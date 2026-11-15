# Changes

## 2026-11-15

- Added design document `docs/superpowers/specs/2026-11-15-kring-design.md`
  (Secret Service, offline keyring files, consolidate, KWallet migration, SSH, GPG).
- Added implementation plan 1 (foundation + Secret Service) in `docs/superpowers/plans/`.
- Scaffolded Cargo workspace (`kring-core`, `kring`), empty eframe window, and
  `scripts/check-no-gui-toolkits.sh` guard against GTK/Qt/GNOME crates.
- Added `kring-core` model types (`SecretValue` zeroized and redacted), `KringError`, and input validation.
- Added `SecretStore`/`MasterPasswordStore` traits and in-memory `FakeStore` (feature `fake`).
- Added `scripts/it-session.sh` (private dbus session + throwaway gnome-keyring) and the `it_smoke` integration test.
- Added Secret Service backend (`SecretServiceBackend`, standard API via oo7, encrypted session) with D-Bus error mapping; integration tests guarded by `it_guard` (session script now exports `KRING_IT_RUNTIME`).
- Added provider detection (`ProviderKind`, `detect`, `classify`) and PAM detection (`pam_status`), with an `it_provider` integration test.
- Added gnome-keyring master password support (`MasterPasswordStore` for `SecretServiceBackend`: create, unlock and change password via the private interface over a dedicated encrypted session, no prompts) with the `it_master_password` integration test.
- Added backups (`BackupManager`, age-encrypted plaintext keyrings, manifest with sha256, pruning) and `paths` helpers.
- Added the `kring` app library with `worker` (background thread, command/event channels, provider gating, backup before deletes, NotFound refresh).
- Added `app_state` (event reducer with sorted collections), `clipboard` (30 s auto-clear guard over arboard) and `secret_display` (text vs hex view).
- Added the egui UI (`KringApp`): sidebar with collections and disabled future sections, collection header with badges and PAM notices, item table with search, item detail (masked secret, Show/Hide, Copy with 30 s auto-clear, editable attributes), modal dialogs (unlock, create, rename, change password, delete confirmations, new/edit item, backup passphrase) with zeroized password buffers, provider gating tooltips and a status bar.
- Added `startup::connect` (keeps the D-Bus runtime alive for the worker) with the `it_startup` integration test, the `it_master_password` check that locked collections list their items as locked, the `seed_dev` example and `scripts/dev-session.sh` for isolated manual testing.
- Unified the private-session safety guard in `kring_core::dev_guard` (feature `dev`), used by both crates' integration tests and `seed_dev`; "Save attributes" now confirms the listed attribute changes (`attribute_diff`); deleting the login or default collection shows a warning; split dialog validation (`dialog_submit`) and the copy flow (`copy_flow::SecretCopier`) into their own modules.
