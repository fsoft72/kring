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
