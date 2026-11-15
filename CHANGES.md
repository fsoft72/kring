# Changes

## 2026-11-15

- Added design document `docs/superpowers/specs/2026-11-15-kring-design.md`
  (Secret Service, offline keyring files, consolidate, KWallet migration, SSH, GPG).
- Added implementation plan 1 (foundation + Secret Service) in `docs/superpowers/plans/`.
- Scaffolded Cargo workspace (`kring-core`, `kring`), empty eframe window, and
  `scripts/check-no-gui-toolkits.sh` guard against GTK/Qt/GNOME crates.
- Added `kring-core` model types (`SecretValue` zeroized and redacted), `KringError`, and input validation.
