# KWallet fixtures

Real wallet files written by the KWallet daemon (`ksecretd` from kwallet 6.20)
in an isolated session. They are not produced by any kring encoder.

| File | Content |
| --- | --- |
| `fixture.kwl` | Wallet `fixture`, header `KWALLET\n\r\0\r\n` + `00 01 03 02` (version 0.1, cipher 3 = Blowfish CBC, hash 2 = PBKDF2-SHA512) |
| `fixture.salt` | 56 random bytes (PBKDF2 salt) |
| `fixture_attributes.json` | Secret Service compat layer metadata, written by the daemon |

Wallet password: `fixture-pw`.

## Regenerate

```sh
cargo build -p kring-core --example make_kwallet_fixture
scripts/kwallet-session.sh "$PWD/target/debug/examples/make_kwallet_fixture"
```

`scripts/kwallet-session.sh` runs a private `dbus-run-session` with a temp
`HOME` / `XDG_*` (including `XDG_CONFIG_DIRS`) and starts `ksecretd` with
`QT_QPA_PLATFORM=offscreen`, no display needed. The example refuses to run
outside that session (`dev_guard`). A new run produces a new random salt and
new timestamps, so the expected values in the tests stay valid but the bytes
change.

Why `ksecretd` and not `kwalletd6`: in kwallet 6.20 `kwalletd6` is only a
KWallet-API shim that forwards to whatever provides `org.freedesktop.secrets`
(`src/runtime/kwalletd/main.cpp`: "A KWallet compatibility service, wrapping
upon Secret Service"). The daemon that reads and writes `.kwl` files, and the
one behind the user's `~/.local/share/kwalletd` wallets, is `ksecretd`
(`src/runtime/ksecretd`): bus names `org.kde.ksecretd` (object `/ksecretd`,
interface `org.kde.KWallet`), `org.freedesktop.secrets` and
`org.kde.secretservicecompat`.

## How the example builds the wallet

1. Writes `fixture.salt` (56 random bytes) and derives the key
   PBKDF2-HMAC-SHA512(`fixture-pw`, salt, 50000 iterations, 56 bytes), as
   `KWallet::Backend::setPassword` / `password2PBKDF2_SHA512` and `pam_kwallet`
   do (`kwalletbackend.h`: `PBKDF2_SHA512_KEYSIZE` 56, `PBKDF2_SHA512_SALTSIZE`
   56, `PBKDF2_SHA512_ITERATIONS` 50000).
2. `pamOpen("fixture", key, 0)` creates the wallet with that key, no dialog
   (`KSecretD::pamOpen` -> `Backend::openPreHashed`).
3. `open("fixture", 0, appid)` returns a handle (no prompt: the wallet is
   already open and `Prompt on Open=false`).
4. Native entries through `org.kde.KWallet`:
   - `Passwords/site`: password `fixture-secret-1` (`writePassword`)
   - `Maps/form`: map `{pass: fixture-secret-2, user: alice}` (`writeMap`, bytes
     are a Qt 6 `QDataStream` `QMap<QString,QString>`: quint32 count, then
     key/value `QString`s (quint32 byte length + UTF-16BE) in ascending key order)
   - `Streams/blob`: stream bytes `00 ff 10` (`writeEntry` with type 2)
5. Unlocks the compat collection `/org/freedesktop/secrets/collection/fixture`
   (Secret Service `Unlock` + `Prompt`; completes without a dialog because the
   wallet is open) and creates 4 text items through the Secret Service API.
6. Cross-check: reads back `Secret Service/Fixture map` (encoded by Qt itself
   from the JSON secret) and requires it to equal the example's own `QMap`
   encoding of the same map, so the native map bytes are genuine Qt bytes.
7. `close(handle, true, appid)` (forced close saves the wallet) and copies the
   3 files here.

Verified independently: with a Python `hashlib.pbkdf2_hmac` key the daemon opens
the committed wallet (a wrong password does not) and returns every entry above.

## Entries

| Folder | Key | Type | Value | fdo label | fdo attributes |
| --- | --- | --- | --- | --- | --- |
| `Passwords` | `site` | Password (1) | `fixture-secret-1` | `Passwords/site` | none in the JSON (see below) |
| `Maps` | `form` | Map (3) | `{pass: fixture-secret-2, user: alice}` | `Maps/form` | none in the JSON |
| `Streams` | `blob` | Stream (2) | `00 ff 10` | `Streams/blob` | synthesized `{server: Streams, type: binary, user: blob}` |
| `Secret Service` | `Fixture bob` | Password | `fixture-secret-3` | `Fixture bob` | `{service: fixture, user: bob}` |
| `Secret Service` | `Fixture bob__0_` | Password | `fixture-secret-5` | `Fixture bob` | `{service: fixture, user: bob-alt}` |
| `Apps` | `Fixture carol` | Password | `fixture-secret-4` | `Apps/Fixture carol` | `{service: fixture, user: carol}` |
| `Secret Service` | `Fixture map` | Map | `{pass: fixture-secret-6, user: dave}` | `Fixture map` | `{service: fixture, type: map, user: dave}` |

## How the compat layer labels entries (for the mapping)

From `src/runtime/ksecretd/kwalletfreedesktop*.cpp` and checked on the bus with
this fixture:

- Folder/key from the fdo label (`KWalletFreedesktopCollection::makeUniqueEntryLocation`):
  a label without `/` (or ending in `/`) goes to folder `Secret Service`
  (`FDO_SECRETS_DEFAULT_DIR`) with key = label; `dir/name` goes to folder `dir`,
  key `name` (split at the first `/`).
- A key already taken gets the suffix `__N_` (N = 0, 1, ...;
  `FdoUniqueLabel::makeName`, regex `(^.*)__(\d+)_$`).
- The fdo `Label` the daemon reports (`KWalletFreedesktopItem::label`) is the
  key without the `__N_` suffix, prefixed with `<folder>/` unless the folder is
  `Secret Service` (`FdoUniqueLabel::fromEntryLocation`). So the original fdo
  label of a compat entry is: `key` minus `__N_` for `Secret Service`, else
  `folder/key` minus `__N_`.
- Secret type (`KWalletFreedesktopCollection::CreateItem`): attribute
  `type=map` -> Map entry (JSON object secret converted to a `QMap`);
  `xdg:schema=org.kde.KWallet.Password` or a `text/*` content type -> Password;
  anything else -> Stream.

## Attributes JSON shape (`KWalletFreedesktopAttributes`)

- Path: `<data dir>/kwalletd/<wallet>_attributes.json` (Qt `toJson`, indented).
- Root object: `$fdo_created`, `$fdo_modified` (seconds since epoch, as decimal
  strings) and one key per entry, `"<folder>/<key>"` (flat, not nested; split at
  the first `/`, so a folder never contains `/` but a key may).
- Entry object: `$fdo_created`, `$fdo_modified` (decimal strings),
  `$fdo_mime_type` (only for items created through the fdo API; `text/plain`
  here because oo7 sends text secrets as `text/plain`) and `attributes`
  (string map; omitted when empty).
- Native entries get a record only when the compat collection is unlocked
  while they have no fdo item yet (`KWalletFreedesktopCollection::onWalletChangeState`):
  synthesized attributes `{server: <folder>, user: <key>, type: plaintext|map|binary}`
  and no `$fdo_mime_type`. `writePassword` / `writeMap` / `writeEntry` without
  a type emit `entryUpdated`, which creates an in-memory fdo item without a
  JSON record; `writeEntry` with an explicit type does not. That is why only
  `Streams/blob` has a synthesized record in this fixture, and why a real
  wallet may hold such records for native entries. Synthesized records are
  not original app attributes: they have exactly the keys `server`, `user`,
  `type` with `server` = folder and `user` = key.
