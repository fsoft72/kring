//! Mapping of wallet entries to Secret Service transfer items.
//!
//! Two kinds of entries, told apart by the attributes JSON
//! (see [`super::attributes`]):
//!
//! * App entries: the compat layer holds a record with real attributes
//!   (`KWalletFreedesktopCollection`, `ksecretd`). They keep exactly those
//!   attributes and the `$fdo_*` dates, so apps find them again. The label is
//!   the one the daemon reports (`KWalletFreedesktopItem::label`,
//!   `FdoUniqueLabel::fromEntryLocation`): the key without its `__N_` suffix
//!   (`FdoUniqueLabel::makeName`, regex `(^.*)__(\d+)_$`), prefixed with
//!   `<folder>/` unless the folder is `Secret Service`.
//! * Native entries (no record, a synthesized one, or a record without
//!   attributes): label `<folder>/<key>` (so a native entry in the
//!   `Secret Service` folder is labelled `Secret Service/<key>`, as KWallet's
//!   own migration does) and the attributes `server=<folder>`, `user=<key>`,
//!   `type=plaintext|map|binary`, plus `kwallet-folder`, `kwallet-key`,
//!   `kwallet-type` and `xdg:schema=org.kde.KWallet.Entry`. The first three
//!   are what the kwalletd6 shim searches for native entries
//!   (`SecretServiceClient::retrieveItem`, secretserviceclient.cpp, schema
//!   `org.qt.keychain` with DONT_MATCH_NAME, so `xdg:schema` does not take
//!   part); `migrateWallet` writes the same ones and `ksecretd` synthesizes
//!   them (`KWalletFreedesktopCollection::onWalletChangeState`), so apps
//!   using the KWallet API keep finding their secrets.
//!
//! Native attributes are always derived from the entry itself, never copied
//! from a synthesized record, so the identity of an entry is stable whether or
//! not such a record exists. A record is "synthesized" when it is exactly
//! `{server: <folder>, user: <key>, type}`: that only decides between an app
//! record and a native entry. Its date is the creation time of the compat
//! collection, not the entry's, so the item gets `modified = 0`. A record
//! with no attributes is treated as native too (an empty identity would clash
//! with every other such item).
//!
//! Values: Password -> text secret, Map -> JSON object text
//! (`application/json`, keys sorted), Stream -> bytes
//! (`application/octet-stream`). Unknown entry types have no value and are
//! skipped.

use std::collections::{BTreeMap, HashMap};

use super::attributes::FdoMeta;
use super::{EntryValue, WalletEntry};
use crate::model::{Attributes, SCHEMA_ATTRIBUTE, SecretValue};
use crate::transfer::plan::{Incoming, TransferSource};

/// Folder of entries created through Secret Service (`FDO_SECRETS_DEFAULT_DIR`).
const SECRET_SERVICE_FOLDER: &str = "Secret Service";
/// Schema of native KWallet entries.
const KWALLET_ENTRY_SCHEMA: &str = "org.kde.KWallet.Entry";
/// Shim lookup attribute: wallet folder.
const ATTR_SERVER: &str = "server";
/// Shim lookup attribute: wallet key.
const ATTR_USER: &str = "user";
/// Shim lookup attribute: `plaintext`, `map` or `binary`.
const ATTR_SHIM_TYPE: &str = "type";
/// Attribute with the wallet folder of a native entry.
const ATTR_FOLDER: &str = "kwallet-folder";
/// Attribute with the wallet key of a native entry.
const ATTR_KEY: &str = "kwallet-key";
/// Attribute with the entry type of a native entry.
const ATTR_TYPE: &str = "kwallet-type";
/// Content type of a map serialized as JSON.
const JSON_CONTENT_TYPE: &str = "application/json";

/// Kind of a native entry, with its two attribute spellings.
#[derive(Clone, Copy)]
enum Kind {
    Password,
    Map,
    Stream,
}

impl Kind {
    /// Value of `kwallet-type`.
    fn kwallet_name(self) -> &'static str {
        match self {
            Kind::Password => "password",
            Kind::Map => "map",
            Kind::Stream => "stream",
        }
    }

    /// Value of the shim's `type` attribute (`SecretServiceClient::retrieveItem`).
    fn shim_name(self) -> &'static str {
        match self {
            Kind::Password => "plaintext",
            Kind::Map => "map",
            Kind::Stream => "binary",
        }
    }
}

/// Maps wallet entries to transfer items with `TransferSource::Offline(index)`.
///
/// `index` is the position in `entries`; entries of unknown type are skipped.
pub fn to_incoming(
    entries: &[WalletEntry],
    meta: &HashMap<(String, String), FdoMeta>,
) -> Vec<Incoming> {
    let mut out = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some((secret, kind)) = _secret(&entry.value) else {
            continue;
        };
        let record = meta.get(&(entry.folder.clone(), entry.key.clone()));
        let app_attributes =
            record.filter(|m| !m.attributes.is_empty() && !_is_synthesized(entry, m));
        let (label, attributes, modified) = match app_attributes {
            Some(m) => (
                _compat_label(&entry.folder, &entry.key),
                m.attributes.clone(),
                m.modified,
            ),
            None => (
                format!("{}/{}", entry.folder, entry.key),
                _native_attributes(entry, kind),
                0,
            ),
        };
        out.push(Incoming {
            source: TransferSource::Offline(index),
            label,
            attributes,
            secret,
            secret_missing: false,
            modified,
        });
    }
    out
}

/// Returns the transfer secret and the entry kind of a value, `None` for unknown types.
fn _secret(value: &EntryValue) -> Option<(SecretValue, Kind)> {
    match value {
        EntryValue::Password(s) => Some((s.clone(), Kind::Password)),
        EntryValue::Stream(s) => Some((s.clone(), Kind::Stream)),
        EntryValue::Map(pairs) => Some((_map_json(pairs), Kind::Map)),
        EntryValue::Unknown(_) => None,
    }
}

/// Serializes a map as a JSON object with sorted keys (non-UTF-8 values are lossy).
fn _map_json(pairs: &[(String, SecretValue)]) -> SecretValue {
    let sorted: BTreeMap<&str, String> = pairs
        .iter()
        .map(|(k, v)| {
            (
                k.as_str(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let json = serde_json::to_string(&sorted)
        .expect("a map of strings to strings always serializes to JSON");
    SecretValue::new(json.into_bytes(), JSON_CONTENT_TYPE)
}

/// True for the record the daemon synthesizes for a native entry
/// (exactly `server=<folder>`, `user=<key>`, `type`).
fn _is_synthesized(entry: &WalletEntry, meta: &FdoMeta) -> bool {
    let a = &meta.attributes;
    a.len() == 3
        && a.get("server") == Some(&entry.folder)
        && a.get("user") == Some(&entry.key)
        && a.contains_key("type")
}

/// Attributes of a native entry (shim lookup attributes, `kwallet-*` and the KWallet schema).
fn _native_attributes(entry: &WalletEntry, kind: Kind) -> Attributes {
    [
        (ATTR_SERVER, entry.folder.as_str()),
        (ATTR_USER, entry.key.as_str()),
        (ATTR_SHIM_TYPE, kind.shim_name()),
        (ATTR_FOLDER, entry.folder.as_str()),
        (ATTR_KEY, entry.key.as_str()),
        (ATTR_TYPE, kind.kwallet_name()),
        (SCHEMA_ATTRIBUTE, KWALLET_ENTRY_SCHEMA),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// Returns the label the compat layer reports for `<folder>/<key>`.
fn _compat_label(folder: &str, key: &str) -> String {
    let name = _strip_unique_suffix(key);
    if folder == SECRET_SERVICE_FOLDER {
        return name.to_string();
    }
    format!("{folder}/{name}")
}

/// Removes a trailing `__<digits>_` unique-name suffix (`FdoUniqueLabel`).
fn _strip_unique_suffix(key: &str) -> &str {
    let Some(body) = key.strip_suffix('_') else {
        return key;
    };
    let digits = body.len() - body.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    let Some(base) = body[..body.len() - digits].strip_suffix("__") else {
        return key;
    };
    if digits == 0 {
        return key;
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kwallet_file::{open_wallet, read_attributes};
    use crate::model::ItemId;
    use crate::transfer::plan::{Action, Existing, plan_transfer};

    /// Reads a file of the KWallet fixtures dir.
    fn _fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/kwallet")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    /// Opens the fixture wallet and maps it with its attributes JSON.
    fn _fixture_items() -> (Vec<WalletEntry>, Vec<Incoming>) {
        let entries = open_wallet(
            &_fixture("fixture.kwl"),
            &_fixture("fixture.salt"),
            &SecretValue::from_text("fixture-pw"),
        )
        .expect("open");
        let meta = read_attributes(&_fixture("fixture_attributes.json")).expect("attrs");
        let items = to_incoming(&entries, &meta);
        (entries, items)
    }

    /// Finds the item of a wallet entry.
    fn _find<'a>(
        entries: &[WalletEntry],
        items: &'a [Incoming],
        folder: &str,
        key: &str,
    ) -> &'a Incoming {
        let index = entries
            .iter()
            .position(|e| e.folder == folder && e.key == key)
            .expect("entry");
        items
            .iter()
            .find(|i| i.source == TransferSource::Offline(index))
            .expect("item")
    }

    /// Builds attributes from pairs.
    fn _attrs(pairs: &[(&str, &str)]) -> Attributes {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Compat entries keep exact attributes, dates and the daemon's label.
    #[test]
    fn compat_entries_keep_attributes() {
        let (entries, items) = _fixture_items();
        let bob = _find(&entries, &items, "Secret Service", "Fixture bob");
        assert_eq!(bob.label, "Fixture bob");
        assert_eq!(
            bob.attributes,
            _attrs(&[("service", "fixture"), ("user", "bob")])
        );
        assert_eq!(bob.modified, 1794752450);
        assert_eq!(bob.secret.as_text(), Some("fixture-secret-3"));
        let alt = _find(&entries, &items, "Secret Service", "Fixture bob__0_");
        assert_eq!(alt.label, "Fixture bob");
        assert_eq!(alt.attributes["user"], "bob-alt");
        let carol = _find(&entries, &items, "Apps", "Fixture carol");
        assert_eq!(carol.label, "Apps/Fixture carol");
        assert_eq!(
            carol.attributes,
            _attrs(&[("service", "fixture"), ("user", "carol")])
        );
        let map = _find(&entries, &items, "Secret Service", "Fixture map");
        assert_eq!(
            map.attributes,
            _attrs(&[("service", "fixture"), ("type", "map"), ("user", "dave")])
        );
    }

    /// Native entries (with or without a synthesized record) use the fallback mapping.
    #[test]
    fn native_entries_use_fallback() {
        let (entries, items) = _fixture_items();
        let want = |folder: &str, key: &str, kind: &str, shim: &str| {
            _attrs(&[
                ("server", folder),
                ("user", key),
                ("type", shim),
                ("kwallet-folder", folder),
                ("kwallet-key", key),
                ("kwallet-type", kind),
                ("xdg:schema", "org.kde.KWallet.Entry"),
            ])
        };
        let site = _find(&entries, &items, "Passwords", "site");
        assert_eq!(site.label, "Passwords/site");
        assert_eq!(
            site.attributes,
            want("Passwords", "site", "password", "plaintext")
        );
        assert_eq!(site.modified, 0);
        let form = _find(&entries, &items, "Maps", "form");
        assert_eq!(form.attributes, want("Maps", "form", "map", "map"));
        let blob = _find(&entries, &items, "Streams", "blob");
        assert_eq!(blob.label, "Streams/blob");
        assert_eq!(blob.attributes, want("Streams", "blob", "stream", "binary"));
        assert_eq!(
            blob.modified, 0,
            "synthesized record dates are not the entry's"
        );
    }

    /// Values: text, sorted JSON for maps, raw bytes for streams.
    #[test]
    fn values_are_mapped() {
        let (entries, items) = _fixture_items();
        let site = _find(&entries, &items, "Passwords", "site");
        assert_eq!(site.secret.content_type, "text/plain");
        let form = _find(&entries, &items, "Maps", "form");
        assert_eq!(form.secret.content_type, "application/json");
        assert_eq!(
            form.secret.as_text(),
            Some(r#"{"pass":"fixture-secret-2","user":"alice"}"#)
        );
        let blob = _find(&entries, &items, "Streams", "blob");
        assert_eq!(blob.secret.as_bytes(), &[0x00, 0xff, 0x10]);
        assert_eq!(blob.secret.content_type, "application/octet-stream");
        assert_eq!(items.len(), 7);
        assert!(items.iter().all(|i| !i.secret_missing));
    }

    /// Unique-name suffixes are removed only in the exact `__N_` form.
    #[test]
    fn suffix_stripping() {
        assert_eq!(_strip_unique_suffix("a__0_"), "a");
        assert_eq!(_strip_unique_suffix("a__12_"), "a");
        assert_eq!(_strip_unique_suffix("a__x_"), "a__x_");
        assert_eq!(_strip_unique_suffix("a__"), "a__");
        assert_eq!(_strip_unique_suffix("a_1_"), "a_1_");
        assert_eq!(_strip_unique_suffix("a____1_"), "a__");
        assert_eq!(_compat_label("Apps", "x__3_"), "Apps/x");
    }

    /// Unknown entry types and attribute-less records fall back or are skipped.
    #[test]
    fn edge_cases() {
        let entries = [
            WalletEntry {
                folder: "F".into(),
                key: "u".into(),
                value: EntryValue::Unknown(9),
            },
            WalletEntry {
                folder: "F".into(),
                key: "p".into(),
                value: EntryValue::Password(SecretValue::from_text("x")),
            },
        ];
        let mut meta = HashMap::new();
        meta.insert(("F".to_string(), "p".to_string()), FdoMeta::default());
        let items = to_incoming(&entries, &meta);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].source, TransferSource::Offline(1));
        assert_eq!(items[0].label, "F/p");
    }

    /// Planning the items against a target that already holds them gives only duplicates.
    #[test]
    fn replanning_is_idempotent() {
        let (_, items) = _fixture_items();
        let first = plan_transfer(&items, &[]);
        assert!(first.actions.iter().all(|a| *a == Action::Create));
        let existing: Vec<Existing> = items
            .iter()
            .enumerate()
            .map(|(i, it)| Existing {
                id: ItemId(format!("/item/{i}")),
                label: it.label.clone(),
                attributes: it.attributes.clone(),
                secret: it.secret.clone(),
                modified: it.modified,
            })
            .collect();
        let again = plan_transfer(&items, &existing);
        assert!(
            again
                .actions
                .iter()
                .all(|a| matches!(a, Action::Duplicate { .. })),
            "{:?}",
            again.actions
        );
    }
}
