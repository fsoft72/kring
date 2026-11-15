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
//! * Native entries (no record, or only a synthesized one): label
//!   `<folder>/<key>` and the attributes `kwallet-folder`, `kwallet-key`,
//!   `kwallet-type` and `xdg:schema=org.kde.KWallet.Entry`.
//!
//! Synthesized records (`KWalletFreedesktopCollection::onWalletChangeState`)
//! are `{server: <folder>, user: <key>, type: plaintext|map|binary}` and no
//! mime type. The daemon invents them only to expose a native entry over
//! Secret Service; no app stored them, so they are NOT kept as attributes
//! (the native mapping is used, which also keeps the identity of an entry
//! stable whether or not such a record exists). Their dates are still used.
//! A record with no attributes is treated like a native entry too, since an
//! empty identity would clash with every other such item.
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
/// Attribute with the wallet folder of a native entry.
const ATTR_FOLDER: &str = "kwallet-folder";
/// Attribute with the wallet key of a native entry.
const ATTR_KEY: &str = "kwallet-key";
/// Attribute with the entry type of a native entry.
const ATTR_TYPE: &str = "kwallet-type";
/// Content type of a map serialized as JSON.
const JSON_CONTENT_TYPE: &str = "application/json";

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
        let app_attributes = record
            .filter(|m| !m.attributes.is_empty() && !_is_synthesized(entry, m))
            .map(|m| m.attributes.clone());
        let (label, attributes) = match app_attributes {
            Some(attributes) => (_compat_label(&entry.folder, &entry.key), attributes),
            None => (
                format!("{}/{}", entry.folder, entry.key),
                _native_attributes(entry, kind),
            ),
        };
        out.push(Incoming {
            source: TransferSource::Offline(index),
            label,
            attributes,
            secret,
            secret_missing: false,
            modified: record.map_or(0, |m| m.modified),
        });
    }
    out
}

/// Returns the transfer secret and the `kwallet-type` name of a value, `None` for unknown types.
fn _secret(value: &EntryValue) -> Option<(SecretValue, &'static str)> {
    match value {
        EntryValue::Password(s) => Some((s.clone(), "password")),
        EntryValue::Stream(s) => Some((s.clone(), "stream")),
        EntryValue::Map(pairs) => Some((_map_json(pairs), "map")),
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
    let json = serde_json::to_string(&sorted).unwrap_or_else(|_| "{}".to_string());
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

/// Attributes of a native entry (`kwallet-*` plus the KWallet schema).
fn _native_attributes(entry: &WalletEntry, kind: &str) -> Attributes {
    [
        (ATTR_FOLDER, entry.folder.as_str()),
        (ATTR_KEY, entry.key.as_str()),
        (ATTR_TYPE, kind),
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
        let want = |folder: &str, key: &str, kind: &str| {
            _attrs(&[
                ("kwallet-folder", folder),
                ("kwallet-key", key),
                ("kwallet-type", kind),
                ("xdg:schema", "org.kde.KWallet.Entry"),
            ])
        };
        let site = _find(&entries, &items, "Passwords", "site");
        assert_eq!(site.label, "Passwords/site");
        assert_eq!(site.attributes, want("Passwords", "site", "password"));
        assert_eq!(site.modified, 0);
        let form = _find(&entries, &items, "Maps", "form");
        assert_eq!(form.attributes, want("Maps", "form", "map"));
        let blob = _find(&entries, &items, "Streams", "blob");
        assert_eq!(blob.label, "Streams/blob");
        assert_eq!(blob.attributes, want("Streams", "blob", "stream"));
        assert_eq!(
            blob.modified, 1794752450,
            "synthesized record keeps its date"
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
