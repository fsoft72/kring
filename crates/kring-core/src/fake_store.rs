//! In-memory store used by tests and UI development.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{KringError, Result};
use crate::model::{
    CollectionId, CollectionInfo, ItemId, ItemInfo, ItemUpdate, NewItem, SecretValue, is_login_collection,
};
use crate::store::{MasterPasswordStore, SecretStore};

/// Object path prefix of collections.
const COLLECTION_PREFIX: &str = "/org/freedesktop/secrets/collection/";

/// A stored collection with its password.
struct FakeCollection {
    id: CollectionId,
    label: String,
    password: Vec<u8>,
    locked: bool,
    created: u64,
    modified: u64,
}

/// A stored item with its secret.
struct FakeItem {
    info: ItemInfo,
    secret: SecretValue,
}

/// Mutable state behind the store mutex.
#[derive(Default)]
struct State {
    collections: Vec<FakeCollection>,
    items: Vec<FakeItem>,
    aliases: BTreeMap<String, CollectionId>,
    next_item: u64,
}

/// In-memory implementation of [`SecretStore`] and [`MasterPasswordStore`].
#[derive(Default)]
pub struct FakeStore {
    state: Mutex<State>,
}

/// Returns the current unix time in seconds.
fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Builds a `NotFound` error for an object path.
fn not_found(path: &str) -> KringError {
    KringError::NotFound(path.to_string())
}

impl State {
    /// Finds a collection by id.
    fn collection(&self, id: &CollectionId) -> Result<&FakeCollection> {
        self.collections.iter().find(|c| &c.id == id).ok_or_else(|| not_found(&id.0))
    }

    /// Finds a collection by id, mutably.
    fn collection_mut(&mut self, id: &CollectionId) -> Result<&mut FakeCollection> {
        self.collections.iter_mut().find(|c| &c.id == id).ok_or_else(|| not_found(&id.0))
    }

    /// Fails with `Locked` unless the collection exists and is unlocked.
    fn require_unlocked(&self, id: &CollectionId) -> Result<()> {
        if self.collection(id)?.locked {
            return Err(KringError::Locked(id.0.clone()));
        }
        Ok(())
    }

    /// Returns the index of an item by id.
    fn item_index(&self, id: &ItemId) -> Result<usize> {
        self.items.iter().position(|i| &i.info.id == id).ok_or_else(|| not_found(&id.0))
    }

    /// Adds a collection, making its path unique, and returns its id.
    fn add_collection(&mut self, label: &str, password: &str, locked: bool) -> CollectionId {
        let mut path = format!("{COLLECTION_PREFIX}{label}");
        let mut n = 1;
        while self.collections.iter().any(|c| c.id.0 == path) {
            n += 1;
            path = format!("{COLLECTION_PREFIX}{label}_{n}");
        }
        let id = CollectionId(path);
        let ts = now();
        self.collections.push(FakeCollection {
            id: id.clone(),
            label: label.to_string(),
            password: password.as_bytes().to_vec(),
            locked,
            created: ts,
            modified: ts,
        });
        id
    }
}

impl FakeStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a collection with the given password and lock state; returns its id.
    pub fn add_collection(&self, label: &str, password: &str, locked: bool) -> CollectionId {
        self.state().add_collection(label, password, locked)
    }

    /// Locks the state mutex, tolerating poisoning.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl SecretStore for FakeStore {
    /// Lists collections with item counts and aliases.
    async fn list_collections(&self) -> Result<Vec<CollectionInfo>> {
        let s = self.state();
        Ok(s.collections
            .iter()
            .map(|c| CollectionInfo {
                id: c.id.clone(),
                label: c.label.clone(),
                locked: c.locked,
                item_count: s.items.iter().filter(|i| i.info.collection == c.id).count(),
                aliases: s.aliases.iter().filter(|(_, v)| **v == c.id).map(|(k, _)| k.clone()).collect(),
                is_login: is_login_collection(&c.id),
                created: c.created,
                modified: c.modified,
            })
            .collect())
    }

    /// Lists items; they report `locked` when their collection is locked.
    async fn list_items(&self, collection: &CollectionId) -> Result<Vec<ItemInfo>> {
        let s = self.state();
        let locked = s.collection(collection)?.locked;
        Ok(s.items
            .iter()
            .filter(|i| &i.info.collection == collection)
            .map(|i| ItemInfo { locked, ..i.info.clone() })
            .collect())
    }

    /// Reads a secret from an unlocked collection.
    async fn read_secret(&self, item: &ItemId) -> Result<SecretValue> {
        let s = self.state();
        let entry = &s.items[s.item_index(item)?];
        s.require_unlocked(&entry.info.collection)?;
        Ok(entry.secret.clone())
    }

    /// Creates an item, replacing one with identical attributes when asked.
    async fn create_item(&self, collection: &CollectionId, item: NewItem) -> Result<ItemId> {
        let mut s = self.state();
        s.require_unlocked(collection)?;
        let ts = now();
        let existing = item
            .replace
            .then(|| s.items.iter().position(|i| &i.info.collection == collection && i.info.attributes == item.attributes))
            .flatten();
        if let Some(idx) = existing {
            let entry = &mut s.items[idx];
            entry.info.label = item.label;
            entry.info.modified = ts;
            entry.secret = item.secret;
            return Ok(entry.info.id.clone());
        }
        s.next_item += 1;
        let id = ItemId(format!("{}/{}", collection.0, s.next_item));
        let info = ItemInfo {
            id: id.clone(),
            collection: collection.clone(),
            label: item.label,
            attributes: item.attributes,
            locked: false,
            created: ts,
            modified: ts,
        };
        s.items.push(FakeItem { info, secret: item.secret });
        s.collection_mut(collection)?.modified = ts;
        Ok(id)
    }

    /// Applies a partial update to an item of an unlocked collection.
    async fn update_item(&self, item: &ItemId, update: ItemUpdate) -> Result<()> {
        let mut s = self.state();
        let idx = s.item_index(item)?;
        let collection = s.items[idx].info.collection.clone();
        s.require_unlocked(&collection)?;
        let entry = &mut s.items[idx];
        if let Some(label) = update.label {
            entry.info.label = label;
        }
        if let Some(attributes) = update.attributes {
            entry.info.attributes = attributes;
        }
        if let Some(secret) = update.secret {
            entry.secret = secret;
        }
        entry.info.modified = now();
        Ok(())
    }

    /// Deletes an item from an unlocked collection.
    async fn delete_item(&self, item: &ItemId) -> Result<()> {
        let mut s = self.state();
        let idx = s.item_index(item)?;
        let collection = s.items[idx].info.collection.clone();
        s.require_unlocked(&collection)?;
        s.items.remove(idx);
        Ok(())
    }

    /// Resolves an alias.
    async fn read_alias(&self, alias: &str) -> Result<Option<CollectionId>> {
        Ok(self.state().aliases.get(alias).cloned())
    }

    /// Points an alias at a collection.
    async fn set_alias(&self, alias: &str, collection: &CollectionId) -> Result<()> {
        let mut s = self.state();
        s.collection(collection)?;
        s.aliases.insert(alias.to_string(), collection.clone());
        Ok(())
    }

    /// Locks a collection.
    async fn lock(&self, collection: &CollectionId) -> Result<()> {
        self.state().collection_mut(collection)?.locked = true;
        Ok(())
    }

    /// Renames a collection.
    async fn rename_collection(&self, collection: &CollectionId, label: &str) -> Result<()> {
        let mut s = self.state();
        let c = s.collection_mut(collection)?;
        c.label = label.to_string();
        c.modified = now();
        Ok(())
    }

    /// Deletes a collection, its items and any alias pointing to it.
    async fn delete_collection(&self, collection: &CollectionId) -> Result<()> {
        let mut s = self.state();
        s.collection(collection)?;
        s.collections.retain(|c| &c.id != collection);
        s.items.retain(|i| &i.info.collection != collection);
        s.aliases.retain(|_, v| v != collection);
        Ok(())
    }
}

#[async_trait::async_trait]
impl MasterPasswordStore for FakeStore {
    /// Creates an unlocked collection protected by `password`.
    async fn create_with_password(&self, label: &str, password: &SecretValue) -> Result<CollectionId> {
        let text = password.as_text().ok_or_else(|| KringError::InvalidInput("password must be UTF-8".into()))?;
        Ok(self.state().add_collection(label, text, false))
    }

    /// Unlocks a collection when the password matches.
    async fn unlock_with_password(&self, collection: &CollectionId, password: &SecretValue) -> Result<()> {
        let mut s = self.state();
        let c = s.collection_mut(collection)?;
        if c.password != password.as_bytes() {
            return Err(KringError::Dbus { context: "unlock".into(), message: "invalid password".into() });
        }
        c.locked = false;
        Ok(())
    }

    /// Changes the password when `old` matches.
    async fn change_password(&self, collection: &CollectionId, old: &SecretValue, new: &SecretValue) -> Result<()> {
        let mut s = self.state();
        let c = s.collection_mut(collection)?;
        if c.password != old.as_bytes() {
            return Err(KringError::Dbus { context: "change_password".into(), message: "invalid password".into() });
        }
        c.password = new.as_bytes().to_vec();
        c.modified = now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::KringError;
    use crate::model::{Attributes, NewItem, SecretValue};
    use crate::store::{MasterPasswordStore, SecretStore};

    /// Builds a new item with one attribute.
    fn new_item(label: &str, secret: &str) -> NewItem {
        let mut attributes = Attributes::new();
        attributes.insert("k".into(), label.into());
        NewItem { label: label.into(), attributes, secret: SecretValue::from_text(secret), replace: false }
    }

    /// A locked collection refuses to reveal secrets.
    #[tokio::test]
    async fn locked_collection_hides_secret() {
        let store = FakeStore::new();
        let c = store.add_collection("a", "pw", false);
        let id = store.create_item(&c, new_item("x", "s3")).await.unwrap();
        assert_eq!(store.read_secret(&id).await.unwrap().as_bytes(), b"s3");
        store.lock(&c).await.unwrap();
        assert!(matches!(store.read_secret(&id).await, Err(KringError::Locked(_))));
    }

    /// A wrong password gives a D-Bus unlock error.
    #[tokio::test]
    async fn unlock_with_wrong_password_fails() {
        let store = FakeStore::new();
        let c = store.add_collection("a", "pw", true);
        let err = store.unlock_with_password(&c, &SecretValue::from_text("bad")).await.unwrap_err();
        assert!(matches!(err, KringError::Dbus { ref context, .. } if context == "unlock"));
        store.unlock_with_password(&c, &SecretValue::from_text("pw")).await.unwrap();
        assert!(!store.list_collections().await.unwrap()[0].locked);
    }

    /// Setting an alias moves it from the previous collection.
    #[tokio::test]
    async fn set_alias_moves_default() {
        let store = FakeStore::new();
        let a = store.add_collection("a", "pw", false);
        let b = store.add_collection("b", "pw", false);
        store.set_alias("default", &a).await.unwrap();
        store.set_alias("default", &b).await.unwrap();
        assert_eq!(store.read_alias("default").await.unwrap(), Some(b));
        let cols = store.list_collections().await.unwrap();
        let info_a = cols.iter().find(|c| c.id == a).unwrap();
        assert!(!info_a.aliases.contains(&"default".to_string()));
    }

    /// Deleting an unknown item is NotFound.
    #[tokio::test]
    async fn delete_unknown_item_is_not_found() {
        let store = FakeStore::new();
        let err = store.delete_item(&ItemId("/nope/1".into())).await.unwrap_err();
        assert!(matches!(err, KringError::NotFound(_)));
    }

    /// Replace semantics, locked writes, password change and alias cleanup.
    #[tokio::test]
    async fn replace_locked_password_and_alias_cleanup() {
        let store = FakeStore::new();
        let c = store.add_collection("a", "pw", false);
        let first = store.create_item(&c, new_item("x", "one")).await.unwrap();
        let mut again = new_item("x", "two");
        again.replace = true;
        let second = store.create_item(&c, again).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(store.read_secret(&second).await.unwrap().as_bytes(), b"two");
        store.create_item(&c, new_item("x", "three")).await.unwrap();
        assert_eq!(store.list_items(&c).await.unwrap().len(), 2);
        assert_eq!(store.list_collections().await.unwrap()[0].item_count, 2);

        let wrong = SecretValue::from_text("nope");
        let new_pw = SecretValue::from_text("pw2");
        let err = store.change_password(&c, &wrong, &new_pw).await.unwrap_err();
        assert!(matches!(err, KringError::Dbus { ref context, .. } if context == "change_password"));
        store.change_password(&c, &SecretValue::from_text("pw"), &new_pw).await.unwrap();

        store.lock(&c).await.unwrap();
        assert!(store.list_items(&c).await.unwrap().iter().all(|i| i.locked));
        assert!(matches!(store.create_item(&c, new_item("y", "z")).await, Err(KringError::Locked(_))));
        assert!(matches!(store.update_item(&first, ItemUpdate::default()).await, Err(KringError::Locked(_))));

        store.set_alias("default", &c).await.unwrap();
        store.delete_collection(&c).await.unwrap();
        assert_eq!(store.read_alias("default").await.unwrap(), None);
        assert!(store.list_collections().await.unwrap().is_empty());
    }
}
