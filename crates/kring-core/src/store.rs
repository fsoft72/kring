//! Storage abstraction over a Secret Service provider.

use crate::error::Result;
use crate::model::{
    CollectionId, CollectionInfo, ItemId, ItemInfo, ItemUpdate, NewItem, SecretValue,
};

/// Operations available on any Secret Service provider.
#[async_trait::async_trait]
pub trait SecretStore: Send + Sync {
    /// Lists all collections.
    async fn list_collections(&self) -> Result<Vec<CollectionInfo>>;
    /// Lists the items of a collection (without secrets).
    async fn list_items(&self, collection: &CollectionId) -> Result<Vec<ItemInfo>>;
    /// Reads the secret of an item; fails with `Locked` if its collection is locked.
    async fn read_secret(&self, item: &ItemId) -> Result<SecretValue>;
    /// Creates an item in a collection and returns its id.
    async fn create_item(&self, collection: &CollectionId, item: NewItem) -> Result<ItemId>;
    /// Applies a partial update to an item.
    async fn update_item(&self, item: &ItemId, update: ItemUpdate) -> Result<()>;
    /// Deletes an item.
    async fn delete_item(&self, item: &ItemId) -> Result<()>;
    /// Resolves an alias to a collection, if set.
    async fn read_alias(&self, alias: &str) -> Result<Option<CollectionId>>;
    /// Points an alias at a collection, moving it if already set elsewhere.
    async fn set_alias(&self, alias: &str, collection: &CollectionId) -> Result<()>;
    /// Locks a collection.
    async fn lock(&self, collection: &CollectionId) -> Result<()>;
    /// Changes the label of a collection.
    async fn rename_collection(&self, collection: &CollectionId, label: &str) -> Result<()>;
    /// Deletes a collection and its items.
    async fn delete_collection(&self, collection: &CollectionId) -> Result<()>;
}

/// Master-password operations (gnome-keyring private interface).
#[async_trait::async_trait]
pub trait MasterPasswordStore: Send + Sync {
    /// Creates an unlocked collection protected by `password`.
    async fn create_with_password(
        &self,
        label: &str,
        password: &SecretValue,
    ) -> Result<CollectionId>;
    /// Unlocks a collection with its password.
    async fn unlock_with_password(
        &self,
        collection: &CollectionId,
        password: &SecretValue,
    ) -> Result<()>;
    /// Changes the password of a collection.
    async fn change_password(
        &self,
        collection: &CollectionId,
        old: &SecretValue,
        new: &SecretValue,
    ) -> Result<()>;
}
