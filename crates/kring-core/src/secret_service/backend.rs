//! [`SecretStore`] implementation over the standard Secret Service D-Bus API.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use oo7::dbus::{Collection, Item, Service, api};
use oo7::zbus;
use oo7::{ContentType, Secret};

use super::errors::{map_dbus, map_zbus};
use crate::error::{KringError, Result};
use crate::model::{
    CollectionId, CollectionInfo, ItemId, ItemInfo, ItemUpdate, NewItem, SecretValue,
    is_login_collection,
};
use crate::store::SecretStore;

/// Aliases that are resolved for every collection in `list_collections`.
const KNOWN_ALIASES: [&str; 3] = ["default", "session", "login"];

/// How many times listing items is attempted when an item vanishes mid-listing.
const ITEM_LIST_ATTEMPTS: u32 = 3;

/// Secret Service backend talking to the session bus with an encrypted session.
pub struct SecretServiceBackend {
    connection: zbus::Connection,
    service: Service,
    api_service: api::Service,
}

impl SecretServiceBackend {
    /// Connects to the session bus and opens an encrypted Secret Service session.
    pub async fn connect() -> Result<Self> {
        let connection = zbus::Connection::session()
            .await
            .map_err(|e| map_zbus("connecting to the session bus", e))?;
        let service = Service::encrypted_with_connection(&connection)
            .await
            .map_err(|e| map_dbus("opening an encrypted session", e))?;
        let api_service = api::Service::new(&connection)
            .await
            .map_err(|e| map_dbus("opening the Secret Service API", e))?;
        Ok(Self {
            connection,
            service,
            api_service,
        })
    }

    /// Returns the underlying D-Bus connection.
    pub fn connection(&self) -> &zbus::Connection {
        &self.connection
    }

    /// Finds a collection by object path.
    async fn find_collection(&self, id: &CollectionId) -> Result<Collection> {
        let collections = self
            .service
            .collections()
            .await
            .map_err(|e| map_dbus("listing collections", e))?;
        collections
            .into_iter()
            .find(|c| c.path().as_str() == id.0)
            .ok_or_else(|| KringError::NotFound(id.0.clone()))
    }

    /// Finds an item by object path; its parent path is the collection path.
    async fn find_item(&self, id: &ItemId) -> Result<Item> {
        let (parent, _) =
            id.0.rsplit_once('/')
                .ok_or_else(|| KringError::NotFound(id.0.clone()))?;
        let collection = self
            .find_collection(&CollectionId(parent.to_string()))
            .await?;
        let items = collection_items(&collection).await?;
        items
            .into_iter()
            .find(|i| i.path().as_str() == id.0)
            .ok_or_else(|| KringError::NotFound(id.0.clone()))
    }

    /// Reads the items of a collection once.
    async fn read_items(&self, collection: &CollectionId) -> Result<Vec<ItemInfo>> {
        let ctx = "reading an item";
        let items = collection_items(&self.find_collection(collection).await?).await?;
        let mut out = Vec::with_capacity(items.len());
        for i in items {
            out.push(ItemInfo {
                id: ItemId(i.path().to_string()),
                collection: collection.clone(),
                label: i.label().await.map_err(|e| map_dbus(ctx, e))?,
                attributes: i
                    .attributes()
                    .await
                    .map_err(|e| map_dbus(ctx, e))?
                    .into_iter()
                    .collect(),
                locked: i.is_locked().await.map_err(|e| map_dbus(ctx, e))?,
                created: secs(i.created().await.map_err(|e| map_dbus(ctx, e))?),
                modified: secs(i.modified().await.map_err(|e| map_dbus(ctx, e))?),
            });
        }
        Ok(out)
    }

    /// Resolves the object paths of the well-known aliases, paired with their names.
    async fn resolve_aliases(&self) -> Result<Vec<(&'static str, String)>> {
        let mut resolved = Vec::new();
        for alias in KNOWN_ALIASES {
            let found = self
                .api_service
                .read_alias(alias)
                .await
                .map_err(|e| map_dbus("reading an alias", e))?;
            if let Some(collection) = found {
                resolved.push((alias, collection.inner().path().to_string()));
            }
        }
        Ok(resolved)
    }
}

/// Lists the items of a collection (single attempt).
async fn collection_items(collection: &Collection) -> Result<Vec<Item>> {
    collection
        .items()
        .await
        .map_err(|e| map_dbus("listing items", e))
}

/// Converts a D-Bus duration to unix seconds.
fn secs(d: Duration) -> u64 {
    d.as_secs()
}

/// Builds an oo7 secret from a [`SecretValue`], honouring its content type.
fn to_oo7_secret(value: &SecretValue) -> Result<Secret> {
    let content_type = ContentType::from_str(&value.content_type).map_err(|_| {
        KringError::InvalidInput(format!("unsupported content type {}", value.content_type))
    })?;
    Ok(Secret::with_content_type(content_type, value.as_bytes()))
}

#[async_trait::async_trait]
impl SecretStore for SecretServiceBackend {
    /// Lists collections with their aliases and item counts.
    async fn list_collections(&self) -> Result<Vec<CollectionInfo>> {
        let aliases = self.resolve_aliases().await?;
        let collections = self
            .service
            .collections()
            .await
            .map_err(|e| map_dbus("listing collections", e))?;
        let mut out = Vec::with_capacity(collections.len());
        for c in collections {
            let ctx = "reading a collection";
            let path = c.path().to_string();
            let id = CollectionId(path.clone());
            out.push(CollectionInfo {
                label: c.label().await.map_err(|e| map_dbus(ctx, e))?,
                locked: c.is_locked().await.map_err(|e| map_dbus(ctx, e))?,
                item_count: c.items().await.map_err(|e| map_dbus(ctx, e))?.len(),
                aliases: aliases
                    .iter()
                    .filter(|(_, p)| *p == path)
                    .map(|(a, _)| a.to_string())
                    .collect(),
                is_login: is_login_collection(&id),
                created: secs(c.created().await.map_err(|e| map_dbus(ctx, e))?),
                modified: secs(c.modified().await.map_err(|e| map_dbus(ctx, e))?),
                id,
            });
        }
        Ok(out)
    }

    /// Lists the items of a collection (without secrets).
    ///
    /// Retries when an item vanishes mid-listing: the `Items` property can briefly list
    /// an object that another client has just deleted.
    async fn list_items(&self, collection: &CollectionId) -> Result<Vec<ItemInfo>> {
        let mut attempt = 1;
        loop {
            match self.read_items(collection).await {
                Err(KringError::NotFound(_)) if attempt < ITEM_LIST_ATTEMPTS => attempt += 1,
                other => return other,
            }
        }
    }

    /// Reads a secret, failing with `Locked` (no prompt) when the item is locked.
    async fn read_secret(&self, item: &ItemId) -> Result<SecretValue> {
        let found = self.find_item(item).await?;
        if found
            .is_locked()
            .await
            .map_err(|e| map_dbus("checking item lock state", e))?
        {
            return Err(KringError::Locked(item.0.clone()));
        }
        let secret = found
            .secret()
            .await
            .map_err(|e| map_dbus("reading a secret", e))?;
        Ok(SecretValue::new(
            secret.as_bytes().to_vec(),
            secret.content_type().as_str(),
        ))
    }

    /// Creates an item (without prompting) and returns its object path.
    async fn create_item(&self, collection: &CollectionId, item: NewItem) -> Result<ItemId> {
        let found = self.find_collection(collection).await?;
        if found
            .is_locked()
            .await
            .map_err(|e| map_dbus("checking collection lock state", e))?
        {
            return Err(KringError::Locked(collection.0.clone()));
        }
        let secret = to_oo7_secret(&item.secret)?;
        let attributes: HashMap<String, String> = item.attributes.into_iter().collect();
        let created = found
            .create_item(&item.label, &attributes, secret, item.replace, None)
            .await
            .map_err(|e| map_dbus("creating an item", e))?;
        Ok(ItemId(created.path().to_string()))
    }

    /// Applies a partial update to an item.
    async fn update_item(&self, item: &ItemId, update: ItemUpdate) -> Result<()> {
        let found = self.find_item(item).await?;
        if found
            .is_locked()
            .await
            .map_err(|e| map_dbus("checking item lock state", e))?
        {
            return Err(KringError::Locked(item.0.clone()));
        }
        let ctx = "updating an item";
        if let Some(label) = update.label {
            found
                .set_label(&label)
                .await
                .map_err(|e| map_dbus(ctx, e))?;
        }
        if let Some(attributes) = update.attributes {
            let attributes: HashMap<String, String> = attributes.into_iter().collect();
            found
                .set_attributes(&attributes)
                .await
                .map_err(|e| map_dbus(ctx, e))?;
        }
        if let Some(secret) = update.secret {
            found
                .set_secret(to_oo7_secret(&secret)?)
                .await
                .map_err(|e| map_dbus(ctx, e))?;
        }
        Ok(())
    }

    /// Deletes an item.
    async fn delete_item(&self, item: &ItemId) -> Result<()> {
        let found = self.find_item(item).await?;
        if found
            .is_locked()
            .await
            .map_err(|e| map_dbus("checking item lock state", e))?
        {
            return Err(KringError::Locked(item.0.clone()));
        }
        found
            .delete(None)
            .await
            .map_err(|e| map_dbus("deleting an item", e))
    }

    /// Resolves an alias to a collection, if set.
    async fn read_alias(&self, alias: &str) -> Result<Option<CollectionId>> {
        let found = self
            .api_service
            .read_alias(alias)
            .await
            .map_err(|e| map_dbus("reading an alias", e))?;
        Ok(found.map(|c| CollectionId(c.inner().path().to_string())))
    }

    /// Points an alias at a collection.
    async fn set_alias(&self, alias: &str, collection: &CollectionId) -> Result<()> {
        let target = api::Collection::new(&self.connection, collection.0.clone())
            .await
            .map_err(|e| map_dbus("resolving a collection", e))?;
        self.api_service
            .set_alias(alias, &target)
            .await
            .map_err(|e| map_dbus("setting an alias", e))
    }

    /// Locks a collection.
    async fn lock(&self, collection: &CollectionId) -> Result<()> {
        self.find_collection(collection)
            .await?
            .lock(None)
            .await
            .map_err(|e| map_dbus("locking a collection", e))
    }

    /// Changes the label of a collection.
    async fn rename_collection(&self, collection: &CollectionId, label: &str) -> Result<()> {
        self.find_collection(collection)
            .await?
            .set_label(label)
            .await
            .map_err(|e| map_dbus("renaming a collection", e))
    }

    /// Deletes a collection and its items.
    async fn delete_collection(&self, collection: &CollectionId) -> Result<()> {
        self.find_collection(collection)
            .await?
            .delete(None)
            .await
            .map_err(|e| map_dbus("deleting a collection", e))
    }
}
