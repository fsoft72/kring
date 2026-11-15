//! [`MasterPasswordStore`] implementation over gnome-keyring's private D-Bus interface.
//!
//! gnome-keyring exposes `org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface`,
//! which creates, unlocks and re-keys collections from a master password sent as an
//! encrypted Secret Service secret, without showing a system prompt.

use std::sync::Arc;

use oo7::dbus::api::{DBusSecret, Properties, Session};
use oo7::zbus;
use oo7::zbus::proxy::CacheProperties;
use oo7::zbus::{ObjectPath, OwnedObjectPath};
use oo7::{Key, Secret};

use super::backend::SecretServiceBackend;
use super::errors::{map_dbus, map_zbus};
use crate::error::{KringError, Result};
use crate::model::{CollectionId, SecretValue};
use crate::store::MasterPasswordStore;

/// Bus name the private interface is called on.
const DESTINATION: &str = "org.freedesktop.secrets";
/// Object path of the service implementing the private interface.
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
/// gnome-keyring private interface name.
const PRIVATE_INTERFACE: &str = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface";
/// Method creating a collection protected by a master password.
const METHOD_CREATE: &str = "CreateWithMasterPassword";
/// Method unlocking a collection with its master password.
const METHOD_UNLOCK: &str = "UnlockWithMasterPassword";
/// Method changing the master password of a collection.
const METHOD_CHANGE: &str = "ChangeWithMasterPassword";
/// Error context for collection creation.
const CTX_CREATE: &str = "create";
/// Error context for unlocking.
const CTX_UNLOCK: &str = "unlock";
/// Error context for changing a password.
const CTX_CHANGE: &str = "change_password";

/// A dedicated encrypted Secret Service session used to transfer master passwords.
struct EncryptedSession {
    session: Arc<Session>,
    aes_key: Key,
}

impl EncryptedSession {
    /// Opens a `dh-ietf1024-sha256-aes128-cbc-pkcs7` session and derives its AES key.
    async fn open(backend: &SecretServiceBackend, context: &str) -> Result<Self> {
        let private_key = Key::generate_private_key().map_err(|e| crypto_error(context, e))?;
        let public_key =
            Key::generate_public_key(&private_key).map_err(|e| crypto_error(context, e))?;
        let (server_key, session) = backend
            .api_service()
            .open_session(Some(public_key))
            .await
            .map_err(|e| map_dbus(context, e))?;
        let session = Arc::new(session);
        let Some(server_key) = server_key else {
            close_quietly(&session).await;
            return Err(KringError::Dbus {
                context: context.to_string(),
                message: "the service did not return a session public key".to_string(),
            });
        };
        let aes_key = match Key::generate_aes_key(&private_key, &server_key) {
            Ok(key) => key,
            Err(e) => {
                close_quietly(&session).await;
                return Err(crypto_error(context, e));
            }
        };
        Ok(Self { session, aes_key })
    }

    /// Encrypts a password for this session; the plaintext copy is zeroized on drop.
    fn encrypt(&self, password: &SecretValue, context: &str) -> Result<DBusSecret> {
        DBusSecret::new_encrypted(self.session.clone(), to_secret(password), &self.aes_key)
            .map_err(|e| map_dbus(context, e))
    }

    /// Closes the session, mapping a failure to a [`KringError`].
    async fn close(&self, context: &str) -> Result<()> {
        self.session.close().await.map_err(|e| map_dbus(context, e))
    }
}

/// Closes a session on an error path; the original error takes precedence over a close failure.
async fn close_quietly(session: &Session) {
    let _ = session.close().await;
}

/// Builds an oo7 secret from a password without leaving unzeroized copies behind.
///
/// `Secret` zeroizes its buffer on drop; text passwords keep the `text/plain` type.
fn to_secret(password: &SecretValue) -> Secret {
    match password.as_text() {
        Some(text) => Secret::text(text),
        None => Secret::blob(password.as_bytes()),
    }
}

/// Maps a key generation failure to a [`KringError`] (no key material is included).
fn crypto_error(context: &str, e: oo7::crypto::Error) -> KringError {
    KringError::Dbus {
        context: context.to_string(),
        message: format!("session key setup failed: {e}"),
    }
}

/// Parses a collection id into a D-Bus object path.
fn object_path(collection: &CollectionId) -> Result<ObjectPath<'_>> {
    ObjectPath::try_from(collection.0.as_str())
        .map_err(|_| KringError::InvalidInput(format!("invalid object path {}", collection.0)))
}

impl SecretServiceBackend {
    /// Builds a proxy for gnome-keyring's private interface.
    async fn private_proxy(&self, context: &str) -> Result<zbus::Proxy<'static>> {
        zbus::proxy::Builder::new(self.connection())
            .destination(DESTINATION)
            .path(SERVICE_PATH)
            .interface(PRIVATE_INTERFACE)
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(|e| map_zbus(context, e))
    }

    /// Calls `CreateWithMasterPassword` inside an open session.
    async fn call_create(
        &self,
        session: &EncryptedSession,
        label: &str,
        password: &SecretValue,
    ) -> Result<CollectionId> {
        let proxy = self.private_proxy(CTX_CREATE).await?;
        let master = session.encrypt(password, CTX_CREATE)?;
        let properties = Properties::for_collection(label);
        let path: OwnedObjectPath = proxy
            .call(METHOD_CREATE, &(properties, &master))
            .await
            .map_err(|e| map_zbus(CTX_CREATE, e))?;
        Ok(CollectionId(path.to_string()))
    }

    /// Calls `UnlockWithMasterPassword` inside an open session.
    async fn call_unlock(
        &self,
        session: &EncryptedSession,
        collection: &CollectionId,
        password: &SecretValue,
    ) -> Result<()> {
        let path = object_path(collection)?;
        let proxy = self.private_proxy(CTX_UNLOCK).await?;
        let master = session.encrypt(password, CTX_UNLOCK)?;
        proxy
            .call_method(METHOD_UNLOCK, &(path, &master))
            .await
            .map_err(|e| map_zbus(CTX_UNLOCK, e))?;
        Ok(())
    }

    /// Calls `ChangeWithMasterPassword` inside an open session.
    async fn call_change(
        &self,
        session: &EncryptedSession,
        collection: &CollectionId,
        old: &SecretValue,
        new: &SecretValue,
    ) -> Result<()> {
        let path = object_path(collection)?;
        let proxy = self.private_proxy(CTX_CHANGE).await?;
        let original = session.encrypt(old, CTX_CHANGE)?;
        let master = session.encrypt(new, CTX_CHANGE)?;
        proxy
            .call_method(METHOD_CHANGE, &(path, &original, &master))
            .await
            .map_err(|e| map_zbus(CTX_CHANGE, e))?;
        Ok(())
    }
}

/// Closes the session and returns the call result; a call error wins over a close error.
async fn finish<T>(session: EncryptedSession, result: Result<T>, context: &str) -> Result<T> {
    let Ok(value) = result else {
        close_quietly(&session.session).await;
        return result;
    };
    session.close(context).await?;
    Ok(value)
}

#[async_trait::async_trait]
impl MasterPasswordStore for SecretServiceBackend {
    /// Creates an unlocked collection protected by `password`, without prompting.
    async fn create_with_password(
        &self,
        label: &str,
        password: &SecretValue,
    ) -> Result<CollectionId> {
        let session = EncryptedSession::open(self, CTX_CREATE).await?;
        let result = self.call_create(&session, label, password).await;
        finish(session, result, CTX_CREATE).await
    }

    /// Unlocks a collection with its password, without prompting.
    async fn unlock_with_password(
        &self,
        collection: &CollectionId,
        password: &SecretValue,
    ) -> Result<()> {
        let session = EncryptedSession::open(self, CTX_UNLOCK).await?;
        let result = self.call_unlock(&session, collection, password).await;
        finish(session, result, CTX_UNLOCK).await
    }

    /// Changes the password of a collection, without prompting.
    async fn change_password(
        &self,
        collection: &CollectionId,
        old: &SecretValue,
        new: &SecretValue,
    ) -> Result<()> {
        let session = EncryptedSession::open(self, CTX_CHANGE).await?;
        let result = self.call_change(&session, collection, old, new).await;
        finish(session, result, CTX_CHANGE).await
    }
}
