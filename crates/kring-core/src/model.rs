//! Plain data types describing collections, items and secrets.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

/// Object path of the login collection.
pub const LOGIN_COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/login";

/// Content type used for text secrets.
const TEXT_CONTENT_TYPE: &str = "text/plain";

/// D-Bus object path of a collection.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CollectionId(pub String);

/// D-Bus object path of an item.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ItemId(pub String);

/// Item attributes (lookup key/value pairs).
pub type Attributes = BTreeMap<String, String>;

/// A secret payload, zeroized on drop and redacted in `Debug`.
#[derive(Clone)]
pub struct SecretValue {
    bytes: Zeroizing<Vec<u8>>,
    /// MIME content type of the secret.
    pub content_type: String,
}

impl SecretValue {
    /// Creates a secret from raw bytes and a content type.
    pub fn new(bytes: Vec<u8>, content_type: &str) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            content_type: content_type.to_string(),
        }
    }

    /// Creates a `text/plain` secret from text.
    pub fn from_text(text: &str) -> Self {
        Self::new(text.as_bytes().to_vec(), TEXT_CONTENT_TYPE)
    }

    /// Returns the raw secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the secret as text, or `None` if it is not valid UTF-8.
    pub fn as_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes).ok()
    }

    /// Returns the secret length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true when the secret has no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for SecretValue {
    /// Prints only the length, never the content.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretValue(<redacted, {} bytes>)", self.len())
    }
}

/// Summary of a collection (keyring).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionInfo {
    pub id: CollectionId,
    pub label: String,
    pub locked: bool,
    pub item_count: usize,
    pub aliases: Vec<String>,
    pub is_login: bool,
    /// Creation time, unix seconds.
    pub created: u64,
    /// Last modification time, unix seconds.
    pub modified: u64,
}

/// Summary of an item (without its secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemInfo {
    pub id: ItemId,
    pub collection: CollectionId,
    pub label: String,
    pub attributes: Attributes,
    pub locked: bool,
    /// Creation time, unix seconds.
    pub created: u64,
    /// Last modification time, unix seconds.
    pub modified: u64,
}

/// Data needed to create an item.
#[derive(Clone, Debug)]
pub struct NewItem {
    pub label: String,
    pub attributes: Attributes,
    pub secret: SecretValue,
    /// Replace an existing item with identical attributes.
    pub replace: bool,
}

/// Partial update of an item; `None` fields are left unchanged.
#[derive(Clone, Debug, Default)]
pub struct ItemUpdate {
    pub label: Option<String>,
    pub attributes: Option<Attributes>,
    pub secret: Option<SecretValue>,
}

/// Returns true if `id` is the login collection.
pub fn is_login_collection(id: &CollectionId) -> bool {
    id.0 == LOGIN_COLLECTION_PATH
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Debug output never reveals the secret.
    #[test]
    fn secret_debug_is_redacted() {
        let s = SecretValue::from_text("hunter2");
        assert_eq!(format!("{s:?}"), "SecretValue(<redacted, 7 bytes>)");
    }

    /// Only the login path is the login collection.
    #[test]
    fn login_path_detected() {
        assert!(is_login_collection(&CollectionId(
            LOGIN_COLLECTION_PATH.into()
        )));
        assert!(!is_login_collection(&CollectionId(
            "/org/freedesktop/secrets/collection/Default_3".into()
        )));
    }

    /// Non-UTF-8 bytes give no text; clones keep the bytes.
    #[test]
    fn as_text_and_clone() {
        let s = SecretValue::new(vec![0xff, 0xfe], "application/octet-stream");
        assert_eq!(s.as_text(), None);
        let c = s.clone();
        assert_eq!(c.as_bytes(), &[0xff, 0xfe]);
        assert_eq!(c.content_type, "application/octet-stream");
        assert_eq!(SecretValue::from_text("ab").as_text(), Some("ab"));
        assert_eq!(SecretValue::from_text("ab").content_type, "text/plain");
    }
}
