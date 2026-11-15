//! Mapping of oo7 / zbus errors to [`KringError`].

use oo7::dbus::{Error, ServiceError};
use oo7::zbus;

use crate::error::KringError;

/// D-Bus error name: the object does not exist.
const ERR_UNKNOWN_OBJECT: &str = "org.freedesktop.DBus.Error.UnknownObject";
/// D-Bus error name: the method does not exist.
///
/// gnome-keyring answers UnknownMethod (not UnknownObject) for calls on an object that
/// vanished, so it is mapped to `NotFound`. This could mask a genuine missing-method bug.
const ERR_UNKNOWN_METHOD: &str = "org.freedesktop.DBus.Error.UnknownMethod";
/// D-Bus error name: no service owns the requested name.
const ERR_SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
/// D-Bus error name: the bus name has no owner.
const ERR_NAME_HAS_NO_OWNER: &str = "org.freedesktop.DBus.Error.NameHasNoOwner";
/// Secret Service error name: collection or item is locked.
const ERR_IS_LOCKED: &str = "org.freedesktop.Secret.Error.IsLocked";
/// Secret Service error name: collection or item does not exist.
const ERR_NO_SUCH_OBJECT: &str = "org.freedesktop.Secret.Error.NoSuchObject";

/// Maps an oo7 D-Bus error to a [`KringError`], tagging unknown errors with `context`.
pub fn map_dbus(context: &str, e: Error) -> KringError {
    match e {
        Error::ZBus(z) | Error::Service(ServiceError::ZBus(z)) => map_zbus(context, z),
        Error::Service(ServiceError::IsLocked(m)) => KringError::Locked(m),
        Error::Service(ServiceError::NoSuchObject(m)) => KringError::NotFound(m),
        Error::Deleted => KringError::NotFound(format!("{context}: object was deleted")),
        Error::NotFound(name) => KringError::NotFound(name),
        other => dbus_error(context, other.to_string()),
    }
}

/// Maps a zbus error to a [`KringError`] using the D-Bus error name when there is one.
pub fn map_zbus(context: &str, e: zbus::Error) -> KringError {
    let name = match &e {
        zbus::Error::MethodError(name, _, _) => Some(name.to_string()),
        zbus::Error::FDO(fdo) => Some(zbus::DBusError::name(fdo.as_ref()).to_string()),
        _ => None,
    };
    match name.as_deref() {
        Some(ERR_IS_LOCKED) => KringError::Locked(e.to_string()),
        Some(ERR_NO_SUCH_OBJECT | ERR_UNKNOWN_OBJECT | ERR_UNKNOWN_METHOD) => {
            KringError::NotFound(e.to_string())
        }
        Some(ERR_SERVICE_UNKNOWN | ERR_NAME_HAS_NO_OWNER) => KringError::NoProvider,
        _ => dbus_error(context, e.to_string()),
    }
}

/// Builds a generic [`KringError::Dbus`].
fn dbus_error(context: &str, message: String) -> KringError {
    KringError::Dbus {
        context: context.to_string(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `zbus::Error::MethodError` carrying the given error name.
    fn method_error(name: &'static str) -> zbus::Error {
        let call = zbus::message::Message::method_call("/x", "Foo")
            .build(&())
            .unwrap();
        let reply = zbus::message::Message::error(&call.header(), name)
            .build(&())
            .unwrap();
        zbus::Error::from(reply)
    }

    /// Secret Service IsLocked maps to `Locked`.
    #[test]
    fn is_locked_maps_to_locked() {
        let e = map_dbus("t", Error::Service(ServiceError::IsLocked("/c".into())));
        assert!(matches!(e, KringError::Locked(_)), "{e:?}");
        let e = map_dbus("t", Error::ZBus(method_error(ERR_IS_LOCKED)));
        assert!(matches!(e, KringError::Locked(_)), "{e:?}");
    }

    /// Missing objects map to `NotFound`.
    #[test]
    fn missing_objects_map_to_not_found() {
        for e in [
            map_dbus("t", Error::Service(ServiceError::NoSuchObject("/i".into()))),
            map_dbus("t", Error::Deleted),
            map_dbus("t", Error::NotFound("x".into())),
            map_dbus("t", Error::ZBus(method_error(ERR_UNKNOWN_OBJECT))),
            map_dbus("t", Error::ZBus(method_error(ERR_UNKNOWN_METHOD))),
            map_dbus("t", Error::ZBus(method_error(ERR_NO_SUCH_OBJECT))),
        ] {
            assert!(matches!(e, KringError::NotFound(_)), "{e:?}");
        }
    }

    /// A missing service maps to `NoProvider`.
    #[test]
    fn missing_service_maps_to_no_provider() {
        for name in [ERR_SERVICE_UNKNOWN, ERR_NAME_HAS_NO_OWNER] {
            let e = map_dbus("t", Error::ZBus(method_error(name)));
            assert!(matches!(e, KringError::NoProvider), "{e:?}");
        }
        let fdo = zbus::fdo::Error::ServiceUnknown("org.x".into());
        let e = map_dbus("t", Error::ZBus(zbus::Error::FDO(Box::new(fdo))));
        assert!(matches!(e, KringError::NoProvider), "{e:?}");
    }

    /// Anything else becomes `Dbus` with the context.
    #[test]
    fn other_errors_map_to_dbus() {
        let e = map_dbus("listing", Error::Dismissed);
        match e {
            KringError::Dbus { context, .. } => assert_eq!(context, "listing"),
            other => panic!("unexpected {other:?}"),
        }
        let e = map_dbus("t", Error::ZBus(method_error("org.example.Weird")));
        assert!(matches!(e, KringError::Dbus { .. }), "{e:?}");
    }
}
