//! Startup connection to the Secret Service provider.
//!
//! zbus (tokio flavour) spawns the socket reader task on the runtime that created
//! the connection. That runtime must therefore keep running for as long as the
//! connection is used, so it is a multi-thread runtime returned to the caller.

use std::sync::Arc;

use kring_core::provider::{self, ProviderInfo};
use kring_core::secret_service::SecretServiceBackend;
use tokio::runtime::Runtime;

/// Threads of the runtime that drives the D-Bus connection.
const BUS_RUNTIME_THREADS: usize = 1;

/// Result of the startup connection attempt.
pub struct Connected {
    /// Runtime driving the connection; keep it alive while `store` is in use.
    pub runtime: Option<Runtime>,
    /// Backend, `None` when no provider is reachable.
    pub store: Option<Arc<SecretServiceBackend>>,
    /// Detected provider, `None` when no provider is reachable.
    pub provider: Option<ProviderInfo>,
    /// Why the connection failed, if it did.
    pub error: Option<String>,
}

/// Connects to the session bus and detects the provider.
pub fn connect() -> Connected {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(BUS_RUNTIME_THREADS)
        .thread_name("kring-bus")
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return _failed(None, format!("cannot start the bus runtime: {e}")),
    };
    let result = runtime.block_on(async {
        let backend = SecretServiceBackend::connect()
            .await
            .map_err(|e| e.to_string())?;
        let info = provider::detect(backend.connection())
            .await
            .map_err(|e| e.to_string())?;
        Ok::<_, String>((backend, info))
    });
    match result {
        Ok((backend, info)) => Connected {
            runtime: Some(runtime),
            store: Some(Arc::new(backend)),
            provider: Some(info),
            error: None,
        },
        Err(e) => _failed(Some(runtime), e),
    }
}

/// Builds a failed connection result.
fn _failed(runtime: Option<Runtime>, error: String) -> Connected {
    Connected {
        runtime,
        store: None,
        provider: None,
        error: Some(error),
    }
}
