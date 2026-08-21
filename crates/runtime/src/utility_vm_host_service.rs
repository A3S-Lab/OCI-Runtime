use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use a3s_oci_sdk::{async_trait, Result};

use crate::unix_service::{combine_service_and_cleanup, UnixServiceEndpoint, SERVICE_SOCKET_NAME};
use crate::{HostRuntimeService, RuntimeDriver};

/// Driver ownership needed by a long-lived Unix SDK Host Service.
#[async_trait]
pub(crate) trait UtilityVmHostDriver: RuntimeDriver {
    /// Reap every driver-owned utility VM after the SDK endpoint stops.
    async fn shutdown_host_driver(&self) -> Result<()>;

    /// Stable label used only to add context to combined service errors.
    fn host_driver_label(&self) -> &'static str;
}

/// Shared Unix endpoint and durable Host Service ownership for utility-VM drivers.
pub(crate) struct UtilityVmHostService<D> {
    endpoint: UnixServiceEndpoint,
    service: Arc<HostRuntimeService>,
    driver: Arc<D>,
}

impl<D> UtilityVmHostService<D>
where
    D: UtilityVmHostDriver + 'static,
{
    /// Open durable state before replacing a stale socket from a dead owner.
    pub(crate) async fn bind(root: &Path, state_root: &Path, driver: Arc<D>) -> Result<Self> {
        let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
        let service = match HostRuntimeService::open(state_root, runtime_driver).await {
            Ok(service) => Arc::new(service),
            Err(error) => {
                let _ = driver.shutdown_host_driver().await;
                return Err(error);
            }
        };
        // Durable state is locked before the stale inode is inspected. A
        // replacement can therefore consume only an endpoint left by a dead
        // owner and never race a second legitimate service incarnation.
        let endpoint =
            match UnixServiceEndpoint::bind_recovering_stale(&root.join(SERVICE_SOCKET_NAME)).await
            {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    let _ = driver.shutdown_host_driver().await;
                    return Err(error);
                }
            };
        Ok(Self {
            endpoint,
            service,
            driver,
        })
    }

    pub(crate) fn socket_path(&self) -> &Path {
        self.endpoint.path()
    }

    /// Serve authenticated clients, then close and reap every owned VM once.
    pub(crate) async fn serve_until<F>(self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        let serve_result = self
            .endpoint
            .serve_until(self.service.clone(), shutdown)
            .await;
        let label = self.driver.host_driver_label();
        let cleanup_result = self.driver.shutdown_host_driver().await;
        combine_service_and_cleanup(serve_result, cleanup_result, label)
    }
}
