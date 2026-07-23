//! Async, strongly typed API used by A3S Box and other runtime callers.
//!
//! The SDK owns the public contract. Runtime drivers, WHPX, libkrun, and
//! durable-state implementation details remain behind [`OciRuntimeService`].

mod bundle;
mod client;
mod error;
mod id;
mod model;
mod schema;
mod service;
mod transport;

pub use a3s_oci_core::{
    DriverCapability, DriverKind, DriverReadiness, IsolationClass, RuntimeFeatures,
};
pub use async_trait::async_trait;
pub use bundle::{
    OciBundle, CONFIG_FILE_NAME, MAX_CONFIG_BYTES, OCI_RUNTIME_SPEC_VERSION_MAX,
    OCI_RUNTIME_SPEC_VERSION_MIN,
};
pub use client::RuntimeClient;
pub use error::{Error, ErrorCode, Result};
pub use id::{ContainerId, Generation, OperationId, ProcessId, TrustDomainId};
pub use model::*;
pub use oci_spec;
pub use oci_spec::runtime::{
    ContainerState as OciContainerState, Features as OciFeatures, LinuxResources, Process, Spec,
    State as OciState,
};
pub use schema::{
    OciSchemaCoverageItem, OciSchemaCoverageManifest, OciSchemaDisposition, OciSchemaDocument,
    OciSchemaInventoryItem, OciSchemaInventoryKind, OciSchemaValidationReport, OciSchemaValidator,
    OciSchemaViolation,
};
pub use service::OciRuntimeService;
pub use transport::{
    serve_transport_connection, LocalIpcEndpoint, RuntimeTransportClient, SDK_PROTOCOL_VERSION_MAX,
    SDK_PROTOCOL_VERSION_MIN,
};
