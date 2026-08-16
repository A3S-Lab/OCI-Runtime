//! Async, strongly typed API used by A3S Box and other runtime callers.
//!
//! The SDK owns the public contract. Runtime drivers, WHPX, libkrun, and
//! durable-state implementation details remain behind [`OciRuntimeService`].

mod attachment;
mod bundle;
mod client;
mod conformance;
mod error;
mod fingerprint;
mod handoff;
mod id;
mod linux_capability;
mod linux_mount_option;
mod model;
pub mod process_serde;
mod rootfs_metadata;
mod schema;
mod semantic;
mod service;
mod transport;
mod validation;

pub use a3s_oci_core::{
    DriverCapability, DriverKind, DriverReadiness, IsolationClass, RuntimeFeatures,
};
pub use async_trait::async_trait;
pub use attachment::{
    AttachmentCapabilities, AttachmentSource, ConfigurationAttachment, CreateAttachments,
    RuntimeExtensionAttachment, ATTACHMENT_SCHEMA_V1, RUNTIME_BUNDLE_HANDOFF_EXTENSION,
    RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION, RUNTIME_BUNDLE_HANDOFF_MOVE_V1,
};
pub use bundle::{
    OciBundle, CONFIG_FILE_NAME, MAX_CONFIG_BYTES, OCI_RUNTIME_SPEC_VERSION_MAX,
    OCI_RUNTIME_SPEC_VERSION_MIN,
};
pub use client::RuntimeClient;
pub use conformance::{
    OciNormativeCoverageItem, OciNormativeCoverageManifest, OciNormativeDisposition,
    OciNormativeDocument, OciNormativeEvidenceBinding, OciNormativeEvidenceManifest,
    OciNormativeInventory, OciNormativeKeyword, OciNormativeRequirement, OciSpecificationScope,
};
pub use error::{Error, ErrorCode, Result};
pub use fingerprint::canonical_json_bytes;
pub use handoff::{
    runtime_bundle_handoff_directory, runtime_bundle_handoff_root,
    RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY, RUNTIME_BUNDLE_HANDOFF_ROOT_DIRECTORY,
};
pub use id::{ContainerId, Generation, OperationId, ProcessId, TrustDomainId};
pub use linux_capability::{oci_linux_capability_number, OCI_LINUX_CAPABILITY_NAMES};
pub use linux_mount_option::{
    OciLinuxMountOption, OciLinuxMountOptionRequirement, OCI_LINUX_MOUNT_OPTIONS,
};
pub use model::*;
pub use oci_spec;
pub use oci_spec::runtime::{
    ContainerState as OciContainerState, Features as OciFeatures, LinuxResources, Process, Spec,
    State as OciState,
};
pub use rootfs_metadata::{
    PortableRootfsEntryKind, PortableRootfsMetadataEntry, PortableRootfsMetadataManifest,
    PORTABLE_ROOTFS_METADATA_ANNOTATION, PORTABLE_ROOTFS_METADATA_FILE,
    PORTABLE_ROOTFS_METADATA_MAX_BYTES, PORTABLE_ROOTFS_METADATA_MAX_ENTRIES,
    PORTABLE_ROOTFS_METADATA_SCHEMA_V1,
};
pub use schema::{
    OciSchemaCoverageItem, OciSchemaCoverageManifest, OciSchemaDisposition, OciSchemaDocument,
    OciSchemaInventoryItem, OciSchemaInventoryKind, OciSchemaValidationReport, OciSchemaValidator,
    OciSchemaViolation,
};
pub use semantic::{
    OciSemanticPhase, OciSemanticRule, OciSemanticRuleKind, OciSemanticValidationReport,
    OciSemanticValidator, OciSemanticViolation, OciSemanticViolationKind,
};
pub use service::OciRuntimeService;
pub use transport::{
    serve_transport_connection, LocalIpcEndpoint, RuntimeTransportClient, SDK_PROTOCOL_VERSION_MAX,
    SDK_PROTOCOL_VERSION_MIN,
};
pub use validation::{
    ValidateRequest, MAX_EVENT_BATCH_ITEMS, MAX_FILESYSTEM_DEPTH, MAX_FILESYSTEM_PATH_BYTES,
    MAX_FILESYSTEM_USER_BYTES, MAX_FILE_TRANSFER_BYTES, MAX_OUTPUT_READ_BYTES,
    MAX_STDIN_WRITE_BYTES,
};
