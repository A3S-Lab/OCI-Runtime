use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::attachment::validate_extension_name;
use crate::{
    AttachmentCapabilities, DriverKind, Error, ErrorCode, IsolationClass, Result, RuntimeOperation,
};

mod artifact;

pub use artifact::RuntimeArtifact;

/// First public schema for exact-artifact, per-driver runtime capabilities.
pub const RUNTIME_EXTENSIONS_SCHEMA_V1: &str = "a3s.oci.extensions.v1";
/// First public contract version for every currently implemented SDK operation.
pub const RUNTIME_OPERATION_CONTRACT_V1: u16 = 1;

const MAX_DRIVER_CAPABILITIES: usize = 16;
const MAX_OPERATION_VERSIONS: usize = 16;
const MAX_NEGOTIATED_OPERATIONS: usize = 64;
const MAX_NEGOTIATED_ATTACHMENT_EXTENSIONS: usize = 64;
const MAX_ATTACHMENT_SCHEMA_BYTES: usize = 128;

/// Supported versions of one SDK operation for one exact driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOperationCapability {
    operation: RuntimeOperation,
    versions: Vec<u16>,
}

impl RuntimeOperationCapability {
    /// Construct one canonical, positive operation-version inventory.
    pub fn new(operation: RuntimeOperation, mut versions: Vec<u16>) -> Result<Self> {
        versions.sort_unstable();
        versions.dedup();
        if versions.is_empty()
            || versions.first() == Some(&0)
            || versions.len() > MAX_OPERATION_VERSIONS
        {
            return Err(negotiation_input_error(format!(
                "runtime operation {operation:?} must advertise between 1 and {MAX_OPERATION_VERSIONS} positive versions"
            )));
        }
        Ok(Self {
            operation,
            versions,
        })
    }

    /// Construct the current v1 contract for one operation.
    pub fn v1(operation: RuntimeOperation) -> Self {
        Self {
            operation,
            versions: vec![RUNTIME_OPERATION_CONTRACT_V1],
        }
    }

    /// Advertised operation.
    #[must_use]
    pub const fn operation(&self) -> RuntimeOperation {
        self.operation
    }

    /// Positive versions in canonical ascending order.
    #[must_use]
    pub fn versions(&self) -> &[u16] {
        &self.versions
    }

    /// Whether this exact contract version is supported.
    #[must_use]
    pub fn supports(&self, version: u16) -> bool {
        self.versions.binary_search(&version).is_ok()
    }

    fn validate(&self) -> Result<()> {
        if self.versions.is_empty()
            || self.versions.len() > MAX_OPERATION_VERSIONS
            || self.versions.first() == Some(&0)
            || !strictly_increasing(&self.versions)
        {
            return Err(negotiation_input_error(format!(
                "runtime operation {:?} has a non-canonical version inventory",
                self.operation
            )));
        }
        Ok(())
    }
}

/// Exact operation and attachment surface of one launch-ready driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeDriverCapabilities {
    driver: DriverKind,
    isolation_classes: Vec<IsolationClass>,
    operations: Vec<RuntimeOperationCapability>,
    attachments: AttachmentCapabilities,
}

impl RuntimeDriverCapabilities {
    /// Construct a canonical driver capability entry.
    pub fn new(
        driver: DriverKind,
        mut isolation_classes: Vec<IsolationClass>,
        mut operations: Vec<RuntimeOperationCapability>,
        attachments: AttachmentCapabilities,
    ) -> Result<Self> {
        isolation_classes.sort_by_key(|class| isolation_key(*class));
        operations.sort_by_key(RuntimeOperationCapability::operation);
        let capabilities = Self {
            driver,
            isolation_classes,
            operations,
            attachments,
        };
        capabilities.validate()?;
        Ok(capabilities)
    }

    /// Driver represented by this exact capability entry.
    #[must_use]
    pub const fn driver(&self) -> DriverKind {
        self.driver
    }

    /// Isolation classes owned by this driver.
    #[must_use]
    pub fn isolation_classes(&self) -> &[IsolationClass] {
        &self.isolation_classes
    }

    /// Versioned operations in canonical order.
    #[must_use]
    pub fn operations(&self) -> &[RuntimeOperationCapability] {
        &self.operations
    }

    /// Versioned create-time attachment surface of this driver.
    #[must_use]
    pub const fn attachments(&self) -> &AttachmentCapabilities {
        &self.attachments
    }

    /// Whether this driver supports one exact operation contract.
    #[must_use]
    pub fn supports_operation(&self, operation: RuntimeOperation, version: u16) -> bool {
        self.operations
            .binary_search_by_key(&operation, RuntimeOperationCapability::operation)
            .ok()
            .is_some_and(|index| self.operations[index].supports(version))
    }

    fn validate(&self) -> Result<()> {
        if self.isolation_classes.is_empty()
            || !strictly_increasing_by(&self.isolation_classes, |class| isolation_key(*class))
        {
            return Err(negotiation_input_error(format!(
                "runtime driver {:?} must own a non-empty, unique isolation inventory",
                self.driver
            )));
        }
        if self.operations.is_empty()
            || !strictly_increasing_by(&self.operations, RuntimeOperationCapability::operation)
        {
            return Err(negotiation_input_error(format!(
                "runtime driver {:?} must advertise a non-empty, unique operation inventory",
                self.driver
            )));
        }
        for operation in &self.operations {
            operation.validate()?;
        }
        self.attachments
            .validate()
            .map_err(|error| negotiation_input_error(error.message))?;
        Ok(())
    }
}

/// Additive, versioned catalog used to select one exact driver contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensions {
    schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact: Option<RuntimeArtifact>,
    drivers: Vec<RuntimeDriverCapabilities>,
}

impl RuntimeExtensions {
    /// Construct the v1 catalog for one exact runtime executable.
    pub fn new(
        artifact: RuntimeArtifact,
        mut drivers: Vec<RuntimeDriverCapabilities>,
    ) -> Result<Self> {
        artifact.validate()?;
        drivers.sort_by_key(RuntimeDriverCapabilities::driver);
        let catalog = Self {
            schema_version: RUNTIME_EXTENSIONS_SCHEMA_V1.to_string(),
            artifact: Some(artifact),
            drivers,
        };
        catalog.validate()?;
        Ok(catalog)
    }

    /// Capability-catalog schema emitted by this peer.
    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Exact executable identity, absent only for a legacy peer.
    #[must_use]
    pub const fn artifact(&self) -> Option<&RuntimeArtifact> {
        self.artifact.as_ref()
    }

    /// Launch-ready driver contracts in canonical driver order.
    #[must_use]
    pub fn drivers(&self) -> &[RuntimeDriverCapabilities] {
        &self.drivers
    }

    /// Select one driver and require every requested operation and attachment version.
    pub fn negotiate(
        &self,
        request: &RuntimeNegotiationRequest,
    ) -> Result<&RuntimeDriverCapabilities> {
        self.validate()?;
        request.validate()?;
        if self.schema_version != RUNTIME_EXTENSIONS_SCHEMA_V1 || self.artifact.is_none() {
            return Err(unsupported(
                "runtime peer did not advertise the v1 extension capability catalog",
            ));
        }
        let driver = self
            .drivers
            .iter()
            .find(|driver| driver.isolation_classes.contains(&request.isolation))
            .ok_or_else(|| {
                unsupported(format!(
                    "no advertised driver owns requested isolation {:?}",
                    request.isolation
                ))
            })?;
        for (operation, version) in &request.operations {
            if !driver.supports_operation(*operation, *version) {
                return Err(unsupported(format!(
                    "runtime driver {:?} does not advertise operation {operation:?} version {version}",
                    driver.driver
                )));
            }
        }
        if let Some(schema) = &request.attachment_schema {
            if !driver.attachments.supports_schema(schema) {
                return Err(unsupported(format!(
                    "runtime driver {:?} does not advertise attachment schema {schema}",
                    driver.driver
                )));
            }
        }
        for (name, version) in &request.attachment_extensions {
            if !driver.attachments.supports_extension(name, *version) {
                return Err(unsupported(format!(
                    "runtime driver {:?} does not advertise attachment extension {name} version {version}",
                    driver.driver
                )));
            }
        }
        Ok(driver)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version.is_empty() && self.artifact.is_none() && self.drivers.is_empty() {
            return Ok(());
        }
        if self.schema_version != RUNTIME_EXTENSIONS_SCHEMA_V1 {
            return Err(negotiation_input_error(format!(
                "unsupported runtime extension catalog schema {:?}",
                self.schema_version
            )));
        }
        self.artifact
            .as_ref()
            .ok_or_else(|| negotiation_input_error("runtime extension catalog has no artifact"))?
            .validate()?;
        if self.drivers.len() > MAX_DRIVER_CAPABILITIES {
            return Err(negotiation_input_error(format!(
                "runtime extension catalog exceeds {MAX_DRIVER_CAPABILITIES} drivers"
            )));
        }
        if !strictly_increasing_by(&self.drivers, RuntimeDriverCapabilities::driver) {
            return Err(negotiation_input_error(
                "runtime extension catalog driver inventory is not canonical",
            ));
        }
        let mut drivers = BTreeSet::new();
        let mut isolation_owners = BTreeMap::new();
        for driver in &self.drivers {
            driver.validate()?;
            if !drivers.insert(driver.driver) {
                return Err(negotiation_input_error(format!(
                    "runtime extension catalog duplicates driver {:?}",
                    driver.driver
                )));
            }
            for isolation in &driver.isolation_classes {
                if let Some(owner) =
                    isolation_owners.insert(isolation_key(*isolation), driver.driver)
                {
                    return Err(negotiation_input_error(format!(
                        "runtime isolation {isolation:?} is advertised by both {owner:?} and {:?}",
                        driver.driver
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Typed requirements for selecting one exact runtime driver contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeNegotiationRequest {
    isolation: IsolationClass,
    operations: BTreeMap<RuntimeOperation, u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attachment_schema: Option<String>,
    attachment_extensions: BTreeMap<String, u16>,
}

impl RuntimeNegotiationRequest {
    /// Begin negotiation for one typed isolation requirement.
    #[must_use]
    pub fn new(isolation: IsolationClass) -> Self {
        Self {
            isolation,
            operations: BTreeMap::new(),
            attachment_schema: None,
            attachment_extensions: BTreeMap::new(),
        }
    }

    /// Require one exact operation contract version.
    pub fn with_operation(mut self, operation: RuntimeOperation, version: u16) -> Result<Self> {
        if version == 0 {
            return Err(negotiation_input_error(format!(
                "runtime operation {operation:?} uses reserved version zero"
            )));
        }
        if self.operations.insert(operation, version).is_some() {
            return Err(negotiation_input_error(format!(
                "runtime operation requirement {operation:?} is duplicated"
            )));
        }
        self.validate()?;
        Ok(self)
    }

    /// Require one attachment manifest schema.
    pub fn with_attachment_schema(mut self, schema: impl Into<String>) -> Result<Self> {
        if self.attachment_schema.is_some() {
            return Err(negotiation_input_error(
                "attachment schema requirement is duplicated",
            ));
        }
        self.attachment_schema = Some(schema.into());
        self.validate()?;
        Ok(self)
    }

    /// Require one exact attachment-extension contract version.
    pub fn with_attachment_extension(
        mut self,
        name: impl Into<String>,
        version: u16,
    ) -> Result<Self> {
        let name = name.into();
        validate_extension_name(&name).map_err(|error| negotiation_input_error(error.message))?;
        if version == 0 {
            return Err(negotiation_input_error(format!(
                "attachment extension {name} uses reserved version zero"
            )));
        }
        if self
            .attachment_extensions
            .insert(name.clone(), version)
            .is_some()
        {
            return Err(negotiation_input_error(format!(
                "attachment extension requirement {name} is duplicated"
            )));
        }
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        if self.operations.len() > MAX_NEGOTIATED_OPERATIONS {
            return Err(negotiation_input_error(format!(
                "runtime negotiation exceeds {MAX_NEGOTIATED_OPERATIONS} operation requirements"
            )));
        }
        if self.attachment_extensions.len() > MAX_NEGOTIATED_ATTACHMENT_EXTENSIONS {
            return Err(negotiation_input_error(format!(
                "runtime negotiation exceeds {MAX_NEGOTIATED_ATTACHMENT_EXTENSIONS} attachment extension requirements"
            )));
        }
        if self.operations.values().any(|version| *version == 0) {
            return Err(negotiation_input_error(
                "runtime negotiation contains operation version zero",
            ));
        }
        if let Some(schema) = &self.attachment_schema {
            validate_bounded_text(
                schema,
                "attachment schema requirement",
                MAX_ATTACHMENT_SCHEMA_BYTES,
            )?;
        }
        for (name, version) in &self.attachment_extensions {
            validate_extension_name(name)
                .map_err(|error| negotiation_input_error(error.message))?;
            if *version == 0 {
                return Err(negotiation_input_error(format!(
                    "attachment extension {name} uses reserved version zero"
                )));
            }
        }
        Ok(())
    }
}

fn validate_bounded_text(value: &str, field: &str, maximum: usize) -> Result<()> {
    if !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        Ok(())
    } else {
        Err(negotiation_input_error(format!(
            "{field} must contain between 1 and {maximum} visible ASCII bytes"
        )))
    }
}

fn strictly_increasing(values: &[u16]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn strictly_increasing_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values
        .windows(2)
        .all(|window| key(&window[0]) < key(&window[1]))
}

const fn isolation_key(isolation: IsolationClass) -> u8 {
    match isolation {
        IsolationClass::DedicatedVm => 0,
        IsolationClass::SharedGuestKernel => 1,
        IsolationClass::SharedHostKernel => 2,
    }
}

fn negotiation_input_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("negotiate-runtime")
}

fn unsupported(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Unsupported, message).for_operation("negotiate-runtime")
}

#[cfg(test)]
mod tests;
