use std::collections::BTreeSet;
use std::sync::Arc;

use a3s_oci_core::{DriverCapability, DriverKind, IsolationClass};
use a3s_oci_sdk::{ContainerRecord, Error, ErrorCode, Result, RuntimeOperation};

use crate::{OciHookPhase, RuntimeDriver};

pub(super) struct DriverRegistration {
    pub(super) driver: Arc<dyn RuntimeDriver>,
    pub(super) capability: DriverCapability,
}

pub(super) struct RegisteredDriver {
    driver: Arc<dyn RuntimeDriver>,
    capability: DriverCapability,
    operations: BTreeSet<RuntimeOperation>,
}

impl RegisteredDriver {
    pub(super) fn driver(&self) -> &Arc<dyn RuntimeDriver> {
        &self.driver
    }

    pub(super) const fn capability(&self) -> &DriverCapability {
        &self.capability
    }

    pub(super) const fn kind(&self) -> DriverKind {
        self.capability.driver
    }

    pub(super) fn ensure_operation(
        &self,
        operation: RuntimeOperation,
        name: &'static str,
    ) -> Result<()> {
        if self.operations.contains(&operation) {
            Ok(())
        } else {
            Err(Error::unsupported(name))
        }
    }
}

pub(super) struct DriverRegistry {
    entries: Vec<RegisteredDriver>,
    operations: BTreeSet<RuntimeOperation>,
    hooks: Vec<OciHookPhase>,
}

impl DriverRegistry {
    pub(super) fn new(registrations: Vec<DriverRegistration>) -> Result<Self> {
        if registrations.is_empty() {
            return Err(open_error(
                "at least one launch-ready runtime driver is required",
            ));
        }

        let mut entries = Vec::with_capacity(registrations.len());
        let mut common_operations = None;
        let mut common_hooks = None;

        for registration in registrations {
            let capability = registration.capability;
            validate_capability(&capability)?;
            if entries
                .iter()
                .any(|entry: &RegisteredDriver| entry.kind() == capability.driver)
            {
                return Err(open_error(format!(
                    "runtime driver {:?} is registered more than once",
                    capability.driver
                )));
            }
            if let Some((isolation, owner)) =
                capability.isolation_classes.iter().find_map(|isolation| {
                    entries
                        .iter()
                        .find(|entry| entry.capability().isolation_classes.contains(isolation))
                        .map(|entry| (*isolation, entry.kind()))
                })
            {
                return Err(open_error(format!(
                    "isolation class {isolation:?} is claimed by both {owner:?} and {:?}",
                    capability.driver
                )));
            }

            let operations = validate_driver_operations(registration.driver.operations())?;
            if let Some(expected) = &common_operations {
                if expected != &operations {
                    return Err(open_error(format!(
                        "runtime driver {:?} advertises a different operation set",
                        capability.driver
                    )));
                }
            } else {
                common_operations = Some(operations.clone());
            }

            let hooks = validate_driver_hooks(registration.driver.hooks())?;
            if let Some(expected) = &common_hooks {
                if expected != &hooks {
                    return Err(open_error(format!(
                        "runtime driver {:?} advertises a different OCI hook set",
                        capability.driver
                    )));
                }
            } else {
                common_hooks = Some(hooks.clone());
            }

            entries.push(RegisteredDriver {
                driver: registration.driver,
                capability,
                operations,
            });
        }

        let operations = common_operations
            .ok_or_else(|| open_error("driver registry did not retain an operation set"))?;
        let hooks = common_hooks
            .ok_or_else(|| open_error("driver registry did not retain an OCI hook set"))?;
        entries.sort_by_key(RegisteredDriver::kind);
        Ok(Self {
            entries,
            operations,
            hooks,
        })
    }

    pub(super) fn select(
        &self,
        isolation: IsolationClass,
        operation: &'static str,
    ) -> Result<&RegisteredDriver> {
        self.entries
            .iter()
            .find(|entry| entry.capability().isolation_classes.contains(&isolation))
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unsupported,
                    format!("no launch-ready driver provides requested isolation {isolation:?}"),
                )
                .for_operation(operation)
            })
    }

    pub(super) fn get(
        &self,
        kind: DriverKind,
        operation: &'static str,
    ) -> Result<&RegisteredDriver> {
        self.entries
            .iter()
            .find(|entry| entry.kind() == kind)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unavailable,
                    format!("recorded runtime driver {kind:?} is not registered"),
                )
                .for_operation(operation)
            })
    }

    pub(super) fn validate_durable_record(
        &self,
        record: &ContainerRecord,
    ) -> Result<&RegisteredDriver> {
        let registered = self
            .entries
            .iter()
            .find(|entry| entry.kind() == record.driver)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unavailable,
                    format!(
                        "durable container {} generation {} requires recorded runtime driver {:?}, but that driver is not registered",
                        record.state.id(), record.generation.0, record.driver
                    ),
                )
                .for_operation("open-host-runtime")
            })?;
        if registered
            .capability()
            .isolation_classes
            .contains(&record.isolation)
        {
            return Ok(registered);
        }

        Err(Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "durable container {} generation {} records runtime driver {:?} for isolation {:?}, but the registered driver no longer provides that isolation",
                record.state.id(), record.generation.0, record.driver, record.isolation
            ),
        )
        .for_operation("open-host-runtime"))
    }

    pub(super) fn capabilities(&self) -> impl Iterator<Item = &DriverCapability> {
        self.entries.iter().map(RegisteredDriver::capability)
    }

    pub(super) fn kinds(&self) -> Vec<DriverKind> {
        self.entries.iter().map(RegisteredDriver::kind).collect()
    }

    pub(super) const fn operations(&self) -> &BTreeSet<RuntimeOperation> {
        &self.operations
    }

    pub(super) fn hooks(&self) -> &[OciHookPhase] {
        &self.hooks
    }
}

fn validate_capability(capability: &DriverCapability) -> Result<()> {
    if !capability.can_launch() {
        let code = if capability.status == a3s_oci_core::CapabilityStatus::Unavailable {
            ErrorCode::Unavailable
        } else {
            ErrorCode::Unsupported
        };
        return Err(Error::new(
            code,
            format!(
                "driver {:?} is not launch-ready: status {:?}, readiness {:?}",
                capability.driver, capability.status, capability.readiness
            ),
        )
        .for_operation("open-host-runtime"));
    }
    if capability.isolation_classes.is_empty() {
        return Err(open_error(format!(
            "launch-ready driver {:?} advertises no isolation class",
            capability.driver
        )));
    }
    if capability
        .isolation_classes
        .iter()
        .enumerate()
        .any(|(index, isolation)| capability.isolation_classes[..index].contains(isolation))
    {
        return Err(open_error(format!(
            "runtime driver {:?} advertises a duplicate isolation class",
            capability.driver
        )));
    }
    Ok(())
}

fn validate_driver_operations(
    operations: &[RuntimeOperation],
) -> Result<BTreeSet<RuntimeOperation>> {
    const REQUIRED: [RuntimeOperation; 5] = [
        RuntimeOperation::Create,
        RuntimeOperation::State,
        RuntimeOperation::Start,
        RuntimeOperation::Kill,
        RuntimeOperation::Delete,
    ];
    const HOST_SUPPORTED: [RuntimeOperation; 20] = [
        RuntimeOperation::Create,
        RuntimeOperation::State,
        RuntimeOperation::Start,
        RuntimeOperation::Kill,
        RuntimeOperation::Delete,
        RuntimeOperation::Wait,
        RuntimeOperation::Exec,
        RuntimeOperation::SignalProcess,
        RuntimeOperation::WaitProcess,
        RuntimeOperation::Pause,
        RuntimeOperation::Resume,
        RuntimeOperation::Processes,
        RuntimeOperation::Update,
        RuntimeOperation::Stats,
        RuntimeOperation::ReadOutput,
        RuntimeOperation::WriteStdin,
        RuntimeOperation::CloseStdin,
        RuntimeOperation::Resize,
        RuntimeOperation::File,
        RuntimeOperation::Filesystem,
    ];
    let reported = operations.iter().copied().collect::<BTreeSet<_>>();
    if reported.len() != operations.len() {
        return Err(open_error("runtime driver advertises duplicate operations"));
    }
    if let Some(operation) = operations
        .iter()
        .find(|operation| !HOST_SUPPORTED.contains(operation))
    {
        return Err(open_error(format!(
            "runtime driver advertises unsupported host operation {operation:?}"
        )));
    }
    if let Some(operation) = REQUIRED
        .iter()
        .find(|operation| !reported.contains(operation))
    {
        return Err(open_error(format!(
            "runtime driver does not advertise required operation {operation:?}"
        )));
    }
    Ok(reported)
}

fn validate_driver_hooks(hooks: &[OciHookPhase]) -> Result<Vec<OciHookPhase>> {
    let reported = hooks.iter().copied().collect::<BTreeSet<_>>();
    if reported.len() != hooks.len() {
        return Err(open_error(
            "runtime driver advertises duplicate OCI hook phases",
        ));
    }
    Ok(OciHookPhase::ALL
        .into_iter()
        .filter(|phase| reported.contains(phase))
        .collect())
}

fn open_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("open-host-runtime")
}
