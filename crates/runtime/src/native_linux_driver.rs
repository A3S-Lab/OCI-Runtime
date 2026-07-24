use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent::LinuxExecutor;
use a3s_oci_agent_protocol::{
    AgentBundle, AgentCreateRequest, AgentDeleteRequest, AgentKillRequest, AgentStartRequest,
    AgentState, AgentStateRequest, GuestAgentService, GuestPath,
};
use a3s_oci_core::{CapabilityStatus, DriverCapability, DriverReadiness, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{async_trait, ContainerTarget, Error, ErrorCode, Result};

use crate::driver::{
    DriverCreateRequest, DriverDeleteRequest, DriverKillRequest, DriverStartRequest, DriverState,
    RuntimeDriver,
};

/// Explicitly opted-in native Linux runtime driver.
///
/// The default feature inventory remains `probe-only`. Constructing this
/// driver is the explicit experimental opt-in that allows
/// [`crate::HostRuntimeService`] to exercise the currently reviewed executor
/// profile without linking or initializing libkrun.
#[derive(Debug)]
pub struct NativeLinuxDriver {
    capability: DriverCapability,
    executor: Arc<LinuxExecutor>,
}

impl NativeLinuxDriver {
    /// Open the experimental native driver beneath a runtime-owned directory.
    ///
    /// `init_executable` must be the matching `a3s-oci-agent` binary. The
    /// caller must invoke [`Self::shutdown`] before removing the runtime
    /// directory.
    pub async fn open_experimental(
        runtime_parent: impl AsRef<Path>,
        init_executable: impl AsRef<Path>,
    ) -> Result<Self> {
        let mut capability = crate::platform::native_driver_capability();
        if capability.status != CapabilityStatus::Available {
            return Err(Error::new(
                ErrorCode::Unavailable,
                capability
                    .reason
                    .clone()
                    .unwrap_or_else(|| "native Linux prerequisites are unavailable".to_string()),
            )
            .for_operation("open-native-linux-driver"));
        }
        capability.readiness = DriverReadiness::Experimental;
        capability.evidence.insert(
            "execution_path".to_string(),
            "shared-linux-executor".to_string(),
        );
        capability
            .evidence
            .insert("kvm_required".to_string(), "false".to_string());
        capability
            .evidence
            .insert("opt_in".to_string(), "open-experimental".to_string());

        Ok(Self {
            capability,
            executor: Arc::new(LinuxExecutor::open(runtime_parent, init_executable).await?),
        })
    }

    /// Stop every process owned by this driver and remove transient state.
    pub async fn shutdown(&self) -> Result<()> {
        self.executor.shutdown().await
    }

    /// Private transient executor root used by this driver instance.
    #[must_use]
    pub fn executor_root(&self) -> &Path {
        self.executor.runtime_root()
    }
}

#[async_trait]
impl RuntimeDriver for NativeLinuxDriver {
    fn capability(&self) -> DriverCapability {
        self.capability.clone()
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        if request.isolation.class() != IsolationClass::SharedHostKernel {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "native Linux execution requires shared-host-kernel isolation",
            )
            .for_operation("native-linux-create"));
        }
        let guest_directory = guest_path(request.bundle.directory()).await?;
        let expected_digest = request.bundle.config_digest().to_string();
        let expected_target = request.target.clone();
        let state = self
            .executor
            .create(AgentCreateRequest {
                context: request.context,
                target: request.target,
                bundle: AgentBundle::new(&request.bundle, guest_directory),
                io: request.io,
            })
            .await?;
        driver_state(&expected_target, Some(&expected_digest), state)
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        let state = self
            .executor
            .state(AgentStateRequest {
                target: target.clone(),
            })
            .await?;
        driver_state(&target, None, state)
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        let expected_digest = request.bundle.config_digest().to_string();
        let expected_target = request.target.clone();
        let state = self
            .executor
            .start(AgentStartRequest {
                context: request.context,
                target: request.target,
                expected_config_digest: expected_digest.clone(),
            })
            .await?;
        driver_state(&expected_target, Some(&expected_digest), state)
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .executor
            .kill(AgentKillRequest {
                context: request.context,
                target: request.target,
                signal: request.signal,
                all: request.all,
            })
            .await?;
        driver_state(&expected_target, None, state)
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.executor
            .delete(AgentDeleteRequest {
                context: request.context,
                target: request.target,
                mode: request.mode,
            })
            .await
    }
}

async fn guest_path(bundle: &Path) -> Result<GuestPath> {
    let canonical = tokio::fs::canonicalize(bundle).await.map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to resolve native Linux bundle {}: {error}",
                bundle.display()
            ),
        )
        .for_operation("native-linux-create")
    })?;
    let value = canonical.to_str().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "native Linux bundle path is not valid UTF-8: {}",
                canonical.display()
            ),
        )
        .for_operation("native-linux-create")
    })?;
    GuestPath::new(value.to_string())
}

fn driver_state(
    expected_target: &ContainerTarget,
    expected_digest: Option<&str>,
    state: AgentState,
) -> Result<DriverState> {
    if state.target() != expected_target {
        return Err(Error::new(
            ErrorCode::Conflict,
            "native Linux executor returned a different container generation",
        )
        .for_operation("map-native-linux-state"));
    }
    if expected_digest.is_some_and(|digest| state.config_digest() != digest) {
        return Err(Error::new(
            ErrorCode::Conflict,
            "native Linux executor returned a different configuration digest",
        )
        .for_operation("map-native-linux-state"));
    }
    match state.status() {
        ContainerState::Created => DriverState::created(required_pid(&state)?),
        ContainerState::Running => DriverState::running(required_pid(&state)?),
        ContainerState::Stopped => Ok(DriverState::stopped()),
        status => Err(Error::new(
            ErrorCode::Internal,
            format!("native Linux executor returned invalid lifecycle state {status}"),
        )
        .for_operation("map-native-linux-state")),
    }
}

fn required_pid(state: &AgentState) -> Result<i32> {
    state.pid().ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "native Linux executor returned {} without an init PID",
                state.status()
            ),
        )
        .for_operation("map-native-linux-state")
    })
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::AgentState;
    use a3s_oci_sdk::oci_spec::runtime::ContainerState;
    use a3s_oci_sdk::{ContainerId, ContainerTarget, Generation};

    use super::driver_state;

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const OTHER_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn maps_exact_created_running_and_stopped_states() {
        let target = ContainerTarget::exact(
            ContainerId::new("native-test").expect("container ID"),
            Generation(1),
        );
        for (status, pid) in [
            (ContainerState::Created, Some(101)),
            (ContainerState::Running, Some(101)),
            (ContainerState::Stopped, None),
        ] {
            let state = AgentState::new(target.clone(), status, pid, DIGEST).expect("agent state");
            let mapped = driver_state(&target, Some(DIGEST), state).expect("mapped driver state");
            assert_eq!(mapped.status(), status);
            assert_eq!(mapped.pid(), pid);
        }
    }

    #[test]
    fn rejects_a_mismatched_generation_or_digest() {
        let target = ContainerTarget::exact(
            ContainerId::new("native-test").expect("container ID"),
            Generation(1),
        );
        let other = ContainerTarget::exact(target.id.clone(), Generation(2));
        let state = AgentState::new(other, ContainerState::Created, Some(101), DIGEST)
            .expect("agent state");
        assert!(driver_state(&target, Some(DIGEST), state).is_err());

        let state = AgentState::new(
            target.clone(),
            ContainerState::Created,
            Some(101),
            OTHER_DIGEST,
        )
        .expect("agent state");
        assert!(driver_state(&target, Some(DIGEST), state).is_err());
    }
}
