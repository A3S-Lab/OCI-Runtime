use std::collections::BTreeSet;

use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerRecord, CreateAttachments, ErrorCode, Generation, OciBundle, OperationId,
    Result,
};

use crate::fault::DurableMutation;

use super::filesystem::state_error;
use super::model::{StoredContainer, CONTAINER_SCHEMA_VERSION};
use super::oci_state::build_state;
use super::{DurableStateStore, CONFIG_SNAPSHOT_FILE, CONTAINER_RECORD_FILE};

#[derive(Debug, Clone, Copy)]
pub(super) struct CreationProfile {
    pub(super) operation: &'static str,
    pub(super) store_config: DurableMutation,
    pub(super) store_container: DurableMutation,
}

impl DurableStateStore {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn reconcile_prepared_container(
        &self,
        id: &ContainerId,
        bundle: &OciBundle,
        isolation: IsolationClass,
        attachments: &CreateAttachments,
        driver: DriverKind,
        generation: Generation,
        operation_id: &OperationId,
        profile: CreationProfile,
    ) -> Result<StoredContainer> {
        let attachments_digest = attachments.digest()?;
        let network_enforcement = attachments.network_enforcement(bundle)?;
        let container_directory = self.container_directory(id);
        if self.filesystem.path_exists(&container_directory).await? {
            self.filesystem
                .ensure_plain_directory(&container_directory, "container state directory")
                .await?;
            self.filesystem
                .set_private_directory_permissions(&container_directory)
                .await?;
        } else {
            self.filesystem
                .create_private_directory(&container_directory)
                .await?;
        }

        let config_path = container_directory.join(CONFIG_SNAPSHOT_FILE);
        if self.filesystem.path_exists(&config_path).await? {
            let durable_config = self.filesystem.read_utf8(&config_path).await?;
            if durable_config.as_bytes() != bundle.config_bytes() {
                return Err(state_error(
                    ErrorCode::Conflict,
                    profile.operation,
                    format!(
                        "container {id} configuration snapshot differs from its creation request"
                    ),
                ));
            }
        } else {
            self.write_bytes(profile.store_config, &config_path, bundle.config_bytes())
                .await?;
        }

        let record_path = container_directory.join(CONTAINER_RECORD_FILE);
        if self.filesystem.path_exists(&record_path).await? {
            let stored = self.load_stored_exact(id, generation).await?;
            if stored.record.driver != driver
                || stored.record.isolation != isolation
                || stored.record.guest_session.as_ref() != attachments.guest_session()
                || stored.record.network_enforcement.as_ref() != network_enforcement.as_ref()
                || stored.record.config_digest != bundle.config_digest()
                || stored.record.attachments_digest.as_deref() != Some(attachments_digest.as_str())
                || stored.attachments.as_ref() != Some(attachments)
            {
                return Err(state_error(
                    ErrorCode::Conflict,
                    profile.operation,
                    format!("container {id} durable record differs from its creation request"),
                ));
            }
            return Ok(stored);
        }

        let state = build_state(id, bundle, ContainerState::Creating, None)?;
        let record = ContainerRecord {
            state,
            generation,
            driver,
            isolation,
            guest_session: attachments.guest_session().cloned(),
            network_enforcement,
            config_digest: bundle.config_digest().to_string(),
            attachments_digest: Some(attachments_digest),
        };
        let stored = StoredContainer {
            schema_version: CONTAINER_SCHEMA_VERSION.to_string(),
            id: id.clone(),
            record,
            attachments: Some(attachments.clone()),
            active_operation: Some(operation_id.clone()),
            init_io_operations: BTreeSet::new(),
            init_exit_status: None,
        };
        self.write_json(profile.store_container, &record_path, &stored)
            .await?;
        Ok(stored)
    }
}
