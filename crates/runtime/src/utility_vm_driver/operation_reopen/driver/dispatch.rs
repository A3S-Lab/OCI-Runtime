use std::sync::atomic::Ordering;

use a3s_oci_sdk::{ErrorCode, Result};

use super::{qualification_error, QualificationKvmOperationDriver};
use crate::driver::{
    DriverCreateRequest, DriverDeleteRequest, DriverKillRequest, DriverStartRequest, DriverState,
};

impl QualificationKvmOperationDriver {
    pub(super) async fn dispatch_create(
        &self,
        request: DriverCreateRequest,
    ) -> Result<DriverState> {
        let identity = (request.context.operation_id.clone(), request.target.clone());
        {
            let mut retained = self.create_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM create identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Create identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        let active = self.ensure_session(&request).await?;
        let guest_bundle = self
            .handoff
            .guest_bundle_path(
                &request.target,
                request.bundle.directory(),
                request.attachment_contract.guest_session(),
            )
            .await?;
        active.client.create(request, guest_bundle).await
    }

    pub(super) async fn dispatch_start(&self, request: DriverStartRequest) -> Result<DriverState> {
        let identity = (request.context.operation_id.clone(), request.target.clone());
        {
            let mut retained = self.start_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM start identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Start identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target)
            .await?
            .client
            .start(request)
            .await
    }

    pub(super) async fn dispatch_kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        let identity = (
            request.context.operation_id.clone(),
            request.target.clone(),
            request.signal,
            request.all,
        );
        {
            let mut retained = self.kill_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM kill identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Kill identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.kill_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target)
            .await?
            .client
            .kill(request)
            .await
    }

    pub(super) async fn dispatch_delete(&self, request: DriverDeleteRequest) -> Result<()> {
        let identity = (
            request.context.operation_id.clone(),
            request.target.clone(),
            request.mode,
        );
        {
            let mut retained = self.delete_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM delete identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Delete identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target)
            .await?
            .client
            .delete(request)
            .await
    }
}
