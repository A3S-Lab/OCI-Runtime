use super::*;

impl UtilityVmRuntimeDriver {
    pub(super) async fn create_gate_for(&self, id: &ContainerId) -> Arc<Mutex<()>> {
        let mut gates = self.create_gates.lock().await;
        gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = gates.get(id).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(Mutex::new(()));
        gates.insert(id.clone(), Arc::downgrade(&gate));
        gate
    }

    pub(super) async fn session_gate_for(&self, id: &GuestSessionId) -> Arc<Mutex<()>> {
        let mut gates = self.session_gates.lock().await;
        gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = gates.get(id).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(Mutex::new(()));
        gates.insert(id.clone(), Arc::downgrade(&gate));
        gate
    }

    /// Ensure a reusable-session identity is either owned by this process or
    /// has no persisted incarnation at all.  Session roots outlive the
    /// process that launched a VM, so treating an unowned root as an empty
    /// pool could start a second guest while the original guest is still
    /// alive.  The only exception is a request recorded in `pending`, which
    /// is the handoff window established by `prepare_create_bundle`.
    pub(super) async fn preflight_session_admission(
        &self,
        target: &ContainerTarget,
        binding: &GuestSessionAttachment,
    ) -> Result<()> {
        require_exact_generation(target, "preflight-utility-vm-guest-session")?;

        let (retained, pending) = {
            let sessions = self.sessions.lock().await;
            let retained = sessions
                .reusable
                .get(binding.id())
                .map(|session| session.attachment.clone());
            let pending = sessions
                .pending
                .values()
                .filter(|entry| entry.attachment.id() == binding.id())
                .cloned()
                .collect::<Vec<_>>();
            (retained, pending)
        };

        // An in-process owner is authoritative; the normal admission path
        // performs the finer generation, trust, capacity, and reset checks.
        if retained.is_some() {
            return Ok(());
        }

        if let Some(pending) = pending
            .iter()
            .find(|pending| pending.attachment != *binding)
        {
            return Err(session_conflict(
                binding,
                &pending.attachment,
                "another create request is transferring a different ownership contract",
            ));
        }
        if !pending.is_empty() {
            return Ok(());
        }

        if let Some(root) =
            existing_reusable_guest_session_identity_root(&self.runtime_share_root, binding).await?
        {
            return Err(orphaned_session_error(binding, &root));
        }
        Ok(())
    }

    pub(super) async fn remember_pending_session(
        &self,
        target: &ContainerTarget,
        binding: &GuestSessionAttachment,
    ) -> Result<()> {
        let mut sessions = self.sessions.lock().await;
        if let Some(existing) = sessions.pending.values().find(|existing| {
            existing.attachment.id() == binding.id() && existing.attachment != *binding
        }) {
            return Err(session_conflict(
                binding,
                &existing.attachment,
                "another create request is transferring a different ownership contract",
            ));
        }
        if let Some(existing) = sessions.pending.get(&target.id) {
            if existing.target != *target || existing.attachment != *binding {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    format!(
                        "container {} already has a different pending reusable guest-session admission",
                        target.id
                    ),
                )
                .for_operation("utility-vm-create"));
            }
        }
        sessions.pending.insert(
            target.id.clone(),
            PendingGuestSessionAdmission {
                target: target.clone(),
                attachment: binding.clone(),
            },
        );
        Ok(())
    }

    pub(super) async fn clear_pending_session(
        &self,
        target: &ContainerTarget,
        binding: &GuestSessionAttachment,
    ) {
        let mut sessions = self.sessions.lock().await;
        if matches!(
            sessions.pending.get(&target.id),
            Some(existing) if existing.target == *target && existing.attachment == *binding
        ) {
            sessions.pending.remove(&target.id);
        }
    }

    pub(super) fn validate_create_contract(&self, request: &DriverCreateRequest) -> Result<()> {
        let isolation = request.isolation.class();
        if isolation == IsolationClass::SharedHostKernel
            || !self.capability.isolation_classes.contains(&isolation)
        {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "the {} driver does not advertise {:?} isolation",
                    self.backend_name, isolation
                ),
            )
            .for_operation("utility-vm-create"));
        }
        request
            .attachment_contract
            .validate_isolation(&request.isolation)?;
        self.attachment_capabilities
            .require(&request.attachment_contract)?;
        require_exact_generation(&request.target, "utility-vm-create")?;
        if !request.attachment_contract.uses_runtime_bundle_handoff() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "{} create requires runtime ownership handoff for its OCI bundle",
                    self.backend_name
                ),
            )
            .for_operation("utility-vm-create"));
        }
        Ok(())
    }

    pub(super) async fn attachment_for(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<UtilityVmAttachment> {
        require_exact_generation(target, operation)?;
        let sessions = self.sessions.lock().await;
        let attachment = sessions
            .attachments
            .get(&target.id)
            .cloned()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unavailable,
                    format!(
                    "container {} has neither an attached utility VM nor a recovered stop record",
                    target.id
                ),
                )
                .for_operation(operation)
            })?;
        if attachment.target() != target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} is attached at generation {:?}, not {:?}",
                    target.id,
                    attachment.target().generation,
                    target.generation
                ),
            )
            .for_operation(operation));
        }
        Ok(attachment)
    }

    pub(super) async fn live_session_for(
        &self,
        target: &ContainerTarget,
        operation: &'static str,
    ) -> Result<Arc<UtilityVmContainer>> {
        match self.attachment_for(target, operation).await? {
            UtilityVmAttachment::Live(container) => Ok(container),
            UtilityVmAttachment::RecoveredStopped { .. } => {
                Err(recovered_stopped_error(target, operation))
            }
        }
    }

    pub(super) async fn existing_create_session(
        &self,
        target: &ContainerTarget,
        guest_session: Option<&GuestSessionAttachment>,
    ) -> Result<Option<Arc<UtilityVmContainer>>> {
        let sessions = self.sessions.lock().await;
        let Some(attachment) = sessions.attachments.get(&target.id) else {
            return Ok(None);
        };
        if attachment.target() != target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} already owns a utility-VM attachment at generation {:?}",
                    target.id,
                    attachment.target().generation
                ),
            )
            .for_operation("utility-vm-create"));
        }
        if attachment.guest_session() != guest_session {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} already owns a different utility-VM guest-session binding",
                    target.id
                ),
            )
            .for_operation("utility-vm-create"));
        }
        match attachment {
            UtilityVmAttachment::Live(container) => Ok(Some(Arc::clone(container))),
            UtilityVmAttachment::RecoveredStopped { .. } => {
                Err(recovered_stopped_error(target, "utility-vm-create"))
            }
        }
    }

    pub(super) async fn launch_guest(
        &self,
        target: &ContainerTarget,
        bundle: &OciBundle,
        guest_bundle: &GuestPath,
        attachment_contract: &CreateAttachments,
    ) -> Result<Arc<UtilityVmGuest>> {
        let guest_session = attachment_contract.guest_session();
        let runtime_share = self.handoff.mount_root(target, guest_session).await?;
        let request = UtilityVmLaunchRequest {
            target,
            runtime_share: &runtime_share,
            bundle,
            guest_bundle,
            attachment_contract,
        };
        request.validate()?;
        let launched = self.factory.launch(request).await?;
        Ok(Arc::new(UtilityVmGuest {
            client: launched.client,
            owner: launched.owner,
        }))
    }

    pub(super) async fn replace_guest_with_stopped(
        &self,
        expected: &Arc<UtilityVmGuest>,
    ) -> Option<(GuestSessionAttachment, bool)> {
        let mut sessions = self.sessions.lock().await;
        let mut member_count = 0_usize;
        for attachment in sessions.attachments.values_mut() {
            let UtilityVmAttachment::Live(container) = attachment else {
                continue;
            };
            if Arc::ptr_eq(&container.guest, expected) {
                member_count += 1;
                *attachment = UtilityVmAttachment::RecoveredStopped {
                    target: container.target.clone(),
                    guest_session: container.guest_session.clone(),
                    init_exit_status: None,
                };
            }
        }
        let reusable_id = sessions
            .reusable
            .iter()
            .find_map(|(id, session)| Arc::ptr_eq(&session.guest, expected).then(|| id.clone()));
        reusable_id.and_then(|id| {
            sessions
                .reusable
                .remove(&id)
                .map(|session| (session.attachment, member_count != 0))
        })
    }

    pub(super) async fn remove_stopped(&self, target: &ContainerTarget) {
        let mut sessions = self.sessions.lock().await;
        sessions.pending.remove(&target.id);
        if matches!(
            sessions.attachments.get(&target.id),
            Some(UtilityVmAttachment::RecoveredStopped { target: current, .. }) if current == target
        ) {
            sessions.attachments.remove(&target.id);
        }
    }

    pub(super) async fn session_root_is_unowned(&self, binding: &GuestSessionAttachment) -> bool {
        let sessions = self.sessions.lock().await;
        !sessions
            .reusable
            .get(binding.id())
            .is_some_and(|session| session.attachment == *binding)
            && !sessions
                .pending
                .values()
                .any(|entry| entry.attachment == *binding)
    }

    pub(super) async fn admit_new_container(
        &self,
        target: &ContainerTarget,
        bundle: &OciBundle,
        guest_bundle: &GuestPath,
        attachment_contract: &CreateAttachments,
    ) -> Result<Arc<UtilityVmContainer>> {
        let guest_session = attachment_contract.guest_session();
        let Some(binding) = guest_session else {
            let guest = self
                .launch_guest(target, bundle, guest_bundle, attachment_contract)
                .await?;
            let cleanup_guest = Arc::clone(&guest);
            let mut launch_cleanup = super::DetachedAsyncCleanup::new(move || async move {
                if let Err(error) = super::shutdown_guest(&cleanup_guest).await {
                    eprintln!("a3s-oci-runtime: cancelled guest launch cleanup failed: {error}");
                }
            });
            let container = Arc::new(UtilityVmContainer {
                target: target.clone(),
                guest_session: None,
                guest,
            });
            self.sessions.lock().await.attachments.insert(
                target.id.clone(),
                UtilityVmAttachment::Live(Arc::clone(&container)),
            );
            launch_cleanup.disarm();
            return Ok(container);
        };

        let generation = require_exact_generation(target, "utility-vm-create")?;
        self.preflight_session_admission(target, binding).await?;

        let retained = {
            let sessions = self.sessions.lock().await;
            sessions.reusable.get(binding.id()).map(|session| {
                (
                    session.attachment.clone(),
                    Arc::clone(&session.guest),
                    session.members.len(),
                )
            })
        };
        if let Some((retained_binding, guest, member_count)) = retained {
            if retained_binding == *binding {
                if member_count >= usize::from(binding.capacity().get()) {
                    return Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        format!(
                            "reusable guest session {} generation {} reached its capacity of {} members",
                            binding.id(),
                            binding.generation(),
                            binding.capacity()
                        ),
                    )
                    .for_operation("utility-vm-create"));
                }
                return self.attach_reusable_member(target, binding, guest).await;
            }
            if binding.generation() <= retained_binding.generation() {
                return Err(session_conflict(
                    binding,
                    &retained_binding,
                    "the requested incarnation is stale or changes an existing generation",
                ));
            }
            if member_count != 0 {
                return Err(session_conflict(
                    binding,
                    &retained_binding,
                    "the retained incarnation still has live members",
                ));
            }

            // Reaping the previous incarnation is destructive, but the
            // remainder of rotation still has several asynchronous
            // publication/cleanup boundaries.  Keep an idempotent detached
            // fallback armed until the old session has been removed from the
            // in-memory registry.  If the create caller disappears at any
            // point in that window, the old owner is still reaped and a later
            // retry can finish the metadata transition.
            let cleanup_guest = Arc::clone(&guest);
            let mut rotation_cleanup = super::DetachedAsyncCleanup::new(move || async move {
                if let Err(error) = super::shutdown_guest(&cleanup_guest).await {
                    eprintln!(
                        "a3s-oci-runtime: cancelled reusable-session rotation cleanup failed: {error}"
                    );
                }
            });
            shutdown_guest(&guest).await?;
            self.recovery.remove_session(&retained_binding).await?;
            self.handoff
                .cleanup_empty_session(&retained_binding)
                .await?;
            let mut sessions = self.sessions.lock().await;
            if matches!(
                sessions.reusable.get(binding.id()),
                Some(current)
                    if current.attachment == retained_binding
                        && current.members.is_empty()
                        && Arc::ptr_eq(&current.guest, &guest)
            ) {
                sessions.reusable.remove(binding.id());
                rotation_cleanup.disarm();
            } else {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    format!(
                        "reusable guest session {} changed while rotating its empty incarnation",
                        binding.id()
                    ),
                )
                .for_operation("utility-vm-create"));
            }
        }

        let guest = self
            .launch_guest(target, bundle, guest_bundle, attachment_contract)
            .await?;
        let cleanup_guest = Arc::clone(&guest);
        let mut launch_cleanup = super::DetachedAsyncCleanup::new(move || async move {
            if let Err(error) = super::shutdown_guest(&cleanup_guest).await {
                eprintln!("a3s-oci-runtime: cancelled guest launch cleanup failed: {error}");
            }
        });
        let container = Arc::new(UtilityVmContainer {
            target: target.clone(),
            guest_session: Some(binding.clone()),
            guest: Arc::clone(&guest),
        });
        let mut sessions = self.sessions.lock().await;
        sessions.reusable.insert(
            binding.id().clone(),
            ReusableGuestSession::new(binding.clone(), guest, target, generation),
        );
        sessions.attachments.insert(
            target.id.clone(),
            UtilityVmAttachment::Live(Arc::clone(&container)),
        );
        launch_cleanup.disarm();
        Ok(container)
    }

    pub(super) async fn attach_reusable_member(
        &self,
        target: &ContainerTarget,
        binding: &GuestSessionAttachment,
        guest: Arc<UtilityVmGuest>,
    ) -> Result<Arc<UtilityVmContainer>> {
        let generation = require_exact_generation(target, "utility-vm-create")?;
        let mut sessions = self.sessions.lock().await;
        let retained = sessions.reusable.get_mut(binding.id()).ok_or_else(|| {
            Error::new(
                ErrorCode::Conflict,
                format!(
                    "reusable guest session {} disappeared during admission",
                    binding.id()
                ),
            )
            .for_operation("utility-vm-create")
        })?;
        if retained.attachment != *binding {
            return Err(session_conflict(
                binding,
                &retained.attachment,
                "the retained ownership contract changed during admission",
            ));
        }
        if !Arc::ptr_eq(&retained.guest, &guest) {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "reusable guest session {} changed owners during admission",
                    binding.id()
                ),
            )
            .for_operation("utility-vm-create"));
        }
        if retained.members.len() >= usize::from(binding.capacity().get()) {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                format!(
                    "reusable guest session {} generation {} reached its capacity of {} members",
                    binding.id(),
                    binding.generation(),
                    binding.capacity()
                ),
            )
            .for_operation("utility-vm-create"));
        }
        if retained.members.contains_key(&target.id) {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "reusable guest session {} already tracks container {} without an attachment",
                    binding.id(),
                    target.id
                ),
            )
            .for_operation("utility-vm-create"));
        }
        retained.members.insert(target.id.clone(), generation);
        let container = Arc::new(UtilityVmContainer {
            target: target.clone(),
            guest_session: Some(binding.clone()),
            guest,
        });
        sessions.attachments.insert(
            target.id.clone(),
            UtilityVmAttachment::Live(Arc::clone(&container)),
        );
        Ok(container)
    }

    pub(super) async fn cleanup_terminal_create(
        &self,
        container: &Arc<UtilityVmContainer>,
        mut error: Error,
    ) -> Error {
        if let Some(binding) = container.guest_session.as_ref() {
            self.clear_pending_session(&container.target, binding).await;
        }
        let mut remove_session = container.guest_session.is_none();
        if let Some(binding) = container.guest_session.as_ref() {
            let last_destroy_member = {
                let sessions = self.sessions.lock().await;
                sessions.reusable.get(binding.id()).is_some_and(|session| {
                    session.attachment == *binding
                        && session.members.len() == 1
                        && session.members.contains_key(&container.target.id)
                        && binding.reset() == GuestSessionReset::DestroyOnEmpty
                })
            };
            remove_session = last_destroy_member;
        }
        let mut guest_cleanup = if remove_session {
            let cleanup_guest = Arc::clone(&container.guest);
            Some(super::DetachedAsyncCleanup::new(move || async move {
                if let Err(error) = super::shutdown_guest(&cleanup_guest).await {
                    eprintln!("a3s-oci-runtime: cancelled terminal-create cleanup failed: {error}");
                }
            }))
        } else {
            None
        };
        if remove_session {
            if let Err(cleanup) = shutdown_guest(&container.guest).await {
                error.message = format!(
                    "{}; failed to reap the utility VM: {}",
                    error.message, cleanup
                );
                return error;
            }
        }

        {
            let mut sessions = self.sessions.lock().await;
            if matches!(
                sessions.attachments.get(&container.target.id),
                Some(UtilityVmAttachment::Live(current)) if Arc::ptr_eq(current, container)
            ) {
                sessions.attachments.remove(&container.target.id);
            }
            if let Some(binding) = container.guest_session.as_ref() {
                if let Some(session) = sessions.reusable.get_mut(binding.id()) {
                    if session.attachment == *binding
                        && Arc::ptr_eq(&session.guest, &container.guest)
                    {
                        session.members.remove(&container.target.id);
                    }
                }
                if remove_session {
                    sessions.reusable.remove(binding.id());
                }
            }
        }
        if let Some(cleanup) = guest_cleanup.as_mut() {
            // The owner is no longer referenced by the live registry after
            // this mutation.  Disarm before the next await so a cancelled
            // recovery/handoff cleanup cannot issue an unnecessary second
            // owner shutdown.
            cleanup.disarm();
        }

        let recovery_cleanup = match container.guest_session.as_ref() {
            Some(binding) if remove_session => self.recovery.remove_session(binding).await,
            Some(_) => Ok(()),
            None => self.recovery.remove(&container.target, None).await,
        };
        for cleanup in [
            recovery_cleanup,
            self.handoff
                .cleanup(
                    &container.target,
                    container.guest_session.as_ref(),
                    remove_session,
                )
                .await,
        ] {
            if let Err(cleanup) = cleanup {
                error.message = format!("{}; cleanup failed: {}", error.message, cleanup);
            }
        }
        error
    }
}
