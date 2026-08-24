use super::*;

const DELETE_SHIM_WAIT_TIMEOUT: Duration = Duration::from_secs(2);

#[async_trait]
impl Shim for Service {
    type T = Service;

    async fn new(_runtime_id: &str, args: &Flags, _config: &mut Config) -> Self {
        let requested_bundle = if args.bundle.is_empty() {
            std::env::current_dir().unwrap_or_default()
        } else {
            PathBuf::from(&args.bundle)
        };
        let (bundle, restore_error) = match tokio::fs::canonicalize(&requested_bundle).await {
            Ok(bundle) => (bundle, None),
            Err(error) => (
                requested_bundle.clone(),
                Some(
                    RuntimeError::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "failed to resolve containerd shim bundle {}: {error}",
                            requested_bundle.display()
                        ),
                    )
                    .for_operation("containerd-shim-bundle"),
                ),
            ),
        };
        Self {
            namespace: args.namespace.clone(),
            task_id: args.id.clone(),
            endpoint: Self::endpoint_from_environment(),
            bundle,
            exit: Arc::new(ExitSignal::default()),
            state: Arc::new(Mutex::new(ServiceState {
                restore_error,
                ..ServiceState::default()
            })),
            metadata_gate: Arc::new(Mutex::new(())),
            monitors: Arc::new(Mutex::new(BTreeMap::new())),
            exit_notify: Arc::new(Notify::new()),
            publisher: None,
            #[cfg(test)]
            test_adapter: Arc::new(Mutex::new(None)),
        }
    }

    async fn start_shim(&mut self, opts: StartOpts) -> Result<String, Error> {
        let grouping = opts.id.clone();
        spawn(opts, &grouping, Vec::new()).await
    }

    async fn delete_shim(&mut self) -> Result<api::DeleteResponse, Error> {
        self.stop_all_monitors().await;
        self.stop_all_pumps().await;
        let mut response = api::DeleteResponse::new();
        let metadata = ShimMetadata::load(&self.metadata_path())
            .map_err(|error| Error::FailedPreconditionError(error.to_string()))?;
        if let Some(metadata) = metadata {
            let identity = metadata
                .identity()
                .map_err(|error| Error::FailedPreconditionError(error.to_string()))?;
            let mut task_delete_receipt = match TaskDeleteReceipt::load(metadata.bundle())
                .map_err(|error| Error::FailedPreconditionError(error.to_string()))?
            {
                Some(receipt)
                    if receipt
                        .matches_for(&identity, metadata.generation(), metadata.bundle())
                        .map_err(|error| Error::FailedPreconditionError(error.to_string()))? =>
                {
                    Some(receipt)
                }
                Some(_) => {
                    TaskDeleteReceipt::remove(metadata.bundle())
                        .map_err(|error| Error::Other(error.to_string()))?;
                    None
                }
                None => None,
            };
            let adapter = self
                .adapter()
                .await
                .map_err(|error| Error::Other(error.to_string()))?;
            let record = match adapter.exact_state(&identity, metadata.generation()).await {
                Ok(record) => Some(record),
                Err(error) if error.code == ErrorCode::NotFound => {
                    match adapter
                        .delete(&identity, metadata.generation(), false)
                        .await
                    {
                        Ok(()) => {}
                        Err(error) if error.code == ErrorCode::NotFound => adapter
                            .delete(&identity, metadata.generation(), true)
                            .await
                            .map_err(|error| Error::Other(error.to_string()))?,
                        Err(error) => return Err(Error::Other(error.to_string())),
                    }
                    None
                }
                Err(error) => return Err(Error::Other(error.to_string())),
            };
            if record.is_some() && task_delete_receipt.is_some() {
                TaskDeleteReceipt::remove(metadata.bundle())
                    .map_err(|error| Error::Other(error.to_string()))?;
                task_delete_receipt = None;
            }
            if let Some(observed) = record.as_ref() {
                if observed.state.id() != identity.container_id.as_str()
                    || observed.generation != metadata.generation()
                    || observed.driver != metadata.driver()
                    || observed.isolation != metadata.isolation()
                {
                    return Err(Error::FailedPreconditionError(
                        "runtime state no longer matches the persisted containerd shim identity, generation, driver, or isolation"
                            .to_string(),
                    ));
                }
            }
            let pid = record.as_ref().map_or(0, record_pid);
            let mut exit = metadata.exit().cloned();
            if record.as_ref().is_some_and(ContainerRecord::is_paused) {
                adapter
                    .delete(&identity, metadata.generation(), true)
                    .await
                    .map_err(|error| Error::Other(error.to_string()))?;
            } else if record.is_some() {
                if exit.is_none() {
                    let _ = adapter
                        .kill(&identity, metadata.generation(), 9, true)
                        .await;
                    exit = tokio::time::timeout(
                        DELETE_SHIM_WAIT_TIMEOUT,
                        adapter.wait(&identity, metadata.generation()),
                    )
                    .await
                    .ok()
                    .and_then(|result| result.ok());
                }
                adapter
                    .delete(&identity, metadata.generation(), true)
                    .await
                    .map_err(|error| Error::Other(error.to_string()))?;
            }
            ShimCreateIntent::remove(metadata.bundle())
                .map_err(|error| Error::Other(error.to_string()))?;
            if metadata.rootfs_mounted() {
                Self::unmount_rootfs(metadata.bundle().join("rootfs"))
                    .await
                    .map_err(Error::from)?;
            }
            ExecDeleteJournal::remove(metadata.bundle())
                .map_err(|error| Error::Other(error.to_string()))?;
            ShimMetadata::remove(metadata.bundle())
                .map_err(|error| Error::Other(error.to_string()))?;
            if let Some(receipt) = task_delete_receipt.as_ref() {
                response = task_delete_response(receipt)
                    .map(|(response, _)| response)
                    .map_err(|error| Error::FailedPreconditionError(error.to_string()))?;
            } else {
                response.set_pid(pid);
                response.set_exit_status(exit.as_ref().map_or(137, adapter::exit_code));
                response.set_exited_at(timestamp_from(
                    metadata
                        .exited_at_unix_nanos()
                        .and_then(system_time_from_unix_nanos)
                        .unwrap_or_else(SystemTime::now),
                ));
            }
        } else if let Some(intent) =
            ShimCreateIntent::load(&ShimCreateIntent::path(&self.bundle))
                .map_err(|error| Error::FailedPreconditionError(error.to_string()))?
        {
            let identity = intent
                .identity()
                .map_err(|error| Error::FailedPreconditionError(error.to_string()))?;
            let adapter = self
                .adapter()
                .await
                .map_err(|error| Error::Other(error.to_string()))?
                .with_isolation(intent.isolation().clone());
            let record = adapter
                .replay_create_for_cleanup(
                    &identity,
                    intent.bundle(),
                    adapter::process_io(
                        intent.terminal(),
                        !intent.stdin().is_empty(),
                        !intent.stdout().is_empty(),
                        !intent.stderr().is_empty(),
                    ),
                )
                .await
                .map_err(|error| Error::Other(error.to_string()))?;
            let pid = record_pid(&record);
            let _ = adapter.kill(&identity, record.generation, 9, true).await;
            let exit = tokio::time::timeout(
                DELETE_SHIM_WAIT_TIMEOUT,
                adapter.wait(&identity, record.generation),
            )
            .await
            .ok()
            .and_then(|result| result.ok());
            adapter
                .delete(&identity, record.generation, true)
                .await
                .map_err(|error| Error::Other(error.to_string()))?;
            ShimCreateIntent::remove(intent.bundle())
                .map_err(|error| Error::Other(error.to_string()))?;
            if intent.rootfs_mounted() {
                Self::unmount_rootfs(intent.bundle().join("rootfs"))
                    .await
                    .map_err(Error::from)?;
            }
            ExecDeleteJournal::remove(intent.bundle())
                .map_err(|error| Error::Other(error.to_string()))?;
            TaskDeleteReceipt::remove(intent.bundle())
                .map_err(|error| Error::Other(error.to_string()))?;
            response.set_pid(pid);
            response.set_exit_status(exit.as_ref().map_or(137, adapter::exit_code));
            response.set_exited_at(timestamp_now());
        } else {
            ExecDeleteJournal::remove(&self.bundle)
                .map_err(|error| Error::Other(error.to_string()))?;
            if let Some(receipt) = TaskDeleteReceipt::load(&self.bundle)
                .map_err(|error| Error::FailedPreconditionError(error.to_string()))?
            {
                receipt
                    .validate_for_service(&self.namespace, &self.task_id, &self.bundle)
                    .map_err(|error| Error::FailedPreconditionError(error.to_string()))?;
                response = task_delete_response(&receipt)
                    .map(|(response, _)| response)
                    .map_err(|error| Error::FailedPreconditionError(error.to_string()))?;
            } else {
                response.set_exited_at(timestamp_now());
            }
        }
        Ok(response)
    }

    async fn wait(&mut self) {
        self.exit.wait().await;
    }

    async fn create_task_service(&self, publisher: RemotePublisher) -> Self::T {
        let mut service = self.clone();
        service.publisher = Some(Arc::new(publisher));
        if !service.task_id.is_empty() {
            if let Err(error) = service.restore_task(&service.task_id).await {
                log::error!("failed to rehydrate containerd shim state: {error}");
                service.state.lock().await.restore_error = Some(error);
            }
        }
        service
    }
}
