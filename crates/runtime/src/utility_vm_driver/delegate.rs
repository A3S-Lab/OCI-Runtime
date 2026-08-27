macro_rules! delegate_utility_vm_runtime_driver {
    ($driver:ty, $inner:ident) => {
        #[a3s_oci_sdk::async_trait]
        impl $crate::RuntimeDriver for $driver {
            fn capability(&self) -> a3s_oci_core::DriverCapability {
                $crate::RuntimeDriver::capability(&self.$inner)
            }

            fn linux_support(&self) -> a3s_oci_sdk::Result<a3s_oci_sdk::OciLinuxSupport> {
                $crate::RuntimeDriver::linux_support(&self.$inner)
            }

            fn operations(&self) -> &[a3s_oci_sdk::RuntimeOperation] {
                $crate::RuntimeDriver::operations(&self.$inner)
            }

            fn hooks(&self) -> &[$crate::OciHookPhase] {
                $crate::RuntimeDriver::hooks(&self.$inner)
            }

            fn attachment_capabilities(&self) -> a3s_oci_sdk::AttachmentCapabilities {
                $crate::RuntimeDriver::attachment_capabilities(&self.$inner)
            }

            async fn acknowledge_operation(
                &self,
                operation_id: &a3s_oci_sdk::OperationId,
            ) -> a3s_oci_sdk::Result<()> {
                $crate::RuntimeDriver::acknowledge_operation(&self.$inner, operation_id).await
            }

            async fn prepare_create_bundle(
                &self,
                request: &$crate::DriverCreateRequest,
            ) -> a3s_oci_sdk::Result<a3s_oci_sdk::OciBundle> {
                $crate::RuntimeDriver::prepare_create_bundle(&self.$inner, request).await
            }

            async fn recover(
                &self,
                record: &a3s_oci_sdk::ContainerRecord,
            ) -> a3s_oci_sdk::Result<$crate::DriverRecovery> {
                $crate::RuntimeDriver::recover(&self.$inner, record).await
            }

            async fn create(
                &self,
                request: $crate::DriverCreateRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::create(&self.$inner, request).await
            }

            async fn state(
                &self,
                target: a3s_oci_sdk::ContainerTarget,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::state(&self.$inner, target).await
            }

            async fn start(
                &self,
                request: $crate::DriverStartRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::start(&self.$inner, request).await
            }

            async fn kill(
                &self,
                request: $crate::DriverKillRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::kill(&self.$inner, request).await
            }

            async fn delete(
                &self,
                request: $crate::DriverDeleteRequest,
            ) -> a3s_oci_sdk::Result<()> {
                $crate::RuntimeDriver::delete(&self.$inner, request).await
            }

            async fn wait(
                &self,
                request: $crate::DriverWaitRequest,
            ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ExitStatus> {
                $crate::RuntimeDriver::wait(&self.$inner, request).await
            }

            async fn exec(
                &self,
                request: $crate::DriverExecRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverProcess> {
                $crate::RuntimeDriver::exec(&self.$inner, request).await
            }

            async fn signal_process(
                &self,
                request: $crate::DriverSignalProcessRequest,
            ) -> a3s_oci_sdk::Result<()> {
                $crate::RuntimeDriver::signal_process(&self.$inner, request).await
            }

            async fn wait_process(
                &self,
                request: $crate::DriverWaitProcessRequest,
            ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ExitStatus> {
                $crate::RuntimeDriver::wait_process(&self.$inner, request).await
            }

            async fn pause(
                &self,
                request: $crate::DriverContainerOperationRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::pause(&self.$inner, request).await
            }

            async fn resume(
                &self,
                request: $crate::DriverContainerOperationRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::resume(&self.$inner, request).await
            }

            async fn processes(
                &self,
                target: a3s_oci_sdk::ContainerTarget,
            ) -> a3s_oci_sdk::Result<Vec<a3s_oci_sdk::ProcessRecord>> {
                $crate::RuntimeDriver::processes(&self.$inner, target).await
            }

            async fn update(
                &self,
                request: $crate::DriverUpdateRequest,
            ) -> a3s_oci_sdk::Result<$crate::DriverState> {
                $crate::RuntimeDriver::update(&self.$inner, request).await
            }

            async fn stats(
                &self,
                target: a3s_oci_sdk::ContainerTarget,
            ) -> a3s_oci_sdk::Result<a3s_oci_sdk::ContainerStats> {
                $crate::RuntimeDriver::stats(&self.$inner, target).await
            }

            async fn read_output(
                &self,
                request: $crate::DriverReadOutputRequest,
            ) -> a3s_oci_sdk::Result<Vec<a3s_oci_sdk::OutputChunk>> {
                $crate::RuntimeDriver::read_output(&self.$inner, request).await
            }

            async fn write_stdin(
                &self,
                request: $crate::DriverWriteStdinRequest,
            ) -> a3s_oci_sdk::Result<()> {
                $crate::RuntimeDriver::write_stdin(&self.$inner, request).await
            }

            async fn close_stdin(
                &self,
                request: $crate::DriverCloseStdinRequest,
            ) -> a3s_oci_sdk::Result<()> {
                $crate::RuntimeDriver::close_stdin(&self.$inner, request).await
            }

            async fn resize(
                &self,
                request: $crate::DriverResizeRequest,
            ) -> a3s_oci_sdk::Result<()> {
                $crate::RuntimeDriver::resize(&self.$inner, request).await
            }

            async fn file(
                &self,
                request: a3s_oci_sdk::FileRequest,
            ) -> a3s_oci_sdk::Result<a3s_oci_sdk::FileResponse> {
                $crate::RuntimeDriver::file(&self.$inner, request).await
            }

            async fn filesystem(
                &self,
                request: a3s_oci_sdk::FilesystemRequest,
            ) -> a3s_oci_sdk::Result<a3s_oci_sdk::FilesystemResponse> {
                $crate::RuntimeDriver::filesystem(&self.$inner, request).await
            }
        }
    };
}

pub(crate) use delegate_utility_vm_runtime_driver;
