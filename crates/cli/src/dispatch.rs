use std::future::Future;
use std::pin::Pin;
use std::process::ExitCode;

use a3s_oci_sdk::RuntimeClient;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use crate::macos_hvf_service;
#[cfg(target_os = "linux")]
use crate::native_service;
use crate::reopen_replacement;
use crate::{write_json, Cli, CliError, Command};

pub(super) type CommandFuture = Pin<Box<dyn Future<Output = Result<ExitCode, CliError>>>>;

// Prevent the synchronous selector from reserving one stack slot large enough
// for the biggest concrete command future before it knows which branch won.
#[inline(never)]
fn boxed_command<Factory, Command>(factory: Factory) -> CommandFuture
where
    Factory: FnOnce() -> Command,
    Command: Future<Output = Result<ExitCode, CliError>> + 'static,
{
    Box::pin(factory())
}

macro_rules! command_future {
    ($body:block) => {
        boxed_command(move || async move $body)
    };
}

pub(super) fn run(
    cli: Cli,
    rootless_device_policy_bootstrap: Option<a3s_oci_runtime::RootlessDevicePolicyBootstrap>,
) -> CommandFuture {
    dispatch(cli, rootless_device_policy_bootstrap)
}

fn dispatch(
    cli: Cli,
    rootless_device_policy_bootstrap: Option<a3s_oci_runtime::RootlessDevicePolicyBootstrap>,
) -> CommandFuture {
    #[cfg(target_os = "linux")]
    let mut rootless_device_policy_bootstrap = rootless_device_policy_bootstrap;
    #[cfg(not(target_os = "linux"))]
    let _ = rootless_device_policy_bootstrap;
    match cli.command {
        Command::Features => command_future!({
            let client = RuntimeClient::new(a3s_oci_runtime::HostRuntimeService::new());
            let info = Box::pin(client.features()).await?;
            write_json(&info.drivers)?;
            Ok(ExitCode::SUCCESS)
        }),
        Command::WhpxSmoke => command_future!({
            let report = a3s_oci_runtime::whpx_smoke();
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::HvfSmoke => command_future!({
            let report = a3s_oci_runtime::hvf_smoke();
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::NativeLinuxSmoke {
            agent,
            bundle,
            work_parent,
        } => command_future!({
            let report = a3s_oci_runtime::native_linux_smoke(&agent, &bundle, &work_parent).await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::NativeLinuxRootlessSmoke {
            agent,
            bundle,
            work_parent,
            delegated_cgroup_root,
            rootless_device_bootstrap,
            post_open_ready_file,
            post_open_continue_file,
        } => command_future!({
            #[cfg(target_os = "linux")]
            let report = if rootless_device_bootstrap {
                let bootstrap = rootless_device_policy_bootstrap.take().ok_or_else(|| {
                    a3s_oci_sdk::Error::new(
                        a3s_oci_sdk::ErrorCode::FailedPrecondition,
                        "rootless command did not complete synchronous device bootstrap",
                    )
                    .for_operation("rootless-device-bootstrap")
                })?;
                a3s_oci_runtime::native_linux_rootless_smoke_with_device_bootstrap_barrier(
                    &agent,
                    &bundle,
                    &work_parent,
                    bootstrap,
                    post_open_ready_file.as_deref(),
                    post_open_continue_file.as_deref(),
                )
                .await
            } else {
                a3s_oci_runtime::native_linux_rootless_smoke_with_cgroup_delegation_barrier(
                    &agent,
                    &bundle,
                    &work_parent,
                    delegated_cgroup_root.as_deref(),
                    post_open_ready_file.as_deref(),
                    post_open_continue_file.as_deref(),
                )
                .await
            };
            #[cfg(not(target_os = "linux"))]
            let report = {
                let _ = rootless_device_bootstrap;
                a3s_oci_runtime::native_linux_rootless_smoke_with_cgroup_delegation_barrier(
                    &agent,
                    &bundle,
                    &work_parent,
                    delegated_cgroup_root.as_deref(),
                    post_open_ready_file.as_deref(),
                    post_open_continue_file.as_deref(),
                )
                .await
            };
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        #[cfg(target_os = "linux")]
        Command::NativeLinuxRootlessDevicePolicySmoke {
            agent,
            bundle,
            work_parent,
            delegated_cgroup_root: _,
        } => command_future!({
            let bootstrap = rootless_device_policy_bootstrap.take().ok_or_else(|| {
                a3s_oci_sdk::Error::new(
                    a3s_oci_sdk::ErrorCode::FailedPrecondition,
                    "rootless device-policy command did not complete synchronous bootstrap",
                )
                .for_operation("rootless-device-policy")
            })?;
            let report = a3s_oci_runtime::native_linux_rootless_device_policy_smoke(
                &agent,
                &bundle,
                &work_parent,
                bootstrap,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        #[cfg(target_os = "linux")]
        Command::NativeLinuxHostService { root, agent } => command_future!({
            native_service::run_host(root, agent).await?;
            Ok(ExitCode::SUCCESS)
        }),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        Command::MacosHvfHostService {
            root,
            shim,
            system_image_manifest,
        } => command_future!({
            macos_hvf_service::run(root, shim, system_image_manifest).await?;
            Ok(ExitCode::SUCCESS)
        }),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        Command::MacosHvfHostServiceSmoke {
            shim,
            system_image_manifest,
            bundle,
            work_parent,
            iterations,
            source_revision,
        } => command_future!({
            let executable = std::env::current_exe().map_err(CliError::CurrentExecutable)?;
            let report = a3s_oci_runtime::macos_hvf_host_service_smoke(
                a3s_oci_runtime::MacosHvfHostServiceSmokeConfig {
                    host_service_executable: executable,
                    shim,
                    system_image_manifest,
                    bundle,
                    work_parent,
                    iterations,
                    source_revision: Some(source_revision),
                },
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        #[cfg(target_os = "linux")]
        Command::NativeLinuxRecoveryOwner {
            agent,
            root,
            bundle,
            container_id,
            ready_file,
            delegated_cgroup_root,
            rootless_device_bootstrap,
        } => command_future!({
            if rootless_device_bootstrap {
                let bootstrap = rootless_device_policy_bootstrap.take().ok_or_else(|| {
                    a3s_oci_sdk::Error::new(
                        a3s_oci_sdk::ErrorCode::FailedPrecondition,
                        "rootless recovery owner did not complete synchronous device bootstrap",
                    )
                    .for_operation("rootless-device-bootstrap")
                })?;
                a3s_oci_runtime::native_linux_recovery_owner_with_device_bootstrap(
                    &agent,
                    &root,
                    &bundle,
                    container_id,
                    &ready_file,
                    bootstrap,
                )
                .await?;
            } else {
                a3s_oci_runtime::native_linux_recovery_owner_with_cgroup_delegation(
                    &agent,
                    &root,
                    &bundle,
                    container_id,
                    &ready_file,
                    delegated_cgroup_root.as_deref(),
                )
                .await?;
            }
            Ok(ExitCode::SUCCESS)
        }),
        #[cfg(target_os = "linux")]
        Command::NativeLinuxRecoveryResume {
            agent,
            root,
            bundle,
            container_id,
            generation,
            delegated_cgroup_root,
            rootless_device_bootstrap,
        } => command_future!({
            let generation = a3s_oci_sdk::Generation(generation);
            let target = a3s_oci_sdk::ContainerTarget::exact(container_id, generation);
            let report = if rootless_device_bootstrap {
                let bootstrap = rootless_device_policy_bootstrap.take().ok_or_else(|| {
                    a3s_oci_sdk::Error::new(
                        a3s_oci_sdk::ErrorCode::FailedPrecondition,
                        "rootless recovery resume did not complete synchronous device bootstrap",
                    )
                    .for_operation("rootless-device-bootstrap")
                })?;
                a3s_oci_runtime::native_linux_recovery_resume_with_device_bootstrap(
                    &agent, &root, &bundle, target, bootstrap,
                )
                .await
            } else {
                a3s_oci_runtime::native_linux_recovery_resume_with_cgroup_delegation(
                    &agent,
                    &root,
                    &bundle,
                    target,
                    delegated_cgroup_root.as_deref(),
                )
                .await
            };
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        #[cfg(target_os = "linux")]
        Command::NativeLinuxService {
            root,
            agent,
            container_id,
            a3s_box_control_fds: _,
        } => command_future!({
            native_service::run(root, agent, container_id).await?;
            Ok(ExitCode::SUCCESS)
        }),
        Command::NativeLinuxServiceSmoke {
            agent,
            bundle,
            work_parent,
        } => command_future!({
            let report =
                a3s_oci_runtime::native_linux_service_smoke(&agent, &bundle, &work_parent).await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::NativeLinuxMultiContainerSmoke {
            agent,
            bundle_a,
            bundle_b,
            work_parent,
        } => command_future!({
            let report = a3s_oci_runtime::native_linux_multi_container_smoke(
                &agent,
                &bundle_a,
                &bundle_b,
                &work_parent,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::NativeLinuxSoak {
            agent,
            bundles,
            work_parent,
            iterations,
            concurrent_containers,
            operation_timeout_ms,
        } => command_future!({
            let report = a3s_oci_runtime::native_linux_soak(
                &agent,
                &bundles,
                &work_parent,
                a3s_oci_runtime::NativeLinuxSoakConfig::new(
                    iterations,
                    concurrent_containers,
                    operation_timeout_ms,
                ),
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::NativeLinuxFaultCleanup {
            agent,
            bundle,
            work_parent,
            fault_after,
        } => command_future!({
            let report = a3s_oci_runtime::native_linux_fault_cleanup(
                &agent,
                &bundle,
                &work_parent,
                fault_after.into(),
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::AgentVmSmoke {
            shim,
            rootfs,
            system_image_manifest,
            runtime_share,
            console,
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            qualify_kvm_post_probe_failure,
        } => command_future!({
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            let report = if qualify_kvm_post_probe_failure {
                a3s_oci_runtime::qualify_kvm_post_probe_failure(
                    &shim,
                    &rootfs,
                    system_image_manifest.as_deref(),
                    runtime_share.as_deref(),
                    &console,
                )
                .await
            } else {
                a3s_oci_runtime::agent_vm_smoke(
                    &shim,
                    &rootfs,
                    system_image_manifest.as_deref(),
                    runtime_share.as_deref(),
                    &console,
                )
                .await
            };
            #[cfg(not(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )))]
            let report = a3s_oci_runtime::agent_vm_smoke(
                &shim,
                &rootfs,
                system_image_manifest.as_deref(),
                runtime_share.as_deref(),
                &console,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::OciVmSmoke {
            shim,
            vm_rootfs,
            system_image_manifest,
            runtime_share,
            bundle,
            console,
        } => command_future!({
            let report = a3s_oci_runtime::oci_vm_smoke(
                &shim,
                &vm_rootfs,
                system_image_manifest.as_deref(),
                runtime_share.as_deref(),
                &bundle,
                &console,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::WhpxDriverSmoke {
            shim,
            runtime_root,
            vm_rootfs,
            system_image_manifest,
            bundle,
            container_id,
            generation,
        } => command_future!({
            let target = a3s_oci_sdk::ContainerTarget::exact(
                container_id,
                a3s_oci_sdk::Generation(generation),
            );
            let report = a3s_oci_runtime::whpx_driver_smoke(
                &shim,
                &runtime_root,
                &vm_rootfs,
                &system_image_manifest,
                &bundle,
                target,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::BoxWhpxQualificationService {
            shim,
            runtime_root,
            vm_rootfs,
            system_image_manifest,
            state_root,
            pipe,
            ready_file,
        } => command_future!({
            let mut config = a3s_oci_runtime::BoxWhpxServiceConfig::new(
                shim,
                runtime_root,
                vm_rootfs,
                system_image_manifest,
                state_root,
                pipe,
            );
            if let Some(ready_file) = ready_file {
                config = config.with_ready_file(ready_file);
            }
            a3s_oci_runtime::serve_box_whpx_qualification(config, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
            Ok(ExitCode::SUCCESS)
        }),
        Command::WhpxRecoveryOwner {
            shim,
            runtime_root,
            vm_rootfs,
            system_image_manifest,
            state_root,
            bundle,
            container_id,
            ready_file,
        } => command_future!({
            a3s_oci_runtime::whpx_recovery_owner(a3s_oci_runtime::WhpxRecoveryOwnerConfig {
                shim: &shim,
                runtime_root: &runtime_root,
                vm_rootfs: &vm_rootfs,
                system_image_manifest: &system_image_manifest,
                state_root: &state_root,
                bundle: &bundle,
                container_id,
                ready_file: &ready_file,
            })
            .await?;
            Ok(ExitCode::SUCCESS)
        }),
        Command::WhpxRecoveryResume {
            shim,
            runtime_root,
            vm_rootfs,
            system_image_manifest,
            state_root,
            bundle,
            container_id,
            generation,
        } => command_future!({
            let target = a3s_oci_sdk::ContainerTarget::exact(
                container_id,
                a3s_oci_sdk::Generation(generation),
            );
            let report = a3s_oci_runtime::whpx_recovery_resume(
                &shim,
                &runtime_root,
                &vm_rootfs,
                &system_image_manifest,
                &state_root,
                &bundle,
                target,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::OciVmMultiContainerSmoke {
            shim,
            vm_rootfs,
            system_image_manifest,
            runtime_share,
            bundle_a,
            bundle_b,
            console,
        } => command_future!({
            let report = a3s_oci_runtime::oci_vm_multi_container_smoke(
                &shim,
                &vm_rootfs,
                system_image_manifest.as_deref(),
                runtime_share.as_deref(),
                &bundle_a,
                &bundle_b,
                &console,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::MacosHvfSoak {
            shim,
            vm_rootfs,
            system_image_manifest,
            bundle_a,
            bundle_b,
            console_dir,
            iterations,
        } => command_future!({
            let report = a3s_oci_runtime::macos_hvf_soak(
                &shim,
                &vm_rootfs,
                &system_image_manifest,
                &bundle_a,
                &bundle_b,
                &console_dir,
                a3s_oci_runtime::MacosHvfSoakConfig::new(iterations),
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::WindowsOciVmMultiContainerSmoke {
            shim,
            vm_rootfs,
            system_image_manifest,
            runtime_share,
            bundle_a,
            bundle_b,
            console,
        } => command_future!({
            let report = a3s_oci_runtime::windows_oci_vm_multi_container_smoke(
                &shim,
                &vm_rootfs,
                &system_image_manifest,
                &runtime_share,
                &bundle_a,
                &bundle_b,
                &console,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::OciVmFaultCleanup {
            shim,
            vm_rootfs,
            system_image_manifest,
            runtime_share,
            bundle,
            console,
            fault_after,
        } => command_future!({
            let report = a3s_oci_runtime::oci_vm_fault_cleanup(
                &shim,
                &vm_rootfs,
                system_image_manifest.as_deref(),
                runtime_share.as_deref(),
                &bundle,
                &console,
                fault_after.into(),
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::OciVmTransportFaultCleanup {
            shim,
            vm_rootfs,
            system_image_manifest,
            runtime_share,
            bundle,
            console,
            fault_at,
        } => command_future!({
            let report = a3s_oci_runtime::oci_vm_transport_fault_cleanup(
                &shim,
                &vm_rootfs,
                system_image_manifest.as_deref(),
                runtime_share.as_deref(),
                &bundle,
                &console,
                a3s_oci_runtime::AgentTransportFaultStage::from(fault_at),
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }),
        Command::OciVmReopenReplacement(arguments) => {
            command_future!({ reopen_replacement::run(arguments).await })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{run, Cli, Command};

    #[test]
    fn command_dispatch_future_stays_heap_bounded() {
        let future = run(
            Cli {
                command: Command::Features,
            },
            None,
        );

        assert_eq!(
            std::mem::size_of_val(&future),
            2 * std::mem::size_of::<usize>()
        );
    }

    #[test]
    fn command_dispatch_constructs_on_a_small_stack() {
        let worker = std::thread::Builder::new()
            .name("bounded-command-dispatch".to_string())
            .stack_size(256 * 1024)
            .spawn(|| {
                drop(run(
                    Cli {
                        command: Command::Features,
                    },
                    None,
                ));
            })
            .expect("spawn bounded command-dispatch worker");

        worker
            .join()
            .expect("command dispatch must not overflow a bounded stack");
    }
}
