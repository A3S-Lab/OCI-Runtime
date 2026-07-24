use std::collections::BTreeSet;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::time::Duration;

use a3s_oci_agent_protocol::AgentVsockEndpoint;
use a3s_oci_core::CapabilityStatus;
use tokio::time::{sleep, Instant};

use crate::agent_socket::PRIVATE_TMP_ROOT;
use crate::{AgentVmSmokeReport, MacosHostCleanupEvidence};

const PROCESS_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// One-shot host-resource baseline for a macOS guest-agent VM session.
#[derive(Debug)]
pub(crate) struct MacosHostCleanupTracker {
    descriptors_before: Result<BTreeSet<(i32, u32)>, String>,
}

impl MacosHostCleanupTracker {
    /// Capture the current process descriptor inventory before a VM session.
    pub(crate) fn capture() -> Self {
        Self {
            descriptors_before: open_descriptor_inventory(),
        }
    }

    /// Attach fail-closed cleanup evidence after every session resource was released.
    pub(crate) async fn apply(self, report: &mut AgentVmSmokeReport) {
        let descriptors_after = open_descriptor_inventory();
        let mut reasons = Vec::new();

        let endpoint_removed = match exact_endpoint_removed(report).await {
            Ok(true) => true,
            Ok(false) => {
                reasons.push(format!(
                    "runtime-owned Unix endpoint {} remained after session cleanup",
                    report.endpoint_name.as_deref().unwrap_or("<unknown>")
                ));
                false
            }
            Err(error) => {
                reasons.push(error);
                false
            }
        };

        let (descriptor_inventory_restored, open_descriptors_before, open_descriptors_after) =
            match (self.descriptors_before, descriptors_after) {
                (Ok(before), Ok(after)) => (
                    before == after,
                    descriptor_count(&before),
                    descriptor_count(&after),
                ),
                (Err(error), Ok(after)) => {
                    reasons.push(format!(
                        "failed to capture pre-session descriptor inventory: {error}"
                    ));
                    (false, None, descriptor_count(&after))
                }
                (Ok(before), Err(error)) => {
                    reasons.push(format!(
                        "failed to capture post-session descriptor inventory: {error}"
                    ));
                    (false, descriptor_count(&before), None)
                }
                (Err(before_error), Err(after_error)) => {
                    reasons.push(format!(
                        "failed to capture pre-session descriptor inventory: {before_error}"
                    ));
                    reasons.push(format!(
                        "failed to capture post-session descriptor inventory: {after_error}"
                    ));
                    (false, None, None)
                }
            };

        if !descriptor_inventory_restored {
            reasons.push(format!(
                "open descriptor inventory changed (count {open_descriptors_before:?} to \
                 {open_descriptors_after:?})"
            ));
        }

        let shim_reaped = process_reaped(report.shim_process_id, !report.shim_spawned).await;
        if !shim_reaped {
            reasons.push(match report.shim_process_id {
                Some(process_id) => {
                    format!("libkrun shim PID {process_id} remained after session cleanup")
                }
                None => "spawned libkrun shim had no process ID to verify".into(),
            });
        }

        let bridge_reaped =
            process_reaped(report.bridge_process_id, !report.shim_client_verified).await;
        if !bridge_reaped {
            reasons.push(match report.bridge_process_id {
                Some(process_id) => {
                    format!("libkrun VM worker PID {process_id} remained after session cleanup")
                }
                None => "verified libkrun VM worker had no process ID to verify".into(),
            });
        }

        let evidence = MacosHostCleanupEvidence {
            endpoint_removed,
            shim_reaped,
            bridge_reaped,
            open_descriptors_before,
            open_descriptors_after,
            descriptor_inventory_restored,
            reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
        };
        let cleanup_succeeded = evidence.is_success();
        let cleanup_reason = evidence.reason.clone();
        report.macos_cleanup = Some(evidence);

        if !cleanup_succeeded {
            report.status = CapabilityStatus::Unavailable;
            append_reason(
                report,
                format!(
                    "macOS host cleanup verification failed: {}",
                    cleanup_reason.unwrap_or_else(|| "incomplete cleanup evidence".into())
                ),
            );
        }
    }
}

async fn exact_endpoint_removed(report: &AgentVmSmokeReport) -> Result<bool, String> {
    let Some(directory) = endpoint_directory(report)? else {
        return Ok(true);
    };
    match tokio::fs::symlink_metadata(&directory).await {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!(
            "failed to inspect runtime-owned Unix endpoint {} after cleanup: {error}",
            directory.display()
        )),
    }
}

fn endpoint_directory(report: &AgentVmSmokeReport) -> Result<Option<PathBuf>, String> {
    let Some(endpoint_name) = report.endpoint_name.as_deref() else {
        return if report.endpoint_bound {
            Err("bound Unix endpoint has no exact endpoint name for cleanup verification".into())
        } else {
            Ok(None)
        };
    };
    let endpoint = AgentVsockEndpoint::new(endpoint_name.to_string()).map_err(|error| {
        format!("reported Unix endpoint name is invalid and cannot be verified: {error}")
    })?;
    Ok(Some(Path::new(PRIVATE_TMP_ROOT).join(endpoint.pipe_name())))
}

fn open_descriptor_inventory() -> Result<BTreeSet<(i32, u32)>, String> {
    // SAFETY: `getpid` has no preconditions.
    let process_id = unsafe { libc::getpid() };
    // SAFETY: a null output buffer and zero size request the byte count needed
    // for `PROC_PIDLISTFDS`; no memory is read or written.
    let bytes = unsafe { libc::proc_pidinfo(process_id, libc::PROC_PIDLISTFDS, 0, null_mut(), 0) };
    if bytes < 0 {
        return Err(format!(
            "failed to count open descriptors for PID {process_id}: {}",
            io::Error::last_os_error()
        ));
    }
    let bytes = usize::try_from(bytes)
        .map_err(|error| format!("invalid descriptor inventory size: {error}"))?;
    let entry_size = size_of::<libc::proc_fdinfo>();
    if bytes % entry_size != 0 {
        return Err(format!(
            "descriptor inventory returned {bytes} bytes, not a multiple of {entry_size}"
        ));
    }
    let capacity = bytes
        .checked_add(entry_size * 16)
        .and_then(|bytes| bytes.checked_div(entry_size))
        .ok_or_else(|| "descriptor inventory capacity overflowed".to_string())?;
    let buffer_bytes = capacity
        .checked_mul(entry_size)
        .and_then(|bytes| libc::c_int::try_from(bytes).ok())
        .ok_or_else(|| "descriptor inventory buffer is not representable".to_string())?;
    let mut entries = Vec::<MaybeUninit<libc::proc_fdinfo>>::with_capacity(capacity);
    // SAFETY: `entries` owns an aligned allocation of `buffer_bytes`; the
    // kernel writes at most that many bytes and reports the initialized prefix.
    let bytes_read = unsafe {
        libc::proc_pidinfo(
            process_id,
            libc::PROC_PIDLISTFDS,
            0,
            entries.as_mut_ptr().cast(),
            buffer_bytes,
        )
    };
    if bytes_read < 0 {
        return Err(format!(
            "failed to read open descriptors for PID {process_id}: {}",
            io::Error::last_os_error()
        ));
    }
    let bytes_read = usize::try_from(bytes_read)
        .map_err(|error| format!("invalid descriptor inventory result: {error}"))?;
    if bytes_read > usize::try_from(buffer_bytes).unwrap_or_default()
        || bytes_read % entry_size != 0
    {
        return Err(format!(
            "descriptor inventory wrote an invalid {bytes_read}-byte result"
        ));
    }
    let initialized = bytes_read / entry_size;
    // SAFETY: `proc_pidinfo` reported `initialized` complete entries in the
    // aligned buffer, and `MaybeUninit` permits setting exactly that prefix.
    unsafe {
        entries.set_len(initialized);
    }
    Ok(entries
        .into_iter()
        .map(|entry| {
            // SAFETY: every retained entry belongs to the initialized prefix.
            let entry = unsafe { entry.assume_init() };
            (entry.proc_fd, entry.proc_fdtype)
        })
        .collect())
}

fn descriptor_count(descriptors: &BTreeSet<(i32, u32)>) -> Option<u32> {
    u32::try_from(descriptors.len()).ok()
}

async fn process_reaped(process_id: Option<u32>, absent_is_valid: bool) -> bool {
    let Some(process_id) = process_id else {
        return absent_is_valid;
    };
    let deadline = Instant::now() + PROCESS_REAP_TIMEOUT;
    loop {
        match process_exists(process_id) {
            Ok(false) => return true,
            Ok(true) if Instant::now() < deadline => sleep(PROCESS_POLL_INTERVAL).await,
            Ok(true) | Err(_) => return false,
        }
    }
}

fn process_exists(process_id: u32) -> Result<bool, String> {
    let process_id = libc::pid_t::try_from(process_id)
        .map_err(|error| format!("invalid process ID {process_id}: {error}"))?;
    // SAFETY: signal zero changes no process state and only checks whether the
    // exact process identifier still exists.
    if unsafe { libc::kill(process_id, 0) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else if error.raw_os_error() == Some(libc::EPERM) {
        Ok(true)
    } else {
        Err(format!(
            "failed to inspect process ID {process_id}: {error}"
        ))
    }
}

fn append_reason(report: &mut AgentVmSmokeReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::{Command, Stdio};

    use a3s_oci_agent_protocol::AgentVsockEndpoint;
    use a3s_oci_core::HostPlatform;

    use super::{endpoint_directory, MacosHostCleanupTracker};
    use crate::agent_socket::PRIVATE_TMP_ROOT;
    use crate::{AgentVmSmokeReport, MacosAgentSocketListener};

    const CHILD_ENV: &str = "A3S_OCI_TEST_HOST_CLEANUP_CHILD";
    const CHILD_TEST_NAME: &str = "host_cleanup::tests::isolated_cleanup_child";

    #[test]
    fn listener_drop_removes_exact_endpoint_and_restores_descriptor_inventory() {
        let output = Command::new(std::env::current_exe().expect("resolve test executable"))
            .args(["--exact", CHILD_TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .expect("run isolated cleanup child");
        assert!(
            output.status.success(),
            "isolated cleanup child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn bound_endpoint_without_an_exact_name_fails_closed() {
        let mut report = AgentVmSmokeReport::initial(HostPlatform::Macos);
        report.endpoint_bound = true;
        let error = endpoint_directory(&report)
            .expect_err("bound endpoint without its exact name must not pass verification");
        assert!(error.contains("no exact endpoint name"), "{error}");
    }

    #[test]
    fn isolated_cleanup_child() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        std::env::remove_var(CHILD_ENV);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build isolated cleanup runtime");
        runtime.block_on(async {
            let tracker = MacosHostCleanupTracker::capture();
            let listener = MacosAgentSocketListener::bind(
                AgentVsockEndpoint::generate().expect("generate endpoint"),
            )
            .expect("bind private macOS endpoint");
            let endpoint_name = listener.endpoint().pipe_name().to_string();
            let directory = listener.directory().to_path_buf();
            let socket = listener.socket_path().to_path_buf();
            let unrelated_endpoint = tempfile::Builder::new()
                .prefix("a3s-oci-agent-unrelated-")
                .tempdir_in(PRIVATE_TMP_ROOT)
                .expect("create unrelated endpoint-shaped directory");
            drop(listener);
            assert!(!directory.exists());
            assert!(!socket.exists());
            assert!(unrelated_endpoint.path().exists());

            let mut report = AgentVmSmokeReport::initial(HostPlatform::Macos);
            report.endpoint_bound = true;
            report.endpoint_name = Some(endpoint_name);
            tracker.apply(&mut report).await;
            let evidence = report
                .macos_cleanup
                .as_ref()
                .expect("macOS cleanup evidence");
            assert!(evidence.is_success(), "{evidence:?}");
            assert!(evidence.endpoint_removed);
            assert!(unrelated_endpoint.path().exists());
            drop(unrelated_endpoint);

            let tracker = MacosHostCleanupTracker::capture();
            let remaining_endpoint =
                AgentVsockEndpoint::generate().expect("generate remaining endpoint");
            let remaining_directory =
                Path::new(PRIVATE_TMP_ROOT).join(remaining_endpoint.pipe_name());
            tokio::fs::create_dir(&remaining_directory)
                .await
                .expect("create endpoint residue");
            let mut report = AgentVmSmokeReport::initial(HostPlatform::Macos);
            report.endpoint_bound = true;
            report.endpoint_name = Some(remaining_endpoint.pipe_name().to_string());
            tracker.apply(&mut report).await;
            let evidence = report
                .macos_cleanup
                .as_ref()
                .expect("macOS cleanup evidence");
            assert!(!evidence.endpoint_removed);
            assert!(!evidence.is_success());
            assert!(
                evidence
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("remained after session cleanup")),
                "{evidence:?}"
            );
            tokio::fs::remove_dir(&remaining_directory)
                .await
                .expect("remove endpoint residue");
        });
    }
}
