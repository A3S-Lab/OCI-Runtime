use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::AGENT_RUNTIME_SHARE_TAG;
use a3s_oci_core::CapabilityStatus;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

use crate::context::KrunContext;
use crate::windows_system_image::WindowsSystemImage;
use crate::{
    fallback_config, AgentVsockEndpoint, WhpxHandleReclamationSample,
    WhpxHandleReclamationSmokeReport, WHPX_HANDLE_RECLAMATION_ALLOWED_FINAL_DELTA,
};

const MAX_ITERATIONS: u16 = 64;
const WORKLOAD_TOKEN: &str = "a3s-oci-whpx-handle-reclamation-v1";
const WINDOWS_RETURN_ON_EXIT_ENV: &str = "LIBKRUN_WINDOWS_RETURN_ON_EXIT";

/// Run repeated complete WHPX VM entries without allowing process teardown to
/// hide native handle leaks.
pub(crate) fn run(
    rootfs: &Path,
    system_image_manifest: &Path,
    runtime_share: &Path,
    console_directory: &Path,
    iterations: u16,
) -> WhpxHandleReclamationSmokeReport {
    let mut report = WhpxHandleReclamationSmokeReport::initial(
        iterations,
        WHPX_HANDLE_RECLAMATION_ALLOWED_FINAL_DELTA,
    );
    if iterations == 0 || iterations > MAX_ITERATIONS {
        report.reason = Some(format!(
            "WHPX handle-reclamation iterations must be between 1 and {MAX_ITERATIONS}; \
             requested {iterations}"
        ));
        return report;
    }

    let rootfs = match canonical_directory(rootfs, "portable OCI rootfs") {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let runtime_share = match canonical_directory(runtime_share, "writable runtime share") {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let console_directory = match canonical_directory(console_directory, "console directory") {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    if console_directory == runtime_share
        || console_directory.starts_with(&runtime_share)
        || runtime_share.starts_with(&console_directory)
    {
        return failed(
            report,
            "console evidence and the writable runtime share must be disjoint".into(),
        );
    }

    let system_image_manifest =
        match canonical_file(system_image_manifest, "Windows system-image manifest") {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        };
    let system_image = match WindowsSystemImage::load(&system_image_manifest) {
        Ok(image) => image,
        Err(error) => return failed(report, error.to_string()),
    };
    if paths_overlap(&runtime_share, system_image.image_path())
        || paths_overlap(&runtime_share, &system_image_manifest)
    {
        return failed(
            report,
            "the immutable Windows system image and writable runtime share must be disjoint".into(),
        );
    }
    report.windows_boot_assets = Some(system_image.evidence());

    let baseline_entries = match directory_entries(&runtime_share) {
        Ok(entries) => entries,
        Err(reason) => return failed(report, reason),
    };
    report.cold_handle_count = match current_process_handle_count() {
        Ok(count) => Some(count),
        Err(reason) => return failed(report, reason),
    };

    let _return_on_exit = ReturnOnExitEnvironment::enable();
    let mut warmup = run_cycle(
        &rootfs,
        &system_image,
        &runtime_share,
        &console_directory,
        0,
        true,
    );
    let baseline = match current_process_handle_count() {
        Ok(count) => count,
        Err(reason) => {
            warmup.reason.get_or_insert(reason.clone());
            report.warmup = Some(warmup);
            return failed(report, reason);
        }
    };
    warmup.process_handle_count = Some(baseline);
    warmup.handle_delta_from_baseline = Some(0);
    report.baseline_handle_count = Some(baseline);
    report.peak_post_cycle_handle_count = Some(baseline);
    let warmup_succeeded = warmup.is_success();
    if !warmup_succeeded {
        let reason = warmup
            .reason
            .clone()
            .unwrap_or_else(|| "WHPX warmup VM did not satisfy the lifecycle contract".into());
        report.warmup = Some(warmup);
        return finish_failed(report, &runtime_share, &baseline_entries, reason);
    }
    report.warmup = Some(warmup);

    for iteration in 1..=iterations {
        let mut sample = run_cycle(
            &rootfs,
            &system_image,
            &runtime_share,
            &console_directory,
            iteration,
            false,
        );
        let handle_count = match current_process_handle_count() {
            Ok(count) => count,
            Err(reason) => {
                sample.reason.get_or_insert(reason.clone());
                report.samples.push(sample);
                return finish_failed(report, &runtime_share, &baseline_entries, reason);
            }
        };
        sample.process_handle_count = Some(handle_count);
        sample.handle_delta_from_baseline = Some(i64::from(handle_count) - i64::from(baseline));
        report.peak_post_cycle_handle_count = Some(
            report
                .peak_post_cycle_handle_count
                .unwrap_or(baseline)
                .max(handle_count),
        );
        let succeeded = sample.is_success();
        let failure = sample.reason.clone();
        report.samples.push(sample);
        if !succeeded {
            return finish_failed(
                report,
                &runtime_share,
                &baseline_entries,
                failure.unwrap_or_else(|| {
                    format!("WHPX VM iteration {iteration} did not satisfy the lifecycle contract")
                }),
            );
        }
        report.completed_iterations = iteration;
    }

    let final_count = match current_process_handle_count() {
        Ok(count) => count,
        Err(reason) => return finish_failed(report, &runtime_share, &baseline_entries, reason),
    };
    report.final_handle_count = Some(final_count);
    report.final_handle_delta = Some(i64::from(final_count) - i64::from(baseline));
    report.peak_post_cycle_handle_count = Some(
        report
            .peak_post_cycle_handle_count
            .unwrap_or(baseline)
            .max(final_count),
    );
    report.runtime_share_restored =
        directory_entries(&runtime_share).is_ok_and(|entries| entries == baseline_entries);

    if !report.runtime_share_restored {
        report.reason =
            Some("the WHPX workload left an entry in the writable runtime share".into());
        return report;
    }
    if final_count > baseline.saturating_add(report.allowed_final_handle_delta) {
        report.reason = Some(format!(
            "WHPX native handles did not return to the warmed baseline: baseline={baseline}, \
             peak={}, final={final_count}, allowed_delta={}",
            report.peak_post_cycle_handle_count.unwrap_or(final_count),
            report.allowed_final_handle_delta,
        ));
        return report;
    }

    report.status = CapabilityStatus::Available;
    report
}

fn run_cycle(
    rootfs: &Path,
    system_image: &WindowsSystemImage,
    runtime_share: &Path,
    console_directory: &Path,
    iteration: u16,
    warmup: bool,
) -> WhpxHandleReclamationSample {
    let phase = if warmup {
        "warmup".to_string()
    } else {
        format!("iteration-{iteration:02}")
    };
    let console_file = console_directory.join(format!("{phase}.console.log"));
    let marker_name = format!(
        ".a3s-oci-whpx-handle-reclamation-{}-{iteration}",
        std::process::id()
    );
    let marker = runtime_share.join(&marker_name);
    let mut sample = WhpxHandleReclamationSample {
        iteration,
        warmup,
        console_file: console_file.clone(),
        guest_exit_code: None,
        marker_verified: false,
        marker_removed: false,
        console_created: false,
        process_handle_count: None,
        handle_delta_from_baseline: None,
        reason: None,
    };

    if marker.exists() {
        sample.reason = Some(format!(
            "refusing to overwrite an existing WHPX reclamation marker: {}",
            marker.display()
        ));
        return sample;
    }
    if console_file.exists() {
        sample.reason = Some(format!(
            "refusing to overwrite existing WHPX console evidence: {}",
            console_file.display()
        ));
        return sample;
    }

    let endpoint_name = format!(
        "a3s-oci-whpx-handle-reclamation-{}-{iteration}",
        std::process::id()
    );
    let endpoint = match AgentVsockEndpoint::new(endpoint_name) {
        Ok(endpoint) => endpoint,
        Err(error) => return cycle_failed(sample, error.to_string()),
    };
    let mut context = match KrunContext::create() {
        Ok(context) => context,
        Err(error) => return cycle_failed(sample, error.to_string()),
    };
    if let Err(error) = context.set_vm_config(fallback_config()) {
        return cycle_failed(sample, error.to_string());
    }
    if let Err(error) = context.set_root(rootfs) {
        return cycle_failed(sample, error.to_string());
    }
    if let Err(error) = context.set_root_disk(system_image.image_path()) {
        return cycle_failed(sample, error.to_string());
    }
    if let Err(error) = context.add_virtiofs(AGENT_RUNTIME_SHARE_TAG, runtime_share) {
        return cycle_failed(sample, error.to_string());
    }
    if let Err(error) = context.set_agent_vsock(&endpoint) {
        return cycle_failed(sample, error.to_string());
    }
    if let Err(error) = context.set_workdir("/") {
        return cycle_failed(sample, error.to_string());
    }

    let marker_guest_path = format!("/run/a3s-oci-runtime/{marker_name}");
    let command = format!(
        "mount -t virtiofs {AGENT_RUNTIME_SHARE_TAG} /run/a3s-oci-runtime && \
         printf '%s\\n' '{WORKLOAD_TOKEN}' > '{marker_guest_path}' && \
         sync && printf '%s\\n' '{WORKLOAD_TOKEN}'"
    );
    let arguments = vec!["-c".to_string(), command];
    if let Err(error) = context.set_exec("/bin/sh", &arguments, &[]) {
        return cycle_failed(sample, error.to_string());
    }
    if let Err(error) = context.set_console_output(&console_file) {
        return cycle_failed(sample, error.to_string());
    }
    if let Err(error) = system_image.reverify() {
        return cycle_failed(sample, error.to_string());
    }

    match context.start_enter() {
        Ok(exit_code) => sample.guest_exit_code = Some(exit_code),
        Err(error) => {
            sample.reason = Some(error.to_string());
        }
    }
    sample.console_created = console_file.is_file();
    match fs::read_to_string(&marker) {
        Ok(contents) if contents == format!("{WORKLOAD_TOKEN}\n") => {
            sample.marker_verified = true;
        }
        Ok(contents) => {
            sample.reason = Some(format!(
                "WHPX reclamation marker had unexpected contents ({} bytes)",
                contents.len()
            ));
        }
        Err(error) => {
            sample.reason.get_or_insert_with(|| {
                format!(
                    "failed to read WHPX reclamation marker {}: {error}",
                    marker.display()
                )
            });
        }
    }
    if marker.exists() {
        match fs::remove_file(&marker) {
            Ok(()) => sample.marker_removed = true,
            Err(error) => {
                sample.reason.get_or_insert_with(|| {
                    format!(
                        "failed to remove WHPX reclamation marker {}: {error}",
                        marker.display()
                    )
                });
            }
        }
    }
    if sample.guest_exit_code != Some(0) {
        sample.reason.get_or_insert_with(|| {
            format!(
                "WHPX reclamation workload returned exit status {:?}",
                sample.guest_exit_code
            )
        });
    }
    if !sample.console_created {
        sample
            .reason
            .get_or_insert_with(|| "WHPX reclamation console evidence was not created".into());
    }
    sample
}

fn current_process_handle_count() -> Result<u32, String> {
    let mut count = 0u32;
    // SAFETY: GetCurrentProcess returns the calling process pseudo-handle and
    // count points to writable storage for the duration of the call.
    let succeeded = unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) };
    if succeeded == 0 {
        Err(format!(
            "GetProcessHandleCount failed: {}",
            io::Error::last_os_error()
        ))
    } else {
        Ok(count)
    }
}

fn canonical_directory(path: &Path, description: &str) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect {description} {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.file_type().is_dir()
    {
        return Err(format!(
            "{description} must be a real directory, not a link: {}",
            path.display()
        ));
    }
    path.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize {description} {}: {error}",
            path.display()
        )
    })
}

fn canonical_file(path: &Path, description: &str) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect {description} {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.file_type().is_file()
    {
        return Err(format!(
            "{description} must be a real file, not a link: {}",
            path.display()
        ));
    }
    path.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize {description} {}: {error}",
            path.display()
        )
    })
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn directory_entries(path: &Path) -> Result<BTreeSet<OsString>, String> {
    fs::read_dir(path)
        .map_err(|error| {
            format!(
                "failed to inventory writable runtime share {}: {error}",
                path.display()
            )
        })?
        .map(|entry| {
            entry.map(|entry| entry.file_name()).map_err(|error| {
                format!(
                    "failed to read a writable runtime-share entry in {}: {error}",
                    path.display()
                )
            })
        })
        .collect()
}

fn cycle_failed(
    mut sample: WhpxHandleReclamationSample,
    reason: String,
) -> WhpxHandleReclamationSample {
    sample.reason = Some(reason);
    sample
}

fn failed(
    mut report: WhpxHandleReclamationSmokeReport,
    reason: String,
) -> WhpxHandleReclamationSmokeReport {
    report.reason = Some(reason);
    report
}

fn finish_failed(
    mut report: WhpxHandleReclamationSmokeReport,
    runtime_share: &Path,
    baseline_entries: &BTreeSet<OsString>,
    reason: String,
) -> WhpxHandleReclamationSmokeReport {
    report.final_handle_count = current_process_handle_count().ok();
    report.final_handle_delta = report
        .baseline_handle_count
        .zip(report.final_handle_count)
        .map(|(baseline, final_count)| i64::from(final_count) - i64::from(baseline));
    report.runtime_share_restored =
        directory_entries(runtime_share).is_ok_and(|entries| entries == *baseline_entries);
    report.reason = Some(reason);
    report
}

struct ReturnOnExitEnvironment {
    previous: Option<OsString>,
}

impl ReturnOnExitEnvironment {
    fn enable() -> Self {
        let previous = std::env::var_os(WINDOWS_RETURN_ON_EXIT_ENV);
        std::env::set_var(WINDOWS_RETURN_ON_EXIT_ENV, OsStr::new("1"));
        Self { previous }
    }
}

impl Drop for ReturnOnExitEnvironment {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::env::set_var(WINDOWS_RETURN_ON_EXIT_ENV, previous);
        } else {
            std::env::remove_var(WINDOWS_RETURN_ON_EXIT_ENV);
        }
    }
}
