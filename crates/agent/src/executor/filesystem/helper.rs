use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use a3s_oci_sdk::{
    Error, ErrorCode, FileRequest, FileResponse, FilesystemRequest, FilesystemResponse, Result,
    ValidateRequest, MAX_FILE_TRANSFER_BYTES,
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::time::timeout;

use super::{file_in_view, filesystem_error, filesystem_in_view, RootView};
use crate::executor::namespace::{become_user_namespace_root, RetainedExecutionContext};
use crate::executor::pid_supervisor;

const FILESYSTEM_MODE: &str = "container-filesystem";
const FILESYSTEM_HELPER_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HELPER_MESSAGE_BYTES: usize = MAX_FILE_TRANSFER_BYTES * 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "kebab-case")]
enum HelperRequest {
    File(FileRequest),
    Filesystem(FilesystemRequest),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "kebab-case")]
enum HelperResponse {
    File(Result<FileResponse>),
    Filesystem(Result<FilesystemResponse>),
}

pub(super) async fn file(
    executable: &Path,
    context: &RetainedExecutionContext,
    request: &FileRequest,
) -> Result<FileResponse> {
    match call(executable, context, HelperRequest::File(request.clone())).await? {
        HelperResponse::File(result) => result,
        HelperResponse::Filesystem(_) => Err(helper_error(
            ErrorCode::Internal,
            "filesystem helper returned the wrong response kind",
        )),
    }
}

pub(super) async fn filesystem(
    executable: &Path,
    context: &RetainedExecutionContext,
    request: &FilesystemRequest,
) -> Result<FilesystemResponse> {
    match call(
        executable,
        context,
        HelperRequest::Filesystem(request.clone()),
    )
    .await?
    {
        HelperResponse::Filesystem(result) => result,
        HelperResponse::File(_) => Err(helper_error(
            ErrorCode::Internal,
            "filesystem helper returned the wrong response kind",
        )),
    }
}

async fn call(
    executable: &Path,
    context: &RetainedExecutionContext,
    request: HelperRequest,
) -> Result<HelperResponse> {
    let request = serde_json::to_vec(&request).map_err(|error| {
        helper_error(
            ErrorCode::Internal,
            format!("failed to encode filesystem helper request: {error}"),
        )
    })?;
    if request.len() > MAX_HELPER_MESSAGE_BYTES {
        return Err(helper_error(
            ErrorCode::ResourceExhausted,
            format!(
                "filesystem helper request is {} bytes; maximum is {MAX_HELPER_MESSAGE_BYTES}",
                request.len()
            ),
        ));
    }

    let namespaces = context
        .namespace_arguments()
        .into_iter()
        .filter(|namespace| {
            matches!(
                namespace.clone_flag,
                libc::CLONE_NEWUSER | libc::CLONE_NEWNS
            )
        })
        .collect::<Vec<_>>();
    let mut inherited = Vec::with_capacity(namespaces.len() + 1);
    inherited.push(context.root_descriptor());
    inherited.extend(namespaces.iter().map(|namespace| namespace.descriptor));
    validate_inherited_descriptors(&inherited)?;

    let mut command = Command::new(executable);
    command
        .arg(FILESYSTEM_MODE)
        .arg(context.root_descriptor().to_string())
        .arg(std::process::id().to_string());
    for namespace in &namespaces {
        command.arg(format!(
            "{}:{}:{}",
            namespace.name, namespace.clone_flag, namespace.descriptor
        ));
    }
    command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // SAFETY: this callback runs after fork in the command child and changes
    // only close-on-exec flags in that child's descriptor table.
    unsafe {
        command.pre_exec(move || make_descriptors_inheritable(&inherited));
    }
    let mut child = command.spawn().map_err(|error| {
        helper_error(
            ErrorCode::Internal,
            format!("failed to spawn container filesystem helper: {error}"),
        )
    })?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        helper_error(
            ErrorCode::Internal,
            "container filesystem helper stdin was not piped",
        )
    })?;
    if let Err(error) = stdin.write_all(&request).await {
        terminate(&mut child).await;
        return Err(helper_error(
            ErrorCode::Unavailable,
            format!("failed to send container filesystem helper request: {error}"),
        ));
    }
    drop(stdin);

    let output = timeout(FILESYSTEM_HELPER_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| {
            helper_error(
                ErrorCode::DeadlineExceeded,
                "container filesystem helper exceeded its bounded execution time",
            )
        })?
        .map_err(|error| {
            helper_error(
                ErrorCode::Internal,
                format!("failed to wait for container filesystem helper: {error}"),
            )
        })?;
    if !output.status.success() {
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        let diagnostic = diagnostic.trim();
        return Err(helper_error(
            ErrorCode::FailedPrecondition,
            if diagnostic.is_empty() {
                format!("container filesystem helper exited with {}", output.status)
            } else {
                format!(
                    "container filesystem helper exited with {}: {diagnostic}",
                    output.status
                )
            },
        ));
    }
    if output.stdout.len() > MAX_HELPER_MESSAGE_BYTES {
        return Err(helper_error(
            ErrorCode::ResourceExhausted,
            "container filesystem helper response exceeded its bounded size",
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        helper_error(
            ErrorCode::Internal,
            format!("container filesystem helper returned an invalid response: {error}"),
        )
    })
}

async fn terminate(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

fn validate_inherited_descriptors(descriptors: &[RawFd]) -> Result<()> {
    let mut unique = BTreeSet::new();
    if descriptors
        .iter()
        .any(|descriptor| *descriptor <= libc::STDERR_FILENO || !unique.insert(*descriptor))
    {
        return Err(helper_error(
            ErrorCode::Internal,
            "container filesystem helper received invalid or duplicate retained descriptors",
        ));
    }
    Ok(())
}

fn make_descriptors_inheritable(descriptors: &[RawFd]) -> std::io::Result<()> {
    for descriptor in descriptors {
        // SAFETY: each descriptor is live in the child descriptor table.
        let flags = unsafe { libc::fcntl(*descriptor, libc::F_GETFD) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: F_SETFD changes only this child-side descriptor table.
        if unsafe { libc::fcntl(*descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(super) fn run_if_requested() -> Option<Result<()>> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(OsStr::new(FILESYSTEM_MODE)) {
        return None;
    }
    Some(parse_helper_arguments(arguments).and_then(run_helper))
}

#[derive(Debug)]
struct HelperArguments {
    root: File,
    expected_parent: libc::pid_t,
    namespaces: Vec<HelperNamespace>,
}

#[derive(Debug)]
struct HelperNamespace {
    name: &'static str,
    clone_flag: libc::c_int,
    descriptor: File,
}

#[derive(Debug)]
struct RawHelperNamespace {
    name: &'static str,
    clone_flag: libc::c_int,
    descriptor: RawFd,
}

fn parse_helper_arguments(arguments: impl Iterator<Item = OsString>) -> Result<HelperArguments> {
    let arguments = arguments.collect::<Vec<_>>();
    if arguments.len() < 2 {
        return Err(helper_error(
            ErrorCode::InvalidArgument,
            "container-filesystem requires ROOTFD PARENTPID [NAMESPACE...]",
        ));
    }
    let root = parse_descriptor(&arguments[0], "root descriptor")?;
    let expected_parent = parse_positive_pid(&arguments[1], "parent PID")?;
    let mut descriptors = BTreeSet::from([root]);
    let mut last_order = None;
    let mut namespaces = Vec::new();
    for encoded in &arguments[2..] {
        let encoded = encoded
            .to_str()
            .ok_or_else(|| invalid_namespace("non-UTF-8"))?;
        let mut parts = encoded.split(':');
        let name = parts.next().unwrap_or_default();
        let flag = parts
            .next()
            .and_then(|value| value.parse::<libc::c_int>().ok())
            .ok_or_else(|| invalid_namespace(encoded))?;
        let descriptor = parts
            .next()
            .and_then(|value| value.parse::<RawFd>().ok())
            .filter(|descriptor| *descriptor > libc::STDERR_FILENO)
            .ok_or_else(|| invalid_namespace(encoded))?;
        let (name, expected_flag, order) =
            allowed_namespace(name).ok_or_else(|| invalid_namespace(encoded))?;
        if parts.next().is_some()
            || flag != expected_flag
            || last_order.is_some_and(|previous| order <= previous)
            || !descriptors.insert(descriptor)
        {
            return Err(invalid_namespace(encoded));
        }
        last_order = Some(order);
        namespaces.push(RawHelperNamespace {
            name,
            clone_flag: flag,
            descriptor,
        });
    }
    let namespaces = namespaces
        .into_iter()
        .map(|namespace| HelperNamespace {
            name: namespace.name,
            clone_flag: namespace.clone_flag,
            // SAFETY: validation proved every inherited descriptor distinct,
            // and ownership is transferred exactly once after all checks pass.
            descriptor: unsafe { File::from_raw_fd(namespace.descriptor) },
        })
        .collect();
    // SAFETY: root is distinct from every namespace descriptor and ownership
    // is transferred only after the complete argument layout was validated.
    let root = unsafe { File::from_raw_fd(root) };
    Ok(HelperArguments {
        root,
        expected_parent,
        namespaces,
    })
}

fn run_helper(arguments: HelperArguments) -> Result<()> {
    verify_and_arm_parent(arguments.expected_parent)?;
    let request = read_request()?;
    enter_namespaces(&arguments.namespaces)?;
    let view = RootView::new(arguments.root.as_raw_fd())?;
    let response = match request {
        HelperRequest::File(request) => HelperResponse::File(
            request
                .validate()
                .and_then(|()| file_in_view(&view, &request)),
        ),
        HelperRequest::Filesystem(request) => HelperResponse::Filesystem(
            request
                .validate()
                .and_then(|()| filesystem_in_view(&view, &request)),
        ),
    };
    let encoded = serde_json::to_vec(&response).map_err(|error| {
        helper_error(
            ErrorCode::Internal,
            format!("failed to encode filesystem helper response: {error}"),
        )
    })?;
    if encoded.len() > MAX_HELPER_MESSAGE_BYTES {
        return Err(helper_error(
            ErrorCode::ResourceExhausted,
            "filesystem helper response exceeds its bounded size",
        ));
    }
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&encoded).map_err(|error| {
        helper_error(
            ErrorCode::Unavailable,
            format!("failed to write filesystem helper response: {error}"),
        )
    })?;
    stdout.flush().map_err(|error| {
        helper_error(
            ErrorCode::Unavailable,
            format!("failed to flush filesystem helper response: {error}"),
        )
    })
}

fn read_request() -> Result<HelperRequest> {
    let mut encoded = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_HELPER_MESSAGE_BYTES as u64 + 1)
        .read_to_end(&mut encoded)
        .map_err(|error| {
            helper_error(
                ErrorCode::Unavailable,
                format!("failed to read filesystem helper request: {error}"),
            )
        })?;
    if encoded.len() > MAX_HELPER_MESSAGE_BYTES {
        return Err(helper_error(
            ErrorCode::ResourceExhausted,
            "filesystem helper request exceeded its bounded size",
        ));
    }
    serde_json::from_slice(&encoded).map_err(|error| {
        helper_error(
            ErrorCode::InvalidArgument,
            format!("filesystem helper request is invalid: {error}"),
        )
    })
}

fn enter_namespaces(namespaces: &[HelperNamespace]) -> Result<()> {
    for namespace in namespaces {
        // SAFETY: the descriptor was inherited from the retained execution
        // context and the encoded clone flag was validated against its name.
        if unsafe { libc::setns(namespace.descriptor.as_raw_fd(), namespace.clone_flag) } != 0 {
            return Err(helper_error(
                ErrorCode::PermissionDenied,
                format!(
                    "failed to enter retained filesystem {} namespace: {}",
                    namespace.name,
                    std::io::Error::last_os_error()
                ),
            ));
        }
        if namespace.clone_flag == libc::CLONE_NEWUSER {
            become_user_namespace_root("retained filesystem")?;
        }
    }
    Ok(())
}

fn verify_and_arm_parent(expected_parent: libc::pid_t) -> Result<()> {
    // SAFETY: getppid has no preconditions.
    if unsafe { libc::getppid() } != expected_parent {
        return Err(helper_error(
            ErrorCode::PermissionDenied,
            "container filesystem helper parent does not match its launcher",
        ));
    }
    pid_supervisor::arm_parent_death_signal("filesystem helper")?;
    // SAFETY: rechecking closes the race between parent inspection and prctl.
    if unsafe { libc::getppid() } != expected_parent {
        return Err(helper_error(
            ErrorCode::Unavailable,
            "container filesystem launcher exited during helper bootstrap",
        ));
    }
    Ok(())
}

fn parse_descriptor(value: &OsStr, description: &str) -> Result<RawFd> {
    value
        .to_str()
        .and_then(|value| value.parse::<RawFd>().ok())
        .filter(|descriptor| *descriptor > libc::STDERR_FILENO)
        .ok_or_else(|| {
            helper_error(
                ErrorCode::InvalidArgument,
                format!("container filesystem helper received invalid {description}"),
            )
        })
}

fn parse_positive_pid(value: &OsStr, description: &str) -> Result<libc::pid_t> {
    value
        .to_str()
        .and_then(|value| value.parse::<libc::pid_t>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            helper_error(
                ErrorCode::InvalidArgument,
                format!("container filesystem helper received invalid {description}"),
            )
        })
}

fn allowed_namespace(name: &str) -> Option<(&'static str, libc::c_int, usize)> {
    match name {
        "user" => Some(("user", libc::CLONE_NEWUSER, 0)),
        "mnt" => Some(("mnt", libc::CLONE_NEWNS, 1)),
        _ => None,
    }
}

fn invalid_namespace(value: &str) -> Error {
    helper_error(
        ErrorCode::InvalidArgument,
        format!("invalid retained filesystem namespace argument `{value}`"),
    )
}

fn helper_error(code: ErrorCode, message: impl Into<String>) -> Error {
    filesystem_error(code, message)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use a3s_oci_sdk::ErrorCode;

    use super::parse_helper_arguments;

    fn parse(values: &[&str]) -> a3s_oci_sdk::Result<super::HelperArguments> {
        parse_helper_arguments(values.iter().map(OsString::from))
    }

    #[test]
    fn helper_requires_authenticated_root_and_parent_arguments() {
        let error = parse(&["3"]).expect_err("missing parent must fail closed");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn helper_rejects_unknown_unordered_or_duplicate_namespace_descriptors() {
        for arguments in [
            vec!["3", "42", "mnt:131072:4", "user:268435456:5"],
            vec!["3", "42", "user:268435456:4", "user:268435456:5"],
            vec!["3", "42", "unknown:1:4"],
            vec!["3", "42", "user:268435456:3"],
        ] {
            let error = parse(&arguments).expect_err("invalid namespaces must fail closed");
            assert_eq!(error.code, ErrorCode::InvalidArgument);
        }
    }
}
