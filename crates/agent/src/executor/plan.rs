use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::LinuxNamespaceType;
use a3s_oci_sdk::{Error, ErrorCode, IoMode, OciBundle, ProcessIo, Result};
use serde_json::{Map, Value};

const MAX_ARGUMENTS: usize = 4_096;
const MAX_ENVIRONMENT_ENTRIES: usize = 4_096;
const MAX_EXEC_BYTES: usize = 1024 * 1024;
const LINUX_HOST_NAME_MAX: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InitPlan {
    pub(super) bundle_directory: PathBuf,
    pub(super) rootfs: PathBuf,
    pub(super) args: Vec<String>,
    pub(super) environment: Vec<String>,
    pub(super) cwd: String,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) additional_gids: Vec<u32>,
    pub(super) umask: Option<u32>,
    pub(super) no_new_privileges: bool,
    pub(super) new_uts_namespace: bool,
    pub(super) hostname: Option<String>,
}

impl InitPlan {
    pub(super) fn from_bundle(bundle: &OciBundle, io: &ProcessIo) -> Result<Self> {
        validate_null_io(io)?;
        let raw: Value = serde_json::from_str(bundle.config_json()).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("validated OCI configuration could not be decoded: {error}"),
            )
            .for_operation("plan-guest-init")
        })?;
        validate_profile(&raw)?;

        let spec = bundle.spec();
        let root = spec.root().as_ref().ok_or_else(|| {
            invalid("OCI bootstrap executor requires a root filesystem configuration")
        })?;
        let root_path = linux_path(root.path(), "root.path", false)?;
        if root_path != "rootfs" {
            return Err(unsupported(
                "root.path",
                "the bootstrap executor currently requires the normalized relative path `rootfs`",
            ));
        }
        if root.readonly().unwrap_or(false) {
            return Err(unsupported(
                "root.readonly",
                "read-only root filesystems are not enforced yet",
            ));
        }

        let process = spec
            .process()
            .as_ref()
            .ok_or_else(|| invalid("OCI bootstrap executor requires process for create/start"))?;
        if process.terminal().unwrap_or(false) {
            return Err(unsupported(
                "process.terminal",
                "terminal allocation is not implemented",
            ));
        }
        if process.no_new_privileges() != Some(true) {
            return Err(unsupported(
                "process.noNewPrivileges",
                "the bootstrap executor requires noNewPrivileges=true",
            ));
        }

        let args = process
            .args()
            .as_ref()
            .filter(|args| !args.is_empty())
            .ok_or_else(|| invalid("process.args must contain an executable"))?
            .clone();
        validate_string_vector("process.args", &args, MAX_ARGUMENTS)?;
        linux_path(Path::new(&args[0]), "process.args[0]", true)?;

        let environment = process.env().as_ref().cloned().unwrap_or_default();
        validate_environment(&environment)?;
        let cwd = linux_path(process.cwd(), "process.cwd", true)?;

        let user = process.user();
        if user.username().is_some() {
            return Err(unsupported(
                "process.user.username",
                "username lookup is not implemented",
            ));
        }
        let additional_gids = user.additional_gids().as_ref().cloned().unwrap_or_default();
        if user.umask().is_some_and(|umask| umask > 0o777) {
            return Err(invalid(
                "process.user.umask must fit the POSIX permission mask",
            ));
        }
        let new_uts_namespace = validate_linux_namespaces(spec.linux().as_ref())?;
        let hostname = spec
            .hostname()
            .as_deref()
            .map(validate_hostname)
            .transpose()?;
        if hostname.is_some() && !new_uts_namespace {
            return Err(unsupported(
                "hostname",
                "the bootstrap executor changes it only in a newly created UTS namespace",
            ));
        }

        Ok(Self {
            bundle_directory: bundle.directory().to_path_buf(),
            rootfs: bundle.directory().join(root_path),
            args,
            environment,
            cwd,
            uid: user.uid(),
            gid: user.gid(),
            additional_gids,
            umask: user.umask(),
            no_new_privileges: true,
            new_uts_namespace,
            hostname,
        })
    }
}

fn validate_profile(raw: &Value) -> Result<()> {
    let root = object(raw, "config")?;
    reject_unimplemented_keys(
        root,
        "config",
        &["ociVersion", "root", "process", "hostname", "linux"],
    )?;

    let root_config = object(
        root.get("root")
            .ok_or_else(|| invalid("config.root is required"))?,
        "root",
    )?;
    reject_unimplemented_keys(root_config, "root", &["path", "readonly"])?;

    let process = object(
        root.get("process")
            .ok_or_else(|| invalid("config.process is required"))?,
        "process",
    )?;
    reject_unimplemented_keys(
        process,
        "process",
        &["terminal", "user", "args", "env", "cwd", "noNewPrivileges"],
    )?;

    let user = object(
        process
            .get("user")
            .ok_or_else(|| invalid("process.user is required"))?,
        "process.user",
    )?;
    reject_unimplemented_keys(
        user,
        "process.user",
        &["uid", "gid", "umask", "additionalGids", "username"],
    )?;

    let Some(linux) = root.get("linux") else {
        return Ok(());
    };
    let linux = object(linux, "linux")?;
    reject_unimplemented_keys(linux, "linux", &["namespaces"])?;
    let namespaces = linux
        .get("namespaces")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("linux.namespaces must be an array"))?;
    if namespaces.len() != 1 {
        return Err(unsupported(
            "linux.namespaces",
            "the bootstrap executor currently accepts exactly one UTS namespace",
        ));
    }
    let namespace = object(&namespaces[0], "linux.namespaces[0]")?;
    reject_unimplemented_keys(namespace, "linux.namespaces[0]", &["type", "path"])?;
    if namespace.get("type").and_then(Value::as_str) != Some("uts") {
        return Err(unsupported(
            "linux.namespaces[0].type",
            "only a new UTS namespace is implemented",
        ));
    }
    if namespace.contains_key("path") {
        return Err(unsupported(
            "linux.namespaces[0].path",
            "joining an existing UTS namespace is not implemented",
        ));
    }
    Ok(())
}

fn validate_linux_namespaces(
    linux: Option<&a3s_oci_sdk::oci_spec::runtime::Linux>,
) -> Result<bool> {
    let Some(linux) = linux else {
        return Ok(false);
    };
    let namespaces = linux.namespaces().as_deref().ok_or_else(|| {
        invalid("linux.namespaces is required when linux is present in the bootstrap profile")
    })?;
    let [namespace] = namespaces else {
        return Err(unsupported(
            "linux.namespaces",
            "the bootstrap executor currently accepts exactly one UTS namespace",
        ));
    };
    if namespace.typ() != LinuxNamespaceType::Uts {
        return Err(unsupported(
            "linux.namespaces[0].type",
            "only a new UTS namespace is implemented",
        ));
    }
    if namespace.path().is_some() {
        return Err(unsupported(
            "linux.namespaces[0].path",
            "joining an existing UTS namespace is not implemented",
        ));
    }
    Ok(true)
}

fn validate_hostname(hostname: &str) -> Result<String> {
    if hostname.len() > LINUX_HOST_NAME_MAX || hostname.as_bytes().contains(&0) {
        return Err(invalid(format!(
            "hostname must contain at most {LINUX_HOST_NAME_MAX} bytes and no NUL"
        )));
    }
    Ok(hostname.to_string())
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid(format!("{field} must be an object")))
}

fn reject_unimplemented_keys(
    object: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<()> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        Err(unsupported(
            &format!("{field}.{key}"),
            "this OCI property is not enforced by the bootstrap executor",
        ))
    } else {
        Ok(())
    }
}

fn validate_null_io(io: &ProcessIo) -> Result<()> {
    if !matches!(io.stdin, IoMode::Null)
        || !matches!(io.stdout, IoMode::Null)
        || !matches!(io.stderr, IoMode::Null)
        || io.terminal_size.is_some()
    {
        Err(unsupported(
            "process I/O",
            "the bootstrap executor currently accepts only null stdin/stdout/stderr",
        ))
    } else {
        Ok(())
    }
}

fn validate_environment(environment: &[String]) -> Result<()> {
    validate_string_vector("process.env", environment, MAX_ENVIRONMENT_ENTRIES)?;
    let mut names = BTreeSet::new();
    for entry in environment {
        let Some((name, _value)) = entry.split_once('=') else {
            return Err(invalid(
                "each process.env entry must contain a name and `=` separator",
            ));
        };
        if name.is_empty() || name.contains('=') {
            return Err(invalid("process.env contains an invalid variable name"));
        }
        if !names.insert(name) {
            return Err(invalid(format!(
                "process.env contains duplicate variable `{name}`"
            )));
        }
    }
    Ok(())
}

fn validate_string_vector(field: &str, values: &[String], maximum: usize) -> Result<()> {
    if values.len() > maximum {
        return Err(invalid(format!(
            "{field} contains {} entries; maximum is {maximum}",
            values.len()
        )));
    }
    let mut bytes = 0_usize;
    for value in values {
        if value.as_bytes().contains(&0) {
            return Err(invalid(format!("{field} contains a NUL byte")));
        }
        bytes = bytes
            .checked_add(value.len().saturating_add(1))
            .ok_or_else(|| invalid(format!("{field} size overflow")))?;
        if bytes > MAX_EXEC_BYTES {
            return Err(invalid(format!(
                "{field} exceeds the {MAX_EXEC_BYTES}-byte bootstrap limit"
            )));
        }
    }
    Ok(())
}

fn linux_path(path: &Path, field: &str, require_absolute: bool) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid(format!("{field} is not valid UTF-8")))?;
    if value.is_empty()
        || value.as_bytes().contains(&0)
        || value.contains('\\')
        || (require_absolute && !value.starts_with('/'))
        || (!require_absolute && value.starts_with('/'))
    {
        return Err(invalid(format!(
            "{field} must be a normalized {} Linux path",
            if require_absolute {
                "absolute"
            } else {
                "relative"
            }
        )));
    }
    let components = if require_absolute {
        value.strip_prefix('/').unwrap_or(value)
    } else {
        value
    };
    if value != "/"
        && (value.ends_with('/')
            || components
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | "..")))
    {
        return Err(invalid(format!(
            "{field} must not contain empty or dot components"
        )));
    }
    Ok(value.to_string())
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("plan-guest-init")
}

fn unsupported(field: &str, reason: &str) -> Error {
    Error::new(ErrorCode::Unsupported, format!("{field}: {reason}"))
        .for_operation("plan-guest-init")
}
