use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;

use a3s_oci_sdk::oci_spec::runtime::LinuxHugepageLimit;
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::{cgroup_error, CgroupSetting};

const PAGE_SIZE_MAX_LENGTH: usize = 32;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct HugeTlbPlan {
    limits: BTreeMap<String, HugeTlbLimit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HugeTlbLimit {
    page_size_bytes: u64,
    limit: u64,
}

impl HugeTlbPlan {
    pub(super) fn from_oci(limits: Option<&[LinuxHugepageLimit]>) -> Result<Self> {
        let Some(limits) = limits else {
            return Ok(Self::default());
        };
        let mut planned = BTreeMap::new();
        for (index, limit) in limits.iter().enumerate() {
            let field = format!("linux.resources.hugepageLimits[{index}]");
            let (page_size, page_size_bytes) = validate_page_size(&field, limit.page_size())?;
            let value = HugeTlbLimit {
                page_size_bytes,
                limit: limit.limit(),
            };
            if planned.insert(page_size.to_string(), value).is_some() {
                return Err(invalid(format!(
                    "linux.resources.hugepageLimits contains duplicate pageSize {page_size:?}"
                )));
            }
        }
        Ok(Self { limits: planned })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }

    pub(super) fn owned_files(&self) -> BTreeSet<String> {
        self.limits
            .keys()
            .flat_map(|page_size| [max_file(page_size), reservation_file(page_size)])
            .collect()
    }

    pub(super) fn settings(&self, path: &Path) -> Result<Vec<CgroupSetting>> {
        let mut settings = Vec::with_capacity(self.limits.len() * 2);
        for (page_size, limit) in &self.limits {
            let max = max_file(page_size);
            require_control_file(path, &max, page_size)?;
            let value = cgroup_v2_limit_value(*limit);
            settings.push(CgroupSetting::new(max, value.clone()));

            let reservation = reservation_file(page_size);
            if optional_control_file(path, &reservation)? {
                settings.push(CgroupSetting::new(reservation, value));
            }
        }
        Ok(settings)
    }

    pub(super) async fn settings_async(&self, path: &Path) -> Result<Vec<CgroupSetting>> {
        let mut settings = Vec::with_capacity(self.limits.len() * 2);
        for (page_size, limit) in &self.limits {
            let max = max_file(page_size);
            require_control_file_async(path, &max, page_size).await?;
            let value = cgroup_v2_limit_value(*limit);
            settings.push(CgroupSetting::new(max, value.clone()));

            let reservation = reservation_file(page_size);
            if optional_control_file_async(path, &reservation).await? {
                settings.push(CgroupSetting::new(reservation, value));
            }
        }
        Ok(settings)
    }
}

fn validate_page_size<'a>(field: &str, value: &'a str) -> Result<(&'a str, u64)> {
    let suffix_and_multiplier = [
        ("KB", 1_u64 << 10),
        ("MB", 1_u64 << 20),
        ("GB", 1_u64 << 30),
    ]
    .into_iter()
    .find(|(suffix, _)| value.ends_with(suffix));
    let Some((suffix, multiplier)) = suffix_and_multiplier else {
        return Err(invalid(format!(
            "{field}.pageSize must use the canonical <size><KB|MB|GB> form"
        )));
    };
    let digits = &value[..value.len() - suffix.len()];
    if value.len() > PAGE_SIZE_MAX_LENGTH
        || digits.is_empty()
        || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid(format!(
            "{field}.pageSize must use the canonical <size><KB|MB|GB> form"
        )));
    }
    let size = digits.parse::<u64>().map_err(|_| {
        invalid(format!(
            "{field}.pageSize does not fit the OCI hugepage-size range"
        ))
    })?;
    let bytes = size.checked_mul(multiplier).ok_or_else(|| {
        invalid(format!(
            "{field}.pageSize does not fit the OCI hugepage-size range"
        ))
    })?;
    Ok((value, bytes))
}

fn cgroup_v2_limit_value(limit: HugeTlbLimit) -> String {
    let aligned = limit.limit - (limit.limit % limit.page_size_bytes);
    #[cfg(target_pointer_width = "64")]
    {
        // Linux stores hugetlb limits in PAGE_COUNTER_MAX base pages, then
        // rounds that count down to the selected hugepage size. On 64-bit
        // kernels this is the largest hugepage multiple below LONG_MAX.
        let maximum = (i64::MAX as u64 / limit.page_size_bytes) * limit.page_size_bytes;
        if maximum != 0 && aligned >= maximum {
            return "max".to_string();
        }
    }
    aligned.to_string()
}

fn max_file(page_size: &str) -> String {
    format!("hugetlb.{page_size}.max")
}

fn reservation_file(page_size: &str) -> String {
    format!("hugetlb.{page_size}.rsvd.max")
}

fn require_control_file(path: &Path, file: &str, page_size: &str) -> Result<()> {
    match control_file_state(path, file) {
        Ok(true) => Ok(()),
        Ok(false) => Err(unsupported_page_size(path, page_size)),
        Err(error) => Err(inspect_error(path, file, error)),
    }
}

fn optional_control_file(path: &Path, file: &str) -> Result<bool> {
    control_file_state(path, file).map_err(|error| inspect_error(path, file, error))
}

fn control_file_state(path: &Path, file: &str) -> io::Result<bool> {
    match std::fs::symlink_metadata(path.join(file)) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "controller path is not a regular cgroup file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

async fn require_control_file_async(path: &Path, file: &str, page_size: &str) -> Result<()> {
    match control_file_state_async(path, file).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(unsupported_page_size(path, page_size)),
        Err(error) => Err(inspect_error(path, file, error)),
    }
}

async fn optional_control_file_async(path: &Path, file: &str) -> Result<bool> {
    control_file_state_async(path, file)
        .await
        .map_err(|error| inspect_error(path, file, error))
}

async fn control_file_state_async(path: &Path, file: &str) -> io::Result<bool> {
    match tokio::fs::symlink_metadata(path.join(file)).await {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "controller path is not a regular cgroup file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn unsupported_page_size(path: &Path, page_size: &str) -> Error {
    cgroup_error(
        ErrorCode::Unsupported,
        format!(
            "cgroup v2 HugeTLB page size {page_size:?} is unavailable at {}",
            path.display()
        ),
    )
}

fn inspect_error(path: &Path, file: &str, error: io::Error) -> Error {
    cgroup_error(
        ErrorCode::FailedPrecondition,
        format!(
            "failed to inspect HugeTLB cgroup control {}: {error}",
            path.join(file).display()
        ),
    )
}

fn invalid(message: impl Into<String>) -> Error {
    cgroup_error(ErrorCode::InvalidArgument, message)
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
    use a3s_oci_sdk::ErrorCode;

    use super::HugeTlbPlan;
    use crate::executor::cgroup::{apply_settings, CgroupSetting};

    fn plan(value: serde_json::Value) -> Result<HugeTlbPlan, a3s_oci_sdk::Error> {
        let resources: LinuxResources = serde_json::from_value(serde_json::json!({
            "hugepageLimits": value
        }))
        .expect("decode HugeTLB resources");
        HugeTlbPlan::from_oci(resources.hugepage_limits().as_deref())
    }

    #[test]
    fn plans_exact_fault_and_reservation_limits_for_available_page_sizes() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        for file in [
            "hugetlb.64KB.max",
            "hugetlb.2MB.max",
            "hugetlb.2MB.rsvd.max",
            "hugetlb.1GB.max",
        ] {
            std::fs::write(directory.path().join(file), "max\n").expect("HugeTLB control");
        }
        let plan = plan(serde_json::json!([
            {"pageSize": "2MB", "limit": 209715200},
            {"pageSize": "1GB", "limit": 1073741824},
            {"pageSize": "64KB", "limit": 18446744073709551615_u64}
        ]))
        .expect("HugeTLB plan");

        assert_eq!(
            plan.settings(directory.path()).expect("HugeTLB settings"),
            [
                CgroupSetting::new("hugetlb.1GB.max", "1073741824"),
                CgroupSetting::new("hugetlb.2MB.max", "209715200"),
                CgroupSetting::new("hugetlb.2MB.rsvd.max", "209715200"),
                CgroupSetting::new("hugetlb.64KB.max", "max"),
            ]
        );
    }

    #[test]
    fn normalizes_limits_to_the_kernel_hugepage_counter_representation() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        std::fs::write(directory.path().join("hugetlb.64KB.max"), "max\n")
            .expect("HugeTLB control");
        let plan = plan(serde_json::json!([
            {"pageSize": "64KB", "limit": 1000000}
        ]))
        .expect("OCI example HugeTLB plan");

        assert_eq!(
            plan.settings(directory.path()).expect("HugeTLB settings"),
            [CgroupSetting::new("hugetlb.64KB.max", "983040")]
        );
    }

    #[test]
    fn applies_hugetlb_limits_with_exact_read_back() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        for file in ["hugetlb.2MB.max", "hugetlb.2MB.rsvd.max"] {
            std::fs::write(directory.path().join(file), "max\n").expect("HugeTLB control");
        }
        let plan = plan(serde_json::json!([
            {"pageSize": "2MB", "limit": 67108864}
        ]))
        .expect("HugeTLB plan");
        let settings = plan.settings(directory.path()).expect("HugeTLB settings");

        apply_settings(directory.path(), &settings).expect("apply HugeTLB settings");
        assert_eq!(
            std::fs::read_to_string(directory.path().join("hugetlb.2MB.max")).expect("usage limit"),
            "67108864"
        );
        assert_eq!(
            std::fs::read_to_string(directory.path().join("hugetlb.2MB.rsvd.max"))
                .expect("reservation limit"),
            "67108864"
        );
    }

    #[test]
    fn rejects_duplicate_unsafe_and_unrepresentable_hugetlb_values() {
        for value in [
            serde_json::json!([
                {"pageSize": "2MB", "limit": 1},
                {"pageSize": "2MB", "limit": 2}
            ]),
            serde_json::json!([{"pageSize": "../2MB", "limit": 1}]),
            serde_json::json!([{"pageSize": "02MB", "limit": 1}]),
            serde_json::json!([{"pageSize": "2MiB", "limit": 1}]),
            serde_json::json!([{"pageSize": "18446744073709551615GB", "limit": 1}]),
        ] {
            let error = plan(value).expect_err("invalid HugeTLB input must fail planning");
            assert_eq!(error.code, ErrorCode::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn rejects_unknown_or_non_file_page_sizes_before_returning_settings() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        std::fs::write(directory.path().join("hugetlb.2MB.max"), "max\n")
            .expect("supported HugeTLB control");
        std::fs::create_dir(directory.path().join("hugetlb.1GB.max"))
            .expect("invalid HugeTLB control type");

        let unknown = plan(serde_json::json!([
            {"pageSize": "64KB", "limit": 65536}
        ]))
        .expect("syntactically valid HugeTLB plan");
        let error = unknown
            .settings_async(directory.path())
            .await
            .expect_err("unknown page size must fail");
        assert_eq!(error.code, ErrorCode::Unsupported);

        let non_file = plan(serde_json::json!([
            {"pageSize": "1GB", "limit": 1073741824}
        ]))
        .expect("syntactically valid HugeTLB plan");
        let error = non_file
            .settings_async(directory.path())
            .await
            .expect_err("non-file control must fail");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
    }
}
