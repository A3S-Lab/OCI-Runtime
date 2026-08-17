use a3s_oci_sdk::{OciLinuxCgroupPath, OciLinuxCgroupPathErrorKind};

#[test]
fn preserves_absolute_and_relative_oci_cgroup_path_semantics() {
    let absolute = OciLinuxCgroupPath::parse("/tenant/workload").expect("absolute cgroup path");
    let relative = OciLinuxCgroupPath::parse("tenant/workload").expect("relative cgroup path");

    assert!(absolute.is_absolute());
    assert_eq!(absolute.relative(), "tenant/workload");
    assert!(!relative.is_absolute());
    assert_eq!(relative.relative(), "tenant/workload");
    assert_ne!(absolute, relative);
}

#[test]
fn rejects_ambiguous_or_dangerous_cgroup_paths_before_execution() {
    for (path, expected) in [
        ("", OciLinuxCgroupPathErrorKind::Empty),
        ("/", OciLinuxCgroupPathErrorKind::UnsafePath),
        ("tenant/", OciLinuxCgroupPathErrorKind::UnsafePath),
        ("tenant//workload", OciLinuxCgroupPathErrorKind::UnsafePath),
        ("tenant/./workload", OciLinuxCgroupPathErrorKind::UnsafePath),
        (
            "tenant/../workload",
            OciLinuxCgroupPathErrorKind::UnsafePath,
        ),
        (
            "system.slice:a3s:workload",
            OciLinuxCgroupPathErrorKind::UnsafePath,
        ),
        ("tenant\nworkload", OciLinuxCgroupPathErrorKind::UnsafePath),
        ("tenant\0workload", OciLinuxCgroupPathErrorKind::Nul),
    ] {
        assert_eq!(
            OciLinuxCgroupPath::parse(path)
                .expect_err("unsafe cgroup path")
                .kind(),
            expected,
            "unexpected error for {path:?}"
        );
    }
}

#[test]
fn bounds_the_complete_path_and_each_cgroup_name() {
    let long_component = "a".repeat(256);
    assert_eq!(
        OciLinuxCgroupPath::parse(&long_component)
            .expect_err("overlong cgroup name")
            .kind(),
        OciLinuxCgroupPathErrorKind::ComponentTooLong
    );

    let long_path = std::iter::repeat_n("a", 2_049)
        .collect::<Vec<_>>()
        .join("/");
    assert_eq!(long_path.len(), 4_097);
    assert_eq!(
        OciLinuxCgroupPath::parse(&long_path)
            .expect_err("overlong cgroup path")
            .kind(),
        OciLinuxCgroupPathErrorKind::TooLong
    );
}
