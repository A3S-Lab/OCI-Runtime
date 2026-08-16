use a3s_oci_sdk::oci_spec::runtime::LinuxCapabilities;

use super::{
    ensure_exact_sets, probe_kernel_capabilities, CapabilityPlan, CapabilitySet,
    KernelCapabilityState,
};

#[test]
fn probes_the_kernel_capability_ceiling_without_procfs() {
    let kernel = probe_kernel_capabilities().expect("probe capability state");
    assert!(kernel.last_capability < 64);
    assert_eq!(kernel.bounding & !kernel.supported_mask(), 0);
}

#[test]
fn bounding_set_mismatch_fails_closed() {
    let expected = CapabilityPlan {
        bounding: 1,
        ..CapabilityPlan::default()
    };
    let error = ensure_exact_sets(expected, CapabilityPlan::default())
        .expect_err("bounding mismatch must fail closed");

    assert!(error.message.contains("differ after enforcement"));
    assert!(error.message.contains("bounding: 1"));
}

#[test]
fn plans_the_exact_a3s_box_capability_profile() {
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../fixtures/a3s-box/config.json"))
            .expect("decode fixture");
    let capabilities: LinuxCapabilities =
        serde_json::from_value(config["process"]["capabilities"].clone())
            .expect("decode capabilities");
    let plan = CapabilityPlan::from_oci(Some(&capabilities)).expect("capability plan");
    assert_eq!(plan.bounding_count(), 11);
    assert_eq!(plan.ambient, 0);
    assert_eq!(plan.inheritable, 0);
    assert_eq!(plan.effective, plan.permitted);
    assert_eq!(plan.permitted, plan.bounding);
}

#[test]
fn rejects_incoherent_capability_sets() {
    let capabilities: LinuxCapabilities = serde_json::from_value(serde_json::json!({
        "bounding": ["CAP_CHOWN"],
        "permitted": [],
        "effective": ["CAP_CHOWN"],
        "inheritable": [],
        "ambient": []
    }))
    .expect("decode capabilities");
    assert!(CapabilityPlan::from_oci(Some(&capabilities)).is_err());
}

#[test]
fn absent_capabilities_are_an_explicit_empty_profile() {
    assert_eq!(
        CapabilityPlan::from_oci(None).expect("empty profile"),
        CapabilityPlan::default()
    );
}

#[test]
fn exec_capabilities_cannot_exceed_the_configured_bounding_set() {
    let container: LinuxCapabilities = serde_json::from_value(serde_json::json!({
        "bounding": ["CAP_CHOWN"],
        "permitted": ["CAP_CHOWN"],
        "effective": ["CAP_CHOWN"],
        "inheritable": [],
        "ambient": []
    }))
    .expect("decode container capabilities");
    let expanded: LinuxCapabilities = serde_json::from_value(serde_json::json!({
        "bounding": ["CAP_CHOWN", "CAP_SYS_ADMIN"],
        "permitted": ["CAP_CHOWN", "CAP_SYS_ADMIN"],
        "effective": ["CAP_CHOWN", "CAP_SYS_ADMIN"],
        "inheritable": [],
        "ambient": []
    }))
    .expect("decode expanded capabilities");
    let reduced: LinuxCapabilities = serde_json::from_value(serde_json::json!({
        "bounding": [],
        "permitted": [],
        "effective": [],
        "inheritable": [],
        "ambient": []
    }))
    .expect("decode reduced capabilities");
    let container = CapabilityPlan::from_oci(Some(&container)).expect("container plan");
    let expanded = CapabilityPlan::from_oci(Some(&expanded)).expect("expanded plan");
    let reduced = CapabilityPlan::from_oci(Some(&reduced)).expect("reduced plan");

    assert!(expanded.validate_exec_ceiling(container).is_err());
    reduced
        .validate_exec_ceiling(container)
        .expect("reduced exec capabilities");
}

#[test]
fn fully_grantable_capabilities_remain_exact_without_warnings() {
    let requested = CapabilityPlan {
        bounding: 1,
        effective: 1,
        inheritable: 1,
        permitted: 1,
        ambient: 1,
    };
    let resolved = requested.resolve_for_kernel(KernelCapabilityState {
        last_capability: 40,
        bounding: 1,
        effective: 1,
        permitted: 1,
        inheritable: 1,
    });

    assert_eq!(resolved.applied, requested);
    assert!(resolved.warnings.is_empty());
}

#[test]
fn kernel_unsupported_capabilities_become_structured_warnings() {
    let capabilities: LinuxCapabilities = serde_json::from_value(serde_json::json!({
        "bounding": ["CAP_CHOWN", "CAP_BPF"],
        "permitted": ["CAP_CHOWN", "CAP_BPF"],
        "effective": ["CAP_CHOWN", "CAP_BPF"],
        "inheritable": ["CAP_CHOWN", "CAP_BPF"],
        "ambient": ["CAP_CHOWN", "CAP_BPF"]
    }))
    .expect("decode capabilities");
    let requested = CapabilityPlan::from_oci(Some(&capabilities)).expect("capability plan");
    let chown = 1_u64;
    let resolved = requested.resolve_for_kernel(KernelCapabilityState {
        last_capability: 37,
        bounding: chown,
        effective: chown,
        permitted: chown,
        inheritable: chown,
    });

    assert_eq!(
        resolved.applied,
        CapabilityPlan {
            bounding: chown,
            effective: chown,
            inheritable: chown,
            permitted: chown,
            ambient: chown,
        }
    );
    assert_eq!(resolved.warnings.len(), 1);
    assert_eq!(resolved.warnings[0].capability(), "CAP_BPF");
    assert_eq!(
        resolved.warnings[0].unavailable_sets(),
        &[
            CapabilitySet::Bounding,
            CapabilitySet::Effective,
            CapabilitySet::Inheritable,
            CapabilitySet::Permitted,
            CapabilitySet::Ambient,
        ]
    );
}

#[test]
fn restricted_runtime_authority_drops_only_ungrantable_sets() {
    let capabilities: LinuxCapabilities = serde_json::from_value(serde_json::json!({
        "bounding": ["CAP_CHOWN", "CAP_SYS_ADMIN"],
        "permitted": ["CAP_CHOWN", "CAP_SYS_ADMIN"],
        "effective": ["CAP_CHOWN", "CAP_SYS_ADMIN"],
        "inheritable": [],
        "ambient": []
    }))
    .expect("decode capabilities");
    let requested = CapabilityPlan::from_oci(Some(&capabilities)).expect("capability plan");
    let chown = 1_u64;
    let sys_admin = 1_u64 << 21;
    let resolved = requested.resolve_for_kernel(KernelCapabilityState {
        last_capability: 40,
        bounding: chown | sys_admin,
        effective: chown,
        permitted: chown,
        inheritable: 0,
    });

    assert_eq!(resolved.applied.bounding, chown | sys_admin);
    assert_eq!(resolved.applied.effective, chown);
    assert_eq!(resolved.applied.permitted, chown);
    assert_eq!(resolved.warnings.len(), 1);
    assert_eq!(resolved.warnings[0].capability(), "CAP_SYS_ADMIN");
    assert_eq!(
        resolved.warnings[0].unavailable_sets(),
        &[CapabilitySet::Effective, CapabilitySet::Permitted]
    );
}
