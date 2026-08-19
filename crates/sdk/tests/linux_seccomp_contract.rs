use a3s_oci_sdk::{OciSchemaDocument, OciSchemaValidator};
use serde_json::{json, Value};

fn configuration(seccomp: Value) -> Value {
    json!({
        "ociVersion": "1.3.0",
        "linux": {"seccomp": seccomp}
    })
}

#[test]
fn schema_requires_complete_seccomp_members() {
    let validator = OciSchemaValidator::new().expect("compile pinned OCI schemas");
    validator
        .validate(
            OciSchemaDocument::Configuration,
            &configuration(json!({
                "defaultAction": "SCMP_ACT_ERRNO",
                "defaultErrnoRet": 1,
                "architectures": ["SCMP_ARCH_X86_64"],
                "flags": ["SECCOMP_FILTER_FLAG_LOG"],
                "listenerPath": "/run/seccomp-agent.sock",
                "listenerMetadata": "opaque",
                "syscalls": [{
                    "names": ["clone"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [{
                        "index": 0,
                        "value": 1,
                        "valueTwo": 2,
                        "op": "SCMP_CMP_MASKED_EQ"
                    }]
                }]
            })),
        )
        .expect("complete seccomp configuration must satisfy the pinned schema");

    for invalid_seccomp in [
        json!({}),
        json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "syscalls": [{"action": "SCMP_ACT_ALLOW"}]
        }),
        json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "syscalls": [{"names": ["read"]}]
        }),
        json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "syscalls": [{"names": [], "action": "SCMP_ACT_ALLOW"}]
        }),
        json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "syscalls": [{
                "names": ["clone"],
                "action": "SCMP_ACT_ALLOW",
                "args": [{"value": 1, "op": "SCMP_CMP_EQ"}]
            }]
        }),
        json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "syscalls": [{
                "names": ["clone"],
                "action": "SCMP_ACT_ALLOW",
                "args": [{"index": 0, "op": "SCMP_CMP_EQ"}]
            }]
        }),
        json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "syscalls": [{
                "names": ["clone"],
                "action": "SCMP_ACT_ALLOW",
                "args": [{"index": 0, "value": 1}]
            }]
        }),
    ] {
        validator
            .validate(
                OciSchemaDocument::Configuration,
                &configuration(invalid_seccomp),
            )
            .expect_err("missing required seccomp members must fail schema validation");
    }
}

#[test]
fn schema_preserves_optional_seccomp_members() {
    let validator = OciSchemaValidator::new().expect("compile pinned OCI schemas");
    for seccomp in [
        json!({"defaultAction": "SCMP_ACT_ALLOW"}),
        json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": [],
            "flags": [],
            "syscalls": []
        }),
        json!({
            "defaultAction": "SCMP_ACT_NOTIFY",
            "listenerPath": "/run/seccomp-agent.sock",
            "listenerMetadata": "opaque"
        }),
        json!({
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": u16::MAX,
            "syscalls": [{
                "names": ["clone"],
                "action": "SCMP_ACT_TRACE",
                "errnoRet": 7,
                "args": [{
                    "index": 0,
                    "value": u64::MAX,
                    "valueTwo": u64::MAX,
                    "op": "SCMP_CMP_MASKED_EQ"
                }]
            }]
        }),
    ] {
        validator
            .validate(OciSchemaDocument::Configuration, &configuration(seccomp))
            .expect("optional seccomp members must retain their schema-defined forms");
    }
}

#[test]
fn schema_rejects_unknown_seccomp_registry_values() {
    let validator = OciSchemaValidator::new().expect("compile pinned OCI schemas");
    for invalid_seccomp in [
        json!({"defaultAction": "SCMP_ACT_UNKNOWN"}),
        json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": ["SCMP_ARCH_UNKNOWN"]
        }),
        json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "flags": ["SECCOMP_FILTER_FLAG_UNKNOWN"]
        }),
        json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "syscalls": [{
                "names": ["clone"],
                "action": "SCMP_ACT_ALLOW",
                "args": [{"index": 0, "value": 1, "op": "SCMP_CMP_UNKNOWN"}]
            }]
        }),
    ] {
        validator
            .validate(
                OciSchemaDocument::Configuration,
                &configuration(invalid_seccomp),
            )
            .expect_err("unknown seccomp enum values must fail schema validation");
    }
}
