use serde_json::{Map, Value};

use super::{contains_nul, is_runtime_absolute, rules, ViolationCollector};

pub(super) fn inspect(value: &Value, collector: &mut ViolationCollector) {
    let Some(vm) = value.get("vm").and_then(Value::as_object) else {
        return;
    };

    if let Some(hypervisor) = vm.get("hypervisor").and_then(Value::as_object) {
        validate_runtime_path(hypervisor, "path", "/vm/hypervisor/path", collector);
        validate_parameters(
            hypervisor,
            "parameters",
            "/vm/hypervisor/parameters",
            collector,
        );
    }
    if let Some(kernel) = vm.get("kernel").and_then(Value::as_object) {
        validate_runtime_path(kernel, "path", "/vm/kernel/path", collector);
        validate_runtime_path(kernel, "initrd", "/vm/kernel/initrd", collector);
        validate_parameters(kernel, "parameters", "/vm/kernel/parameters", collector);
    }
    if let Some(image) = vm.get("image").and_then(Value::as_object) {
        validate_runtime_path(image, "path", "/vm/image/path", collector);
    }
}

fn validate_runtime_path(
    object: &Map<String, Value>,
    field: &str,
    instance_path: &str,
    collector: &mut ViolationCollector,
) {
    let Some(path) = object.get(field).and_then(Value::as_str) else {
        return;
    };
    if !is_runtime_absolute(path) {
        collector.invalid(
            instance_path,
            rules::VM_PATH_ABSOLUTE,
            "VM runtime paths must be absolute",
        );
    }
    if contains_nul(path) {
        collector.invalid(
            instance_path,
            rules::PATH_NO_NUL,
            "VM runtime paths must not contain a NUL byte",
        );
    }
}

fn validate_parameters(
    object: &Map<String, Value>,
    field: &str,
    base_path: &str,
    collector: &mut ViolationCollector,
) {
    let Some(parameters) = object.get(field).and_then(Value::as_array) else {
        return;
    };
    for (index, parameter) in parameters.iter().filter_map(Value::as_str).enumerate() {
        if contains_nul(parameter) {
            collector.invalid(
                format!("{base_path}/{index}"),
                rules::VM_PARAMETER_NO_NUL,
                "VM parameters must not contain a NUL byte",
            );
        }
    }
}
