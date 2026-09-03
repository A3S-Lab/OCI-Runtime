#!/usr/bin/env bash
set -Eeuo pipefail

# Run the nine transport-boundary owner-replacement cases shared by the Linux
# KVM File and Filesystem qualifications.  The operation-specific Rust entry
# point owns the durable-state semantics; this helper owns reproducibility,
# provenance, isolation, and the matrix gate.
linux_kvm_mutation_reopen() {
  local operation="$1"
  local cli_command="$2"
  local matrix_schema="$3"
  local qualification_profile="$4"
  local report_path="$5"
  local qualification_prefix="$6"
  local cgroups_path="$7"
  local operation_label="${operation^}"

  : "${A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST:?set the exact Linux KVM system-image manifest}"

  source .github/scripts/lib/linux-kvm-provenance.sh

  if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'Linux KVM %s reopen qualification requires a Linux host\n' \
      "$operation_label" >&2
    exit 2
  fi

  for command in \
    awk cargo chmod cp curl cut dirname find id jq mkdir mktemp ps rm sha256sum sort \
    tail tee uname wc
  do
    if ! command -v "$command" >/dev/null 2>&1; then
      printf 'required Linux KVM %s reopen command is unavailable: %s\n' \
        "$operation_label" "$command" >&2
      exit 1
    fi
  done

  local architecture
  architecture="$(uname -m)"
  local alpine_name alpine_url
  case "$architecture" in
    x86_64)
      alpine_name="alpine-minirootfs-3.22.5-x86_64.tar.gz"
      alpine_url="https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/$alpine_name"
      ;;
    aarch64)
      alpine_name="alpine-minirootfs-3.22.5-aarch64.tar.gz"
      alpine_url="https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/$alpine_name"
      ;;
    *)
      printf 'unsupported Linux KVM %s reopen architecture: %s\n' \
        "$operation_label" "$architecture" >&2
      exit 2
      ;;
  esac

  local target_dir="${CARGO_TARGET_DIR:-target}"
  if [[ "$target_dir" != /* ]]; then
    target_dir="$PWD/$target_dir"
  fi
  local profile="${A3S_OCI_BUILD_PROFILE:-debug}"
  local -a build_arguments=(build -p a3s-oci-cli -p a3s-oci-krun)
  case "$profile" in
    debug) ;;
    release) build_arguments+=(--release) ;;
    *) build_arguments+=(--profile "$profile") ;;
  esac
  local binary_dir="$target_dir/$profile"
  local source_cli="$binary_dir/a3s-oci"
  local source_shim="$binary_dir/a3s-oci-krun-shim"
  local source_runtime_dir="$binary_dir/a3s-oci-krun-runtime"
  local runtime_assets_manifest="crates/krun/runtime/runtime-assets.json"

  local temporary_root="${RUNNER_TEMP:-/tmp}"
  test -d "$temporary_root"
  local work
  work="$(mktemp -d "$temporary_root/a3s-oci-kvm-${operation}-reopen.XXXXXX")"
  local current_stage="setup"
  local case_report=""
  local case_stderr=""
  cleanup() {
    local status=$?
    if [[ "$status" -ne 0 && "${A3S_OCI_KEEP_FAILED_WORK:-0}" == "1" ]]; then
      printf 'preserving failed Linux KVM %s reopen work directory: %s\n' \
        "$operation_label" "$work" >&2
      return 0
    fi
    case "$work" in
      "$temporary_root"/a3s-oci-kvm-${operation}-reopen.*)
        rm -rf -- "$work"
        ;;
      *)
        printf 'refusing to clean unexpected Linux KVM %s reopen path: %s\n' \
          "$operation_label" "$work" >&2
        return 1
        ;;
    esac
  }
  trap cleanup EXIT

  on_error() {
    local status=$?
    trap - ERR
    printf 'Linux KVM %s reopen stage %s failed with status %s near line %s\n' \
      "$operation_label" "$current_stage" "$status" "${BASH_LINENO[0]}" >&2
    if [[ -n "$case_report" && -s "$case_report" ]]; then
      jq --compact-output \
        '{schema_version, status, requested_stage, reason,
          first_response_matches_durable_record,
          replacement_rehydrated_file, replacement_rehydrated_filesystem,
          operation_replayed_without_driver_dispatch,
          replacement_file_effect_verified, replacement_filesystem_effect_verified,
          first_operation_dispatches, replacement_operation_dispatches,
          host_service_reopened, replacement_recovery_calls,
          host_changed_request_rejected, guest_changed_request_rejected,
          host_stale_generation_rejected, guest_stale_generation_rejected,
          force_delete_completed, durable_records_empty,
          marker_absent_after_cleanup, file_effect_absent_after_cleanup,
          filesystem_effect_absent_after_cleanup, owners_distinct, state_root_removed}' \
        "$case_report" >&2 2>/dev/null || true
    fi
    if [[ -n "$case_stderr" && -s "$case_stderr" ]]; then
      tail -n 40 "$case_stderr" >&2 || true
    fi
    exit "$status"
  }
  trap on_error ERR

  if [[ -z "$report_path" ]]; then
    report_path="$work/report.json"
  fi
  if [[ -e "$report_path" || -L "$report_path" ]]; then
    printf 'refusing to overwrite Linux KVM %s reopen report: %s\n' \
      "$operation_label" "$report_path" >&2
    exit 1
  fi
  test -d "$(dirname "$report_path")"
  test -f "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"
  test ! -L "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"

  cargo "${build_arguments[@]}"
  test -x "$source_cli"
  test -x "$source_shim"
  test -d "$source_runtime_dir"

  local binary_stage="$work/bin"
  mkdir "$binary_stage"
  chmod 0700 "$work" "$binary_stage"
  cp -p "$source_cli" "$binary_stage/a3s-oci"
  cp -p "$source_shim" "$binary_stage/a3s-oci-krun-shim"
  cp -a "$source_runtime_dir" "$binary_stage/a3s-oci-krun-runtime"
  local cli="$binary_stage/a3s-oci"
  local shim="$binary_stage/a3s-oci-krun-shim"
  local runtime_dir="$binary_stage/a3s-oci-krun-runtime"

  local provenance
  provenance="$(
    linux_kvm_provenance \
      "$qualification_profile" "$profile" \
      "$cli" "$shim" "$runtime_dir" \
      "$runtime_assets_manifest" \
      "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"
  )"

  local features kvm_driver kvm_status manifest_sha256
  features="$($cli features)"
  kvm_driver="$(jq --compact-output '.drivers[] | select(.driver == "libkrun-kvm")' <<<"$features")"
  test -n "$kvm_driver"
  kvm_status="$(jq --raw-output '.status' <<<"$kvm_driver")"
  manifest_sha256="$(sha256sum "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" | cut -d ' ' -f 1)"

  if [[ "$kvm_status" == "unavailable" ]]; then
    local reason
    reason="$(jq --raw-output '.reason // "Linux KVM is unavailable"' <<<"$kvm_driver")"
    jq --null-input \
      --arg architecture "$architecture" \
      --arg manifest_sha256 "$manifest_sha256" \
      --arg reason "$reason" \
      --argjson kvm_driver "$kvm_driver" \
      --argjson provenance "$provenance" \
      --arg schema "$matrix_schema" \
      --arg profile_name "$qualification_profile" \
      --arg operation "$operation" \
      '{
        schema_version: $schema,
        platform: "linux",
        architecture: $architecture,
        status: "unavailable",
        kvm_required: true,
        qualification_scope: "linux-kvm-operation-stage-reopen-only-v1",
        expected_case_count: 9,
        case_count: 0,
        system_image_manifest_sha256: $manifest_sha256,
        provenance: $provenance,
        kvm_driver: $kvm_driver,
        operation: $operation,
        qualification_profile: $profile_name,
        cases: [],
        reason: $reason
      }' | tee "$report_path"
    jq --exit-status \
      --arg schema "$matrix_schema" \
      --arg profile_name "$qualification_profile" \
      '.schema_version == $schema
       and .platform == "linux" and .status == "unavailable"
       and .qualification_scope == "linux-kvm-operation-stage-reopen-only-v1"
       and .kvm_required and .expected_case_count == 9 and .case_count == 0
       and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
       and .provenance.qualification_profile == $profile_name
       and .provenance.source_tree_clean
      and .kvm_driver.status == "unavailable"
       and .cases == [] and (.reason | length > 0)' \
      "$report_path" >/dev/null
    trap - EXIT
    cleanup
    return 0
  fi
  if [[ "$kvm_status" != "available" ]]; then
    printf 'unexpected Linux KVM probe status: %s\n' "$kvm_status" >&2
    exit 1
  fi

  local alpine_archive="${A3S_OCI_LINUX_KVM_ALPINE_ARCHIVE:-}"
  if [[ -n "$alpine_archive" ]]; then
    test -f "$alpine_archive"
    test ! -L "$alpine_archive"
    cp -p "$alpine_archive" "$work/$alpine_name"
  else
    alpine_archive="$work/$alpine_name"
    curl --fail --location --retry 3 --silent --show-error \
      --output "$alpine_archive" "$alpine_url"
  fi
  local rootfs_archive_sha256
  rootfs_archive_sha256="$(sha256sum "$alpine_archive" | cut -d ' ' -f 1)"
  local bundle="$work/bundle"
  scripts/prepare-utility-vm-bundle.sh \
    --alpine-archive "$alpine_archive" \
    --config fixtures/utility-vm/config.linux-kvm.json \
    --bundle "$bundle" \
    --cgroups-path "$cgroups_path"
  local init_marker="$bundle/rootfs/.a3s-oci-create-start-smoke"
  test ! -e "$init_marker"

  local case_report_directory="$work/cases"
  mkdir "$case_report_directory"
  chmod 0700 "$case_report_directory"
  local cases_path="$work/cases.ndjson"
  : > "$cases_path"

  endpoint_inventory() {
    find /tmp -maxdepth 1 -type d -uid "$(id -u)" \
      -name 'a3s-oci-agent-*' -print 2>/dev/null | sort
  }
  shim_process_inventory() {
    ps -eo pid=,comm= | \
      awk 'index($2, "a3s-oci-krun") == 1 {print $1 " " $2}' | sort
  }
  local endpoint_baseline process_baseline
  endpoint_baseline="$(endpoint_inventory)"
  process_baseline="$(shim_process_inventory)"

  local -a stages=(
    host-before-request-write
    host-after-request-write
    host-before-response-read
    host-after-response-read
    guest-after-request-read
    guest-before-dispatch
    guest-after-dispatch
    guest-before-response-write
    guest-after-response-write
  )

  run_stage() {
    local stage="$1"
    local runtime_root="$work/runtime-$stage"
    local status
    current_stage="$stage"
    case_report="$case_report_directory/$stage.json"
    case_stderr="$case_report_directory/$stage.stderr.log"
    printf 'Qualifying Linux KVM %s reopen stage: %s\n' "$operation_label" "$stage" >&2

    set +e
    "$cli" "$cli_command" \
      --shim "$shim" \
      --runtime-root "$runtime_root" \
      --system-image-manifest "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" \
      --bundle "$bundle" \
      --fault-at "$stage" \
      > "$case_report" 2> "$case_stderr"
    status=$?
    set -e
    test "$status" -eq 0

    jq --exit-status \
      --arg stage "$stage" \
      --arg architecture "$architecture" \
      --arg manifest_sha256 "$manifest_sha256" \
      --arg operation "$operation" \
      --arg prefix "$qualification_prefix" \
      '.schema_version
         == (if $operation == "file"
             then "a3s.oci.oci-vm-operation-reopen-replacement.v18"
             else "a3s.oci.oci-vm-operation-reopen-replacement.v19" end)
       and .platform == "linux" and .status == "available"
       and .bundle_loaded and .requested_operation == $operation
       and .requested_stage == $stage
       and (.qualification_operation_id | startswith($prefix))
       and (.setup_create_operation_id | startswith($prefix))
       and (.setup_start_operation_id | startswith($prefix))
       and (.qualification_operation_id != .setup_create_operation_id)
       and (.qualification_operation_id != .setup_start_operation_id)
       and (.setup_create_operation_id != .setup_start_operation_id)
       and (.setup_exec_operation_id == null)
       and (.setup_kill_operation_id == null)
       and (.container_id | startswith($prefix))
       and .negotiated_protocol == 10
       and .injected_point == ("agent-v10." + $operation + "-" + $stage)
       and .fault_crossings == 1
       and .first_operation_error_code == "unavailable"
       and .first_operation_error_retryable
       and (if ($stage | startswith("guest-")) then
              (.first_operation_error_operation
               | IN("agent-protocol", "read-agent-frame-header",
                    "read-agent-frame-payload", "write-agent-frame-header",
                    "write-agent-frame-payload", "flush-agent-frame"))
              and .guest_evidence_verified
              and (.guest_evidence_operation_id == .qualification_operation_id)
            else
              .first_operation_error_operation
                == "oci-vm-transport-qualification-fault"
              and (.guest_evidence_verified | not)
              and (.guest_evidence_operation_id == null)
            end)
       and (if $stage == "guest-after-response-write" then
              .first_response_matches_durable_record
              and .operation_replayed_without_driver_dispatch
              and (if $operation == "file"
                   then .replacement_rehydrated_file
                   else .replacement_rehydrated_filesystem end)
            else
              (.first_response_matches_durable_record | not)
              and (.operation_replayed_without_driver_dispatch | not)
              and (if $operation == "file"
                   then (.replacement_rehydrated_file | not)
                   else (.replacement_rehydrated_filesystem | not) end)
            end)
       and (.first_operation_response_received | not)
       and (.disconnect_probe_attempted | not)
       and (if $operation == "file"
            then (.first_file_response_verified | not)
                 and .replacement_file_response_verified
                 and .file_response_replayed
                 and .replacement_file_effect_verified
                 and .file_request_identity_reused
                 and .file_effect_absent_after_cleanup
            else (.first_filesystem_response_verified | not)
                 and .replacement_filesystem_response_verified
                 and .filesystem_response_replayed
                 and .replacement_filesystem_effect_verified
                 and .filesystem_request_identity_reused
                 and .filesystem_effect_absent_after_cleanup end)
       and (.durable_created_retained | not)
       and .durable_running_retained
       and (.durable_stopped_retained | not)
       and (.first_durable_records_empty | not)
       and (.first_created_pid > 0)
       and (.first_exec_pid == null)
       and .generation_before_reopen == 1
       and .host_service_reopened and .replacement_recovery_calls == 1
       and .replacement_rehydrated_created_record
       and .replacement_rehydrated_running_record
       and (.replacement_rehydrated_stopped_record | not)
       and (.replacement_rehydrated_exec_record | not)
       and .operation_completed_after_reopen
       and .generation_after_reopen == .generation_before_reopen
       and (.replacement_created_pid > 0)
       and (.replacement_exec_pid == null)
       and .replacement_response_matches_durable_record
       and .same_generation_reused
       and .setup_create_identity_reused and .setup_start_identity_reused
       and (.setup_kill_identity_reused | not)
       and .same_operation_id_reused
       and .setup_create_response_rebound and .setup_start_response_rebound
       and (.exec_response_rebound | not)
       and (.first_operation_dispatches == 1)
       and (.replacement_operation_dispatches == 1)
       and .host_changed_request_rejected
       and (.guest_changed_request_rejected | not)
       and .host_stale_generation_rejected and .guest_stale_generation_rejected
       and .marker_reset_before_replacement and .replacement_workload_verified
       and .force_delete_completed and (.stopped_only_delete_completed | not)
       and .durable_records_empty
       and (.delete_journal_succeeded_empty_after_reopen | not)
       and .marker_absent_after_cleanup
       and .first_guest_runtime_clean and .replacement_guest_runtime_clean
       and .owners_distinct and .state_root_removed
       and (if $operation == "file"
            then (.file_path | startswith("/tmp/.a3s-oci-file-reopen-"))
                 and (.file_data | length > 0)
                 and .file_op == "upload"
                 and (.filesystem_path == null)
            else (.filesystem_path | startswith("/tmp/.a3s-oci-filesystem-reopen-"))
                 and .filesystem_op == "make-dir"
                 and .filesystem_depth == 0
                 and (.file_path == null) end)
       and all(.first_vm, .replacement_vm;
         .platform == "linux" and .status == "available"
         and .endpoint_bound and .shim_spawned
         and (.shim_process_id > 0) and (.bridge_process_id > 0)
         and .shim_client_verified and .protocol_negotiated
         and .selected_protocol == 10
         and .guest_architecture == $architecture
         and .shim_report_verified and .shim_exit_code == 0
         and .console_created
         and .shim_report.status == "available"
         and .shim_report.kvm_device_opened
         and .shim_report.kvm_api_verified
         and .shim_report.vm_entered
         and .shim_report.linux_boot_assets.target_arch == $architecture
         and .shim_report.linux_boot_assets.manifest_sha256 == $manifest_sha256)
       and (.first_vm.endpoint_name != .replacement_vm.endpoint_name)
       and (.first_vm.shim_process_id != .replacement_vm.shim_process_id)
       and (.first_vm.bridge_process_id != .replacement_vm.bridge_process_id)
       and (.reason == null)' \
      "$case_report" >/dev/null

    test ! -e "$init_marker"
    test ! -e "$runtime_root/operation-reopen-state"
    test -z "$(find "$runtime_root/bootstrap" -mindepth 1 -print -quit)"
    test -z "$(find "$runtime_root/bundle-handoffs" -mindepth 1 -print -quit)"
    test -z "$(find "$runtime_root/shares" -mindepth 1 -print -quit)"
    test -z "$(find "$runtime_root/recovery" -mindepth 1 -print -quit)"
    test "$(endpoint_inventory)" = "$endpoint_baseline"
    test "$(shim_process_inventory)" = "$process_baseline"

    jq --compact-output --arg stage "$stage" \
      '{
        stage: $stage,
        status: "available",
        cleanup: {
          endpoint_inventory_restored: true,
          shim_process_inventory_restored: true,
          bootstrap_empty: true,
          bundle_handoffs_clean: true,
          runtime_shares_clean: true,
          recovery_reports_clean: true,
          init_marker_absent: true
        },
        report: .
      }' "$case_report" >> "$cases_path"
  }

  local stage
  for stage in "${stages[@]}"; do
    run_stage "$stage"
  done

  local case_count
  case_count="$(wc -l < "$cases_path")"
  test "$case_count" -eq 9
  jq --null-input \
    --arg architecture "$architecture" \
    --arg rootfs_archive_sha256 "$rootfs_archive_sha256" \
    --arg manifest_sha256 "$manifest_sha256" \
    --argjson kvm_driver "$kvm_driver" \
    --argjson provenance "$provenance" \
    --arg operation "$operation" \
    --arg schema "$matrix_schema" \
    --arg profile_name "$qualification_profile" \
    --slurpfile cases "$cases_path" \
    '{
      schema_version: $schema,
      platform: "linux",
      architecture: $architecture,
      status: "available",
      kvm_required: true,
      qualification_scope: "linux-kvm-operation-stage-reopen-only-v1",
      expected_case_count: 9,
      case_count: ($cases | length),
      operation: $operation,
      qualification_profile: $profile_name,
      rootfs_archive_sha256: $rootfs_archive_sha256,
      system_image_manifest_sha256: $manifest_sha256,
      provenance: $provenance,
      kvm_driver: $kvm_driver,
      cases: $cases,
      reason: null
    }' | tee "$report_path"

  jq --exit-status \
    --arg schema "$matrix_schema" \
    --arg operation "$operation" \
    --arg profile_name "$qualification_profile" \
    '.schema_version == $schema
     and .platform == "linux" and .status == "available"
     and .qualification_scope == "linux-kvm-operation-stage-reopen-only-v1"
     and .kvm_required and .expected_case_count == 9 and .case_count == 9
     and .operation == $operation
     and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
     and .provenance.platform == .platform
     and .provenance.architecture == .architecture
     and .provenance.qualification_profile == $profile_name
     and .provenance.driver == "libkrun-kvm"
     and .provenance.isolation == "dedicated-vm"
     and .provenance.source_tree_clean
     and .provenance.system_image_manifest_sha256 == .system_image_manifest_sha256
     and .kvm_driver.status == "available"
     and ([.cases[].stage] | length) == 9
     and ([.cases[].stage] | unique | length) == 9
     and all(.cases[];
       .status == "available"
       and .report.status == "available"
       and .report.requested_stage == .stage
       and all(.cleanup[]; . == true))
     and (.reason == null)' \
    "$report_path" >/dev/null

  # The work directory is local to this function.  Run the EXIT cleanup while
  # that scope is still alive; otherwise Bash drops the local before firing
  # the trap and a successful qualification would leak its private VM state.
  trap - EXIT
  cleanup
}
