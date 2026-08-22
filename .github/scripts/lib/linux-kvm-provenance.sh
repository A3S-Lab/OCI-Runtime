#!/usr/bin/env bash

# Build one fail-closed provenance object for retained Linux KVM evidence.
# Callers must run from the repository root after building the exact CLI and
# shim that the qualification will execute.
linux_kvm_provenance() {
  if [[ "$#" -ne 7 ]]; then
    printf '%s\n' \
      'linux_kvm_provenance requires profile, build profile, CLI, shim, runtime directory, runtime manifest, and system-image manifest' >&2
    return 2
  fi

  local qualification_profile="$1"
  local build_profile="$2"
  local host_executable="$3"
  local shim_executable="$4"
  local runtime_directory="$5"
  local runtime_assets_manifest="$6"
  local system_image_manifest="$7"
  local command

  for command in cut find git jq sha256sum uname wc; do
    if ! command -v "$command" >/dev/null 2>&1; then
      printf 'required Linux KVM provenance command is unavailable: %s\n' \
        "$command" >&2
      return 1
    fi
  done

  if [[ ! "$qualification_profile" =~ ^[a-z0-9][a-z0-9._-]{0,95}$ ]]; then
    printf 'invalid Linux KVM qualification profile: %s\n' \
      "$qualification_profile" >&2
    return 2
  fi
  if [[ ! "$build_profile" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
    printf 'invalid Cargo build profile: %s\n' "$build_profile" >&2
    return 2
  fi

  local path
  for path in \
    "$host_executable" "$shim_executable" \
    "$runtime_assets_manifest" "$system_image_manifest"
  do
    if [[ ! -f "$path" || -L "$path" ]]; then
      printf 'Linux KVM provenance input must be a real regular file: %s\n' \
        "$path" >&2
      return 1
    fi
  done
  if [[ ! -x "$host_executable" || ! -x "$shim_executable" ]]; then
    printf '%s\n' \
      'Linux KVM provenance executables must retain executable permission' >&2
    return 1
  fi
  if [[ ! -d "$runtime_directory" || -L "$runtime_directory" ]]; then
    printf 'Linux KVM runtime directory must be a real directory: %s\n' \
      "$runtime_directory" >&2
    return 1
  fi

  local architecture
  if ! architecture="$(uname -m)"; then
    printf '%s\n' 'failed to determine Linux KVM provenance architecture' >&2
    return 1
  fi
  case "$architecture" in
    x86_64 | aarch64) ;;
    *)
      printf 'unsupported Linux KVM provenance architecture: %s\n' \
        "$architecture" >&2
      return 2
      ;;
  esac

  local checkout_revision requested_revision source_tree_id source_status
  local source_object_format object_id_length
  if ! source_object_format="$(git rev-parse --show-object-format)"; then
    printf '%s\n' 'failed to determine the Git object format' >&2
    return 1
  fi
  case "$source_object_format" in
    sha1) object_id_length=40 ;;
    sha256) object_id_length=64 ;;
    *)
      printf 'unsupported Git object format for Linux KVM provenance: %s\n' \
        "$source_object_format" >&2
      return 1
      ;;
  esac
  if ! checkout_revision="$(git rev-parse --verify 'HEAD^{commit}')"; then
    printf '%s\n' 'failed to resolve the checked-out Git commit' >&2
    return 1
  fi
  requested_revision="${A3S_QUALIFICATION_SOURCE_COMMIT:-$checkout_revision}"
  if [[ ! "$requested_revision" =~ ^[0-9a-f]+$ ]] ||
    [[ "${#requested_revision}" -ne "$object_id_length" ]]; then
    printf 'Linux KVM source revision is not a canonical %s object ID: %s\n' \
      "$source_object_format" "$requested_revision" >&2
    return 1
  fi
  if [[ "$requested_revision" != "$checkout_revision" ]]; then
    printf 'Linux KVM source revision does not match the checked-out commit: expected %s, found %s\n' \
      "$checkout_revision" "$requested_revision" >&2
    return 1
  fi
  if ! source_tree_id="$(git rev-parse --verify 'HEAD^{tree}')"; then
    printf '%s\n' 'failed to resolve the checked-out Git tree' >&2
    return 1
  fi
  if [[ ! "$source_tree_id" =~ ^[0-9a-f]+$ ]] ||
    [[ "${#source_tree_id}" -ne "$object_id_length" ]]; then
    printf 'Linux KVM source tree identity is not a canonical %s object ID: %s\n' \
      "$source_object_format" "$source_tree_id" >&2
    return 1
  fi
  if ! source_status="$(git status --porcelain=v1 --untracked-files=all)"; then
    printf '%s\n' 'failed to inspect the Linux KVM source checkout' >&2
    return 1
  fi
  if [[ -n "$source_status" ]]; then
    printf '%s\n' \
      'Linux KVM retained qualification requires a clean source checkout' >&2
    return 1
  fi

  local runtime_bundle runtime_file_count runtime_entry_count
  if ! runtime_bundle="$(
    jq --compact-output --exit-status \
      --arg architecture "$architecture" \
      'if .schema_version != "a3s.oci.krun-runtime-assets.v1" then
         error("unexpected runtime asset schema")
       else
         [.bundles[] | select(
           .target_os == "linux" and .target_arch == $architecture
         )]
         | if length == 1 then .[0]
           else error("runtime manifest must contain one Linux architecture bundle")
           end
       end' \
      "$runtime_assets_manifest"
  )"; then
    printf '%s\n' \
      'failed to select one Linux architecture bundle from the runtime manifest' >&2
    return 1
  fi
  if ! jq --exit-status \
    --arg architecture "$architecture" \
    '.target_os == "linux" and .target_arch == $architecture
     and (.files | type) == "array" and (.files | length) > 0
     and ([.files[].name] | length) == ([.files[].name] | unique | length)
     and all(.files[];
       (.name | type) == "string"
       and (.name | test("^[A-Za-z0-9][A-Za-z0-9._+-]{0,255}$"))
       and (.sha256 | type) == "string"
       and (.sha256 | test("^[0-9a-f]{64}$")))' \
    <<<"$runtime_bundle" >/dev/null
  then
    printf '%s\n' 'Linux KVM runtime manifest contains invalid file identities' >&2
    return 1
  fi
  if ! jq --exit-status \
    --arg architecture "$architecture" \
    --argjson runtime_bundle "$runtime_bundle" \
    '.schema_version == "a3s.oci.linux-kvm-system-image.v1"
     and .architecture == $architecture and .runtime == $runtime_bundle' \
    "$system_image_manifest" >/dev/null
  then
    printf '%s\n' \
      'Linux KVM system-image manifest does not match the selected runtime bundle' >&2
    return 1
  fi

  if ! runtime_file_count="$(
    jq --raw-output '.files | length' <<<"$runtime_bundle"
  )"; then
    printf '%s\n' 'failed to count Linux KVM runtime manifest files' >&2
    return 1
  fi
  if ! runtime_entry_count="$(
    find "$runtime_directory" -mindepth 1 -maxdepth 1 -print | wc -l
  )"; then
    printf '%s\n' 'failed to count Linux KVM runtime directory entries' >&2
    return 1
  fi
  if [[ "$runtime_entry_count" -ne "$runtime_file_count" ]]; then
    printf 'Linux KVM runtime directory contains %s entries; manifest requires %s\n' \
      "$runtime_entry_count" "$runtime_file_count" >&2
    return 1
  fi

  local runtime_name expected_sha256 actual_sha256
  while IFS=$'\t' read -r runtime_name expected_sha256; do
    path="$runtime_directory/$runtime_name"
    if [[ ! -f "$path" || -L "$path" ]]; then
      printf 'Linux KVM runtime asset must be a real regular file: %s\n' \
        "$path" >&2
      return 1
    fi
    if ! actual_sha256="$(sha256sum "$path" | cut -d ' ' -f 1)"; then
      printf 'failed to hash Linux KVM runtime asset: %s\n' "$path" >&2
      return 1
    fi
    if [[ "$actual_sha256" != "$expected_sha256" ]]; then
      printf 'Linux KVM runtime asset digest mismatch for %s: expected %s, found %s\n' \
        "$runtime_name" "$expected_sha256" "$actual_sha256" >&2
      return 1
    fi
  done < <(jq --raw-output '.files[] | [.name, .sha256] | @tsv' <<<"$runtime_bundle")

  local host_sha256 shim_sha256 runtime_manifest_sha256 system_manifest_sha256
  if ! host_sha256="$(sha256sum "$host_executable" | cut -d ' ' -f 1)"; then
    printf 'failed to hash Linux KVM host executable: %s\n' \
      "$host_executable" >&2
    return 1
  fi
  if ! shim_sha256="$(sha256sum "$shim_executable" | cut -d ' ' -f 1)"; then
    printf 'failed to hash Linux KVM shim executable: %s\n' \
      "$shim_executable" >&2
    return 1
  fi
  if ! runtime_manifest_sha256="$(
    sha256sum "$runtime_assets_manifest" | cut -d ' ' -f 1
  )"; then
    printf 'failed to hash Linux KVM runtime manifest: %s\n' \
      "$runtime_assets_manifest" >&2
    return 1
  fi
  if ! system_manifest_sha256="$(
    sha256sum "$system_image_manifest" | cut -d ' ' -f 1
  )"; then
    printf 'failed to hash Linux KVM system-image manifest: %s\n' \
      "$system_image_manifest" >&2
    return 1
  fi

  jq --null-input --compact-output \
    --arg qualification_profile "$qualification_profile" \
    --arg build_profile "$build_profile" \
    --arg architecture "$architecture" \
    --arg source_object_format "$source_object_format" \
    --arg source_revision "$checkout_revision" \
    --arg source_tree_id "$source_tree_id" \
    --arg host_executable_sha256 "$host_sha256" \
    --arg shim_executable_sha256 "$shim_sha256" \
    --arg runtime_assets_manifest_sha256 "$runtime_manifest_sha256" \
    --arg system_image_manifest_sha256 "$system_manifest_sha256" \
    --argjson runtime_bundle "$runtime_bundle" \
    '{
      schema_version: "a3s.oci.linux-kvm-provenance.v1",
      platform: "linux",
      architecture: $architecture,
      qualification_profile: $qualification_profile,
      build_profile: $build_profile,
      source_object_format: $source_object_format,
      source_revision: $source_revision,
      source_tree_id: $source_tree_id,
      source_tree_clean: true,
      driver: "libkrun-kvm",
      isolation: "dedicated-vm",
      host_executable_sha256: $host_executable_sha256,
      shim_executable_sha256: $shim_executable_sha256,
      runtime_assets_manifest_sha256: $runtime_assets_manifest_sha256,
      system_image_manifest_sha256: $system_image_manifest_sha256,
      runtime_bundle: $runtime_bundle
    }'
}
