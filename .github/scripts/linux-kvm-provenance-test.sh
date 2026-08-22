#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repository_root/.github/scripts/lib/linux-kvm-provenance.sh"

for command in chmod cp cut git jq ln mkdir mktemp rm sha256sum uname; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required Linux KVM provenance test command is unavailable: %s\n' \
      "$command" >&2
    exit 1
  fi
done

temporary_root="${RUNNER_TEMP:-/tmp}"
test -d "$temporary_root"
work="$(mktemp -d "$temporary_root/a3s-oci-kvm-provenance-test.XXXXXX")"
cleanup() {
  case "$work" in
    "$temporary_root"/a3s-oci-kvm-provenance-test.*)
      rm -rf -- "$work"
      ;;
    *)
      printf 'refusing to clean unexpected provenance test path: %s\n' \
        "$work" >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT

source_repository="$work/source"
asset_root="$work/assets"
runtime_directory="$asset_root/runtime"
runtime_manifest="$asset_root/runtime-assets.json"
system_image_manifest="$asset_root/system-image.json"
host_executable="$asset_root/a3s-oci"
shim_executable="$asset_root/a3s-oci-krun-shim"
mkdir -p "$source_repository" "$runtime_directory"

git -C "$source_repository" init --quiet
git -C "$source_repository" config user.name 'A3S Test'
git -C "$source_repository" config user.email 'test@example.invalid'
printf 'tracked\n' > "$source_repository/tracked"
git -C "$source_repository" add tracked
git -C "$source_repository" commit --quiet --message initial

cp /bin/true "$host_executable"
cp /bin/true "$shim_executable"
chmod 0755 "$host_executable" "$shim_executable"
printf 'library\n' > "$runtime_directory/libkrun.so"
printf 'firmware\n' > "$runtime_directory/libkrunfw.so"

architecture="$(uname -m)"
library_sha256="$(
  sha256sum "$runtime_directory/libkrun.so" | cut -d ' ' -f 1
)"
firmware_sha256="$(
  sha256sum "$runtime_directory/libkrunfw.so" | cut -d ' ' -f 1
)"
runtime_bundle="$(
  jq --null-input --compact-output \
    --arg architecture "$architecture" \
    --arg library_sha256 "$library_sha256" \
    --arg firmware_sha256 "$firmware_sha256" \
    '{
      target_os: "linux",
      target_arch: $architecture,
      platform: ("linux-" + $architecture),
      files: [
        {
          role: "library",
          name: "libkrun.so",
          size: 8,
          sha256: $library_sha256
        },
        {
          role: "firmware",
          name: "libkrunfw.so",
          size: 9,
          sha256: $firmware_sha256
        }
      ]
    }'
)"
jq --null-input \
  --argjson runtime_bundle "$runtime_bundle" \
  '{
    schema_version: "a3s.oci.krun-runtime-assets.v1",
    bundles: [$runtime_bundle]
  }' > "$runtime_manifest"
jq --null-input \
  --arg architecture "$architecture" \
  --argjson runtime_bundle "$runtime_bundle" \
  '{
    schema_version: "a3s.oci.linux-kvm-system-image.v1",
    architecture: $architecture,
    runtime: $runtime_bundle
  }' > "$system_image_manifest"

invoke_provenance() {
  linux_kvm_provenance \
    linux-kvm-provenance-test-v1 debug \
    "$host_executable" "$shim_executable" "$runtime_directory" \
    "$runtime_manifest" "$system_image_manifest"
}

expect_rejection() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'Linux KVM provenance accepted invalid fixture: %s\n' "$name" >&2
    return 1
  fi
}

cd "$source_repository"
report="$(invoke_provenance)"
source_revision="$(git rev-parse HEAD)"
jq --exit-status \
  --arg architecture "$architecture" \
  --arg source_revision "$source_revision" \
  '.schema_version == "a3s.oci.linux-kvm-provenance.v1"
   and .platform == "linux" and .architecture == $architecture
   and .qualification_profile == "linux-kvm-provenance-test-v1"
   and .build_profile == "debug" and .source_object_format == "sha1"
   and .source_revision == $source_revision and .source_tree_clean
   and .driver == "libkrun-kvm" and .isolation == "dedicated-vm"
   and (.host_executable_sha256 | length) == 64
   and (.shim_executable_sha256 | length) == 64
   and (.runtime_bundle.files | length) == 2' <<<"$report" >/dev/null

A3S_QUALIFICATION_SOURCE_COMMIT=0000000000000000000000000000000000000000 \
  expect_rejection forged-source-revision invoke_provenance

printf 'dirty\n' >> tracked
expect_rejection dirty-checkout invoke_provenance
git restore tracked

printf 'extra\n' > "$runtime_directory/extra"
expect_rejection extra-runtime-file invoke_provenance
rm "$runtime_directory/extra"

cp "$runtime_directory/libkrun.so" "$asset_root/libkrun.so.backup"
rm "$runtime_directory/libkrun.so"
ln -s "$asset_root/libkrun.so.backup" "$runtime_directory/libkrun.so"
expect_rejection linked-runtime-file invoke_provenance
rm "$runtime_directory/libkrun.so"
cp "$asset_root/libkrun.so.backup" "$runtime_directory/libkrun.so"

printf 'drift\n' >> "$runtime_directory/libkrun.so"
expect_rejection digest-drift invoke_provenance
cp "$asset_root/libkrun.so.backup" "$runtime_directory/libkrun.so"

mismatched_system_image_manifest="$asset_root/system-image-mismatch.json"
jq '.architecture = "wrong"' "$system_image_manifest" \
  > "$mismatched_system_image_manifest"
system_image_manifest="$mismatched_system_image_manifest"
expect_rejection system-image-runtime-mismatch invoke_provenance
system_image_manifest="$asset_root/system-image.json"

duplicate_runtime_manifest="$asset_root/runtime-assets-duplicate.json"
duplicate_system_image_manifest="$asset_root/system-image-duplicate.json"
jq '.bundles[0].files[1].name = .bundles[0].files[0].name' \
  "$runtime_manifest" > "$duplicate_runtime_manifest"
jq --argjson runtime_bundle "$(
  jq --compact-output '.bundles[0]' "$duplicate_runtime_manifest"
)" '.runtime = $runtime_bundle' \
  "$system_image_manifest" > "$duplicate_system_image_manifest"
runtime_manifest="$duplicate_runtime_manifest"
system_image_manifest="$duplicate_system_image_manifest"
expect_rejection duplicate-runtime-name invoke_provenance
runtime_manifest="$asset_root/runtime-assets.json"
system_image_manifest="$asset_root/system-image.json"

sha256_repository="$work/source-sha256"
git init --quiet --object-format=sha256 "$sha256_repository"
git -C "$sha256_repository" config user.name 'A3S Test'
git -C "$sha256_repository" config user.email 'test@example.invalid'
printf 'tracked\n' > "$sha256_repository/tracked"
git -C "$sha256_repository" add tracked
git -C "$sha256_repository" commit --quiet --message initial
cd "$sha256_repository"
sha256_report="$(invoke_provenance)"
jq --exit-status \
  '.source_object_format == "sha256"
   and (.source_revision | length) == 64
   and (.source_tree_id | length) == 64' <<<"$sha256_report" >/dev/null

printf '%s\n' 'Linux KVM provenance contract passed'
