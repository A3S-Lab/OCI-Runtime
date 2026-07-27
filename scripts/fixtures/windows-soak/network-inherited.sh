#!/bin/sh
set -eu

evidence='/.a3s-network-evidence'
marker='/.a3s-oci-create-start-smoke'

on_term() {
    printf 'phase=term\n' >> "$evidence"
    exit 0
}
trap on_term TERM

printf 'phase=begin\n' > "$evidence"
self_net="$(readlink /proc/self/ns/net)"
printf 'self_net=%s\n' "$self_net" >> "$evidence"

interfaces="$(
    awk -F: '
        NR > 2 {
            gsub(/[[:space:]]/, "", $1)
            if (length($1) > 0) {
                print $1
            }
        }
    ' /proc/self/net/dev | sort
)"

route_count="$(
    awk 'NR > 1 { count += 1 } END { print count + 0 }' /proc/self/net/route
)"
{
    printf 'phase=probe\n'
    printf 'self_net=%s\n' "$self_net"
    printf 'interfaces=%s\n' "$(printf '%s' "$interfaces" | tr '\n' ',')"
    printf 'route_count=%s\n' "$route_count"
} >> "$evidence"
printf '%s\n' "$interfaces" | grep -qx 'lo'
{
    printf 'phase=ready\n'
    printf 'mode=inherited\n'
} >> "$evidence"
printf 'a3s-oci-create-start-user-time-v1\n' > "$marker"

while :; do
    sleep 1
done
