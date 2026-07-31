#!/bin/sh
set -eu

evidence='/.a3s-network-evidence'
marker='/.a3s-oci-create-start-smoke'

on_term() {
    printf 'phase=term\n' >> "$evidence"
    exit 0
}
trap on_term TERM

self_net="$(readlink /proc/self/ns/net)"
init_net="$(readlink /proc/1/ns/net)"
test "$self_net" = "$init_net"

interfaces="$(
    awk -F: '
        NR > 2 {
            gsub(/[[:space:]]/, "", $1)
            if (length($1) > 0) {
                print $1
            }
        }
    ' /proc/net/dev | sort
)"
printf '%s\n' "$interfaces" | grep -qx 'lo'

route_count="$(
    awk 'NR > 1 { count += 1 } END { print count + 0 }' /proc/net/route
)"
{
    printf 'phase=ready\n'
    printf 'mode=inherited\n'
    printf 'self_net=%s\n' "$self_net"
    printf 'init_net=%s\n' "$init_net"
    printf 'interfaces=%s\n' "$(printf '%s' "$interfaces" | tr '\n' ',')"
    printf 'route_count=%s\n' "$route_count"
} > "$evidence"
printf 'a3s-oci-create-start-v1\n' > "$marker"

while :; do
    sleep 1
done
