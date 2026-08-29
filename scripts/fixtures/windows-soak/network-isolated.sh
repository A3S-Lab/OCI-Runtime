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
self_net="$(readlink /proc/self/ns/net 2>&1)" || self_net="error:$self_net"
printf 'self_net=%s\n' "$self_net" >> "$evidence"

interfaces="$(
    awk -F: '
        NR > 2 {
            gsub(/[[:space:]]/, "", $1)
            if (length($1) > 0) {
                print $1
            }
        }
    ' /proc/self/net/dev 2>&1 | sort
)" || interfaces="error:$interfaces"

route_count="$(
    awk 'NR > 1 { count += 1 } END { print count + 0 }' /proc/self/net/route 2>&1
)" || route_count="error:$route_count"

validation='pass'
if [ "$interfaces" != 'lo' ] || [ "$route_count" != '0' ]; then
    validation='fail'
fi

{
    printf 'phase=probe\n'
    printf 'self_net=%s\n' "$self_net"
    printf 'interfaces=%s\n' "$(printf '%s' "$interfaces" | tr '\n' ',')"
    printf 'route_count=%s\n' "$route_count"
    printf 'validation=%s\n' "$validation"
    printf 'phase=ready\n'
    printf 'mode=isolated\n'
} >> "$evidence"
printf 'a3s-oci-create-start-user-time-v1\n' > "$marker"

while :; do
    sleep 1
done
