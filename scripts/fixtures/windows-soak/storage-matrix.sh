#!/bin/sh
set -eu

log='/mnt/rw/lifecycle.log'
marker='/.a3s-oci-create-start-smoke'

on_term() {
    printf 'phase=term\n' >> "$log"
    exit 0
}
trap on_term TERM

test "$(cat /mnt/readonly/sentinel.txt)" = 'read-only-volume-v1'
if { printf 'tamper\n' >> /mnt/readonly/sentinel.txt; } 2>/dev/null; then
    exit 71
fi

printf 'rw-round-trip-v1\n' > /mnt/rw/round-trip.txt
test "$(cat /mnt/rw/round-trip.txt)" = 'rw-round-trip-v1'

{
    printf 'phase=ready\n'
    printf 'readonly=verified\n'
    printf 'rw_round_trip=verified\n'
} > "$log"
printf 'a3s-oci-create-start-user-time-v1\n' > "$marker"

while :; do
    sleep 1
done
