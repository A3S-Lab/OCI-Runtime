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

grep -q ' /mnt/tree/proc .* - proc ' /proc/self/mountinfo
grep -q ' /scratch .* - tmpfs ' /proc/self/mountinfo
test "$(stat -c '%a' /scratch)" = '1770'

printf 'rw-round-trip-v1\n' > /mnt/rw/round-trip.txt
test "$(cat /mnt/rw/round-trip.txt)" = 'rw-round-trip-v1'
printf '#!/bin/sh\nexit 0\n' > /scratch/noexec.sh
chmod 0755 /scratch/noexec.sh
if /scratch/noexec.sh >/dev/null 2>&1; then
    exit 72
fi
printf 'tmpfs-volatile-v1\n' > /scratch/volatile.txt

{
    printf 'phase=ready\n'
    printf 'readonly=verified\n'
    printf 'nested_proc=verified\n'
    printf 'tmpfs=verified\n'
    printf 'noexec=verified\n'
    printf 'rw_round_trip=verified\n'
} > "$log"
printf 'a3s-oci-create-start-v1\n' > "$marker"

while :; do
    sleep 1
done
