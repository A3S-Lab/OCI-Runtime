#!/bin/sh
set -eu

log='/mnt/rw/lifecycle.log'
marker='/.a3s-oci-create-start-smoke'

on_term() {
    printf 'phase=term\n' >> "$log"
    exit 0
}
trap on_term TERM

test "${A3S_INIT_SCENARIO:-}" = 'volume-init'
test "${A3S_INIT_DELAY_SECONDS:-}" = '1'
test "$(pwd)" = '/'

{
    printf 'phase=begin\n'
    printf 'scenario=%s\n' "$A3S_INIT_SCENARIO"
    printf 'cwd=%s\n' "$(pwd)"
    printf 'state_volume=rw\n'
} > "$log"
sleep "$A3S_INIT_DELAY_SECONDS"
printf 'phase=ready\n' >> "$log"
printf 'a3s-oci-create-start-user-time-v1\n' > "$marker"

while :; do
    sleep 1
done
