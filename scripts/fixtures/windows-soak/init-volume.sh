#!/bin/sh
set -eu

log='/var/lib/a3s-init/lifecycle.log'
marker='/.a3s-oci-create-start-smoke'

on_term() {
    printf 'phase=term\n' >> "$log"
    exit 0
}
trap on_term TERM

test "${A3S_INIT_SCENARIO:-}" = 'volume-init'
test "${A3S_INIT_DELAY_SECONDS:-}" = '1'
test "$(pwd)" = '/work'
umask_value="$(umask)"
test "$umask_value" = '0027' || test "$umask_value" = '27'
test "$(cat /etc/a3s-init.conf)" = 'profile=windows-whpx'
if { printf 'tamper\n' >> /etc/a3s-init.conf; } 2>/dev/null; then
    exit 81
fi

{
    printf 'phase=begin\n'
    printf 'scenario=%s\n' "$A3S_INIT_SCENARIO"
    printf 'cwd=%s\n' "$(pwd)"
    printf 'umask=%s\n' "$umask_value"
    printf 'config=verified\n'
} > "$log"
sleep "$A3S_INIT_DELAY_SECONDS"
printf 'phase=ready\n' >> "$log"
printf 'a3s-oci-create-start-v1\n' > "$marker"

while :; do
    sleep 1
done
