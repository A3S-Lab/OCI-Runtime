#!/bin/sh
set -eu

log='/var/lib/a3s-init/lifecycle.log'
{
    printf 'phase=begin\n'
    printf 'scenario=%s\n' "${A3S_INIT_SCENARIO:-missing}"
    printf 'phase=failure\n'
    printf 'exit=42\n'
} > "$log"
exit 42
