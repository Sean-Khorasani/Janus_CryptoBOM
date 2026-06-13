#!/bin/sh
set -eu

mode_file="${0}.mode"
config_path_file="${0}.config"
reload_count_file="${0}.reload-count"
reload_observed_file="${0}.reload-observed"
mode="$(cat "$mode_file")"
config_path="$(cat "$config_path_file")"
config_content="$(cat "$config_path")"

case "${1:-}" in
    -t|configtest)
        if [ "$config_content" != "mutated" ]; then
            exit 90
        fi
        : > "${0}.validation-observed"
        if [ "$mode" = "validation-fail" ]; then
            exit 42
        fi
        exit 0
        ;;
esac

if [ "$mode" = "reload-fail-once" ]; then
    count=0
    if [ -f "$reload_count_file" ]; then
        count="$(cat "$reload_count_file")"
    fi
    count=$((count + 1))
    printf '%s\n' "$count" > "$reload_count_file"
    printf '%s\n' "$config_content" >> "$reload_observed_file"
    if [ "$count" -eq 1 ]; then
        [ "$config_content" = "mutated" ] || exit 91
        exit 43
    fi
    [ "$config_content" = "original" ] || exit 92
fi

exit 0
