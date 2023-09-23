#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

get_first_boot_id() {
    journalctl -b "${1:?}" -o json | jq -sr '.[0]._BOOT_ID'
}

get_last_boot_id() {
    journalctl -b "${1:?}" -o json -n 1 | jq -r '._BOOT_ID'
}

get_first_timestamp() {
    journalctl -b "${1:?}" -o json | jq -sr '.[0].__REALTIME_TIMESTAMP'
}

get_last_timestamp() {
    journalctl -b "${1:?}" -o json -n 1 | jq -r '.__REALTIME_TIMESTAMP'
}

if [[ "$REBOOT_COUNT" -lt 4 ]]; then
    # Issue: #29275, first part
    # Do a couple of reboots first to generate some boot entries in the journal
    systemd-cat echo "Reboot count: $REBOOT_COUNT"
    systemd-cat journalctl --list-boots
    systemctl_final reboot

elif [[ "$REBOOT_COUNT" -eq 4 ]]; then
    # Issue: #29275, second part
    # Now let's check if the boot entries are in the correct/expected order
    index=0
    journalctl --list-boots
    journalctl --list-boots -o json | jq -r '.[] | [.index, .boot_id, .first_entry, .last_entry] | @tsv' |
    while read -r offset boot_id first_ts last_ts; do
        : "Boot #$((index++)) with ID $boot_id"

        # Try the "regular" (non-json) variants first, as they provide a helpful
        # error message if something is not right
        journalctl -q -n 0 -b "$index"
        journalctl -q -n 0 -b "$offset"
        journalctl -q -n 0 -b "$boot_id"

        # Check the boot ID of the first entry
        entry_boot_id="$(get_first_boot_id "$index")"
        assert_eq "$entry_boot_id" "$boot_id"
        entry_boot_id="$(get_first_boot_id "$offset")"
        assert_eq "$entry_boot_id" "$boot_id"
        entry_boot_id="$(get_first_boot_id "$boot_id")"
        assert_eq "$entry_boot_id" "$boot_id"

        # Check the timestamp of the first entry
        entry_ts="$(get_first_timestamp "$index")"
        assert_eq "$entry_ts" "$first_ts"
        entry_ts="$(get_first_timestamp "$offset")"
        assert_eq "$entry_ts" "$first_ts"
        entry_ts="$(get_first_timestamp "$boot_id")"
        assert_eq "$entry_ts" "$first_ts"

        # Check the boot ID of the last entry
        entry_boot_id="$(get_last_boot_id "$index")"
        assert_eq "$entry_boot_id" "$boot_id"
        entry_boot_id="$(get_last_boot_id "$offset")"
        assert_eq "$entry_boot_id" "$boot_id"
        entry_boot_id="$(get_last_boot_id "$boot_id")"
        assert_eq "$entry_boot_id" "$boot_id"

        # Check the timestamp of the last entry
        if [[ "$offset" != "0" ]]; then
            entry_ts="$(get_last_timestamp "$index")"
            assert_eq "$entry_ts" "$last_ts"
            entry_ts="$(get_last_timestamp "$offset")"
            assert_eq "$entry_ts" "$last_ts"
            entry_ts="$(get_last_timestamp "$boot_id")"
            assert_eq "$entry_ts" "$last_ts"
        fi
    done
else
    assert_not_reached
fi

touch /testok
