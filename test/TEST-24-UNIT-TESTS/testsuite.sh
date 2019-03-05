#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
#set -ex
#set -o pipefail

CHUNK_SIZE="$(nproc)"
IFS=$'\n' TEST_LIST=($(ls /usr/lib/systemd/tests/test-*))

# Check test results
# Arguments:
#   $1: test path
#   $2: test exit code
function check_result() {
    if [[ $# -ne 2 ]]; then
        echo >&2 "check_result: missing arguments"
        exit 1
    fi

    local name="${1##*/}"
    local ret=$2

    if [[ $ret -ne 0 && $ret != 77 ]]; then
        echo "$name failed with $ret"
        echo "$name" >> /failed-tests
        {
            echo "--- $name begin ---"
            cat "/$name.log"
            echo "--- $name end ---"
        } >> /failed
    elif [[ $ret == 77 ]]; then
        echo "$name skipped"
        echo "$name" >> /skipped-tests
        {
            echo "--- $name begin ---"
            cat "/$name.log"
            echo "--- $name end ---"
        } >> /skipped
    else
        echo "$name OK"
        echo "$name" >> /testok
    fi

    systemd-cat echo "--- $name ---"
    systemd-cat cat "/$name.log"
}

base=0
# Outer loop: run until $base exceeds or equals to the length of the TEST_LIST array
while [[ $base -lt ${#TEST_LIST[@]} ]]; do
    # Associative array for running tasks, where running[test-path]=PID
    declare -A running=()

    # Run CHUNK_SIZE tasks in parallel and save their PIDs into the aforementioned
    # associative array
    for (( chunk = 0; chunk < CHUNK_SIZE; chunk++ )); do
        idx=$((base + chunk))
        testcase="${TEST_LIST[$idx]}"
        # This covers both non-executable tests and indexes beyond array length
        if [[ -x $testcase ]]; then
            log_file="/${testcase##*/}.log"
            $testcase &> "$log_file" &
            running[$testcase]=$!
        fi
    done

    # Loop over all running tasks and wait for each of them to complete. After
    # that check result of each task.
    # This can be done in serialized fashion as we still have to wait for the
    # longest running task anyway.
    for key in "${!running[@]}"; do
        wait ${running[$key]}
        ec=$?
        check_result "$key" $ec
    done

    # Increment the base counter by number of tasks which we just ran in parallel
    base=$((base + CHUNK_SIZE))
    # To properly clear the associative array we need to call unset before
    # declare -A
    unset running
done

exit 0
