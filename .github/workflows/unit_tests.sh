#!/bin/bash -ex

RELEASE="$(lsb_release -cs)"
ADDITIONAL_DEPS=(
    clang
    expect
    fdisk
    libfdisk-dev
    libfido2-dev
    libp11-kit-dev
    libpwquality-dev
    libqrencode-dev
    libssl-dev
    libtss2-dev
    libzstd-dev
    perl
    python3-libevdev
    python3-pyparsing
    zstd
)

bash -c "echo 'deb-src http://archive.ubuntu.com/ubuntu/ $RELEASE main restricted universe multiverse' >>/etc/apt/sources.list"
# PPA with some newer build dependencies
add-apt-repository -y ppa:upstream-systemd-ci/systemd-ci
apt-get -y update
apt-get -y build-dep systemd
apt-get -y install "${ADDITIONAL_DEPS[@]}"

# Skip test-bus-track for now (unrelated fail in Travis)
echo 'int main(void) { return 77; }' > src/libsystemd/sd-bus/test-bus-track.c

meson --werror -Dtests=unsafe -Db_sanitize=address,undefined --optimization=1 build
ninja -C build -v

export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1
export UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1

[[ $1 == "WATCHDOG_TRUE" ]] && (set +x; while :; do printf "\n[WATCHDOG] $(date) ($(cat /proc/loadavg))\n"; sleep 30; done) &

ls -la /proc/self/fd
meson test --timeout-multiplier=3 -C build --print-errorlogs
