#!/bin/bash

PHASES=(${@:-SETUP RUN RUN_ASAN_UBSAN CLEANUP})
RELEASE="$(lsb_release -cs)"
ADDITIONAL_DEPS=(
    clang
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

function info() {
    echo -e "\033[33;1m$1\033[0m"
}

set -e

source "$(dirname $0)/travis_wait.bash"

for phase in "${PHASES[@]}"; do
    case $phase in
        SETUP)
            info "Setup phase"
            sudo bash -c "echo 'deb-src http://archive.ubuntu.com/ubuntu/ $RELEASE main restricted universe multiverse' >>/etc/apt/sources.list"
            # PPA with some newer build dependencies
            sudo add-apt-repository -y ppa:upstream-systemd-ci/systemd-ci
            sudo apt-get -y update
            sudo apt-get -y build-dep systemd
            sudo apt-get -y install "${ADDITIONAL_DEPS[@]}"
            ;;
        RUN|RUN_GCC|RUN_CLANG)
            if [[ "$phase" = "RUN_CLANG" ]]; then
                export CC=clang
                export CXX=clang++
                MESON_ARGS=(--optimization=1)
            fi
            meson --werror -Dtests=unsafe -Dslow-tests=true -Dfuzz-tests=true -Dsplit-usr=true -Dman=true "${MESON_ARGS[@]}" build
            ninja -v -C build
            ninja -C build test
            ;;
        RUN_ASAN_UBSAN|RUN_GCC_ASAN_UBSAN|RUN_CLANG_ASAN_UBSAN)
            if [[ "$phase" = "RUN_CLANG_ASAN_UBSAN" ]]; then
                export CC=clang
                export CXX=clang++
                # Build fuzzer regression tests only with clang (for now),
                # see: https://github.com/systemd/systemd/pull/15886#issuecomment-632689604
                # -Db_lundef=false: See https://github.com/mesonbuild/meson/issues/764
                MESON_ARGS=(-Db_lundef=false -Dfuzz-tests=true --optimization=1)
            fi
            meson --werror -Dtests=unsafe -Db_sanitize=address,undefined -Dsplit-usr=true "${MESON_ARGS[@]}" build
            ninja -v -C build

            export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1
            # Never remove halt_on_error from UBSAN_OPTIONS. See https://github.com/systemd/systemd/commit/2614d83aa06592aedb.
            export UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1
            meson test --timeout-multiplier=3 -C ./build/ --print-errorlogs
            ;;
        CLEANUP)
            info "Cleanup phase"
            ;;
        *)
            echo >&2 "Unknown phase '$phase'"
            exit 1
    esac
done
