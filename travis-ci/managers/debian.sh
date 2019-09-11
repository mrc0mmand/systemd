#!/bin/bash

# Run this script from the root of the systemd's git repository
# or set REPO_ROOT to a correct path.
#
# Example execution on Fedora:
# dnf install docker
# systemctl start docker
# export CONT_NAME="my-fancy-container"
# travis-ci/managers/debian.sh SETUP RUN CLEANUP

PHASES=(${@:-SETUP RUN RUN_ASAN CLEANUP})
DEBIAN_RELEASE="${DEBIAN_RELEASE:-testing}"
CONT_NAME="${CONT_NAME:-debian-$DEBIAN_RELEASE-$RANDOM}"
DOCKER_EXEC="${DOCKER_EXEC:-docker exec -it $CONT_NAME}"
DOCKER_RUN="${DOCKER_RUN:-docker run}"
REPO_ROOT="${REPO_ROOT:-$PWD}"
ADDITIONAL_DEPS=(
    clang
    curl
    git
    perl
    python3-libevdev
    python3-pyparsing
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
            info "Using Debian $DEBIAN_RELEASE"
            printf "FROM debian:$DEBIAN_RELEASE\nRUN bash -c 'apt-get -y update && apt-get install -y systemd'\n" | docker build -t debian-with-systemd/latest -
            info "Starting container $CONT_NAME"
            $DOCKER_RUN -v $REPO_ROOT:/build:rw -e container=docker \
                        -w /build --privileged=true --name $CONT_NAME \
                        -dit --net=host debian-with-systemd/latest /bin/systemd
            $DOCKER_EXEC bash -c "echo deb-src http://deb.debian.org/debian $DEBIAN_RELEASE main >>/etc/apt/sources.list"
            $DOCKER_EXEC apt-get -y update
            $DOCKER_EXEC apt-get -y build-dep systemd
            $DOCKER_EXEC apt-get -y install "${ADDITIONAL_DEPS[@]}"
            ;;
        RUN|RUN_CLANG)
            if [[ "$phase" = "RUN_CLANG" ]]; then
                ENV_VARS="-e CC=clang -e CXX=clang++"
            fi
            docker exec $ENV_VARS -it $CONT_NAME meson --werror -Dtests=unsafe -Dslow-tests=true -Dsplit-usr=true -Dman=true build
            $DOCKER_EXEC ninja -v -C build
            docker exec -e "TRAVIS=$TRAVIS" -it $CONT_NAME ninja -C build test
            ;;
        RUN_ASAN|RUN_CLANG_ASAN)
            if [[ "$phase" = "RUN_CLANG_ASAN" ]]; then
                ENV_VARS="-e CC=clang -e CXX=clang++"
                MESON_ARGS="-Db_lundef=false" # See https://github.com/mesonbuild/meson/issues/764
            fi
            docker exec $ENV_VARS -it $CONT_NAME meson --werror -Dtests=unsafe -Db_sanitize=address,undefined -Dsplit-usr=true $MESON_ARGS build
            $DOCKER_EXEC ninja -v -C build

            # Never remove halt_on_error from UBSAN_OPTIONS. See https://github.com/systemd/systemd/commit/2614d83aa06592aedb.
            travis_wait docker exec --interactive=false \
                -e UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1 \
                -e ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1 \
                -e "TRAVIS=$TRAVIS" \
                -t $CONT_NAME \
                meson test --timeout-multiplier=3 -C ./build/ --print-errorlogs
            ;;
        CODECOV)
            ENV_VARS=(
                -e LDFLAGS="-lgcov --coverage"
            )
            docker exec "${ENV_VARS[@]}" -it $CONT_NAME meson --werror -Dc_args="-O0 -coverage" -Dtests=unsafe -Dslow-tests=true -Dsplit-usr=true build
            $DOCKER_EXEC ninja -v -C build
            docker exec -e "TRAVIS=$TRAVIS" -it $CONT_NAME meson test -C build --print-errorlogs --timeout-multiplier=3

            # This expands to a set of env variables (in -e ENV=xxx format)
            # so Codecov can correctly detect Travis CI even when running
            # under docker
            # See: https://docs.codecov.io/docs/testing-with-docker
            CODECOV_ENV=$(bash <(curl -s https://codecov.io/env))
            # Collect results and send them to Codecov
            # In Travis CI (and other CIs) we don't need to supply an API key
            docker exec $CODECOV_ENV -it $CONT_NAME bash -c 'bash <(curl -s https://codecov.io/bash) -X coveragepy'
            ;;
        CLEANUP)
            info "Cleanup phase"
            docker stop $CONT_NAME
            docker rm -f $CONT_NAME
            ;;
        *)
            echo >&2 "Unknown phase '$phase'"
            exit 1
    esac
done
