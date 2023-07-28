/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Notes on how to run the fuzzer manually:
 *  1) Build the fuzzers with LLVM's libFuzzer and ASan+UBSan:
 *    $ CC=clang CXX=clang++ meson build-libfuzz -Db_sanitize=address,undefined -Dllvm-fuzz=true -Db_lundef=false
 *
 *  2) Collect some valid inputs:
 *    $ awk 'match($0, /startswith\(.+, "([^"]+=)"/, m) { print m[1]; }' src/core/execute-serialize.c > test/fuzz/fuzz-execute-serialize/initial
 *
 *  3) Run the fuzzer:
 *    $ build-libfuzz/fuzz-execute-serialize test/fuzz/fuzz-execute-serialize
 */

#include <stdio.h>

#include "alloc-util.h"
#include "execute-serialize.h"
#include "fd-util.h"
#include "fuzz.h"
#include "service.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unit_freep) Unit *unit = NULL;
        _cleanup_free_ int *fds_array = NULL;
        size_t n_fds_array = 0;
        _cleanup_(exec_params_serialized_clear) ExecParameters params = {
                .stdin_fd         = -EBADF,
                .stdout_fd        = -EBADF,
                .stderr_fd        = -EBADF,
                .exec_fd          = -EBADF,
                .user_lookup_fd   = -EBADF,
                .bpf_outer_map_fd = -EBADF,
        };
        ExecContext exec_context_empty = {}, *exec_context_ptr;
        CGroupContext cgroup_context_empty = {}, *cgroup_context_ptr;
        DynamicCreds dynamic_creds = {};
        ExecCommand command = {};
        ExecSharedRuntime shared = {
                .netns_storage_socket = PIPE_EBADF,
                .ipcns_storage_socket = PIPE_EBADF,
        };
        ExecRuntime runtime = {
                .ephemeral_storage_socket = PIPE_EBADF,
                .shared = &shared,
                .dynamic_creds = &dynamic_creds,
        };

        /* We don't want to fill the logs with messages about parse errors.
         * Disable most logging if not running standalone. */
        if (!getenv("SYSTEMD_LOG_LEVEL")) {
                log_set_max_level(LOG_CRIT);
                log_set_target(LOG_TARGET_NULL);
        }

        assert_se(fdset = fdset_new());
        assert_se(f = data_to_file(data, size));

        (void) exec_deserialize(f, fdset, fds_array, n_fds_array, &unit, &command, &params, &runtime);
        exec_context_ptr = unit ? unit_get_exec_context(unit) : &exec_context_empty;
        cgroup_context_ptr = unit ? unit_get_cgroup_context(unit) : &cgroup_context_empty;
        (void) exec_serialize(f, fdset, &fds_array, &n_fds_array, unit, exec_context_ptr,
                              &command, &params, &runtime, cgroup_context_ptr);

        exec_command_done_array(&command, /* n= */ 1);
        exec_shared_runtime_done(&shared);
        if (dynamic_creds.group != dynamic_creds.user)
                dynamic_user_free(dynamic_creds.group);
        dynamic_user_free(dynamic_creds.user);
        free(runtime.ephemeral_copy);
        safe_close_pair(runtime.ephemeral_storage_socket);
        exec_context_done(&exec_context_empty);
        cgroup_context_done(&cgroup_context_empty);

        return 0;
}
