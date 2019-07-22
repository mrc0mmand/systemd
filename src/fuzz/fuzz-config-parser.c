/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>

#include "alloc-util.h"
#include "fuzz.h"
#include "load-fragment.h"
#include "service.h"
#include "strv.h"
#include "unit.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *str = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *u;
        /* Various destination variables for data from parser functions */
        CGroupContext dest_cgroupcontext = {};
        EmergencyAction dest_emergencyaction;
        ExecOutput dest_execoutput;
        int dest_int;
        JobMode dest_jobmode;
        usec_t dest_usec;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        str = memdup_suffix0(data, size);

        /* Create a dummy service unit (needed by some parsers) */
        assert_se(manager_new(UNIT_FILE_SYSTEM, MANAGER_TEST_RUN_MINIMAL, &m) >= 0);
        assert_se(unit_new_for_name(m, sizeof(Service), "fuzz-config-parser.service", &u) >= 0);

        (void) config_parse_job_mode_isolate(u->id, "test-file", 0, "test-section", 0,
                           "test-lvalue", 0, str, &dest_jobmode, NULL);
        {
                _cleanup_(strv_freep) char **dest_strv = NULL;
                (void) config_parse_exec_directories(u->id, "test-file", 0, "test-section", 0,
                                   "test-lvalue", 0, str, &dest_strv, u);
        }

        {
                ExitStatusSet dest_existstatusset = {};
                (void) config_parse_set_status(u->id, "test-file", 0, "test-section", 0,
                                   "test-lvalue", 0, str, &dest_existstatusset, NULL);
        }

        {
                _cleanup_(strv_freep) char **dest_strv = NULL;
                (void) config_parse_namespace_path_strv(u->id, "test-file", 0, "test-section", 0,
                                   "test-lvalue", 0, str, &dest_strv, u);
        }

        {
                ExecContext dest_execcontext = {};
                exec_context_init(&dest_execcontext);

                (void) config_parse_temporary_filesystems(u->id, "test-file", 0, "test-section", 0,
                                   "test-lvalue", 0, str, &dest_execcontext, u);

                exec_context_done(&dest_execcontext);
        }

        {
                ExecContext dest_execcontext = {};
                exec_context_init(&dest_execcontext);

                (void) config_parse_bind_paths(u->id, "test-file", 0, "test-section", 0,
                                   "test-lvalue", 0, str, &dest_execcontext, u);

                exec_context_done(&dest_execcontext);
        }

        (void) config_parse_job_timeout_sec(u->id, "test-file", 0, "test-section", 0,
                           "test-lvalue", 0, str, u, NULL);
        (void) config_parse_job_running_timeout_sec(u->id, "test-file", 0, "test-section", 0,
                           "test-lvalue", 0, str, u, NULL);
        (void) config_parse_emergency_action(u->id, "test-file", 0, "test-section", 0,
                           "test-lvalue", 0, str, &dest_emergencyaction, u);

        {
                _cleanup_free_ char *dest_str = NULL;
                (void) config_parse_pid_file(u->id, "test-file", 0, "test-section", 0,
                                   "test-lvalue", 0, str, &dest_str, u);
        }

        (void) config_parse_exit_status(u->id, "test-file", 0, "test-section", 0,
                           "test-lvalue", 0, str, &dest_int, NULL);
        (void) config_parse_disable_controllers(u->id, "test-file", 0, "test-section", 0,
                           "test-lvalue", 0, str, &dest_cgroupcontext, NULL);

        {
                _cleanup_(strv_freep) char **dest_strv = NULL;
                (void) config_parse_ip_filter_bpf_progs(u->id, "test-file", 0, "test-section", 0,
                                   "test-lvalue", 0, str, &dest_strv, u);
        }

        {
                _cleanup_(cpu_set_reset) CPUSet dest_cpuset = {};
                (void) config_parse_cpu_affinity2(u->id, "test-file", 0, "test-section", 0,
                                   "test-lvalue", 0, str, &dest_cpuset, NULL);
        }

        (void) config_parse_output_restricted(u->id, "test-file", 0, "test-section", 0,
                           "test-lvalue", 0, str, &dest_execoutput, NULL);
        (void) config_parse_crash_chvt(u->id, "test-file", 0, "test-section", 0,
                           "test-lvalue", 0, str, &dest_int, NULL);
        (void) config_parse_timeout_abort(u->id, "test-file", 0, "test-section", 0,
                           "test-lvalue", 0, str, &dest_usec, NULL);

        return 0;
}
