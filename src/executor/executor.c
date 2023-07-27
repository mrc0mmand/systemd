/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "alloc-util.h"
#include "build.h"
#include "execute-serialize.h"
#include "exit-status.h"
#include "fdset.h"
#include "fd-util.h"
#include "fileio.h"
#include "getopt-defs.h"
#include "io-util.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "sd-messages.h"
#include "socket-util.h"
#include "unit-serialize.h"

static FILE* arg_serialization = NULL;
static int arg_manager_socket = -EBADF;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s\n\n"
               "Sandbox and execute processes.\n\n"
               "  -h --help              Show this help and exit\n"
               "  --version              Print version string and exit\n"
               "  --log-target=TARGET    Set log target (console, journal, kmsg,\n"
               "                                         journal-or-kmsg, null)\n"
               "  --log-level=LEVEL      Set log level (debug, info, notice, warning,\n"
               "                                        err, crit, alert, emerg)\n"
               "  --log-color[=BOOL]     Highlight important log messages\n"
               "  --log-location[=BOOL]  Include code location in log messages\n"
               "  --log-time[=BOOL]      Prefix log messages with current time\n"
               "  --deserialize=FD       Deserialize process config from FD\n"
               "  --manager-socket=FD    Socket to receive commands from manager\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                COMMON_GETOPT_ARGS,
                ARG_VERSION,
                ARG_DESERIALIZE,
                ARG_MANAGER_SOCKET,
        };

        static const struct option options[] = {
                COMMON_GETOPT_OPTIONS,
                { "help",           no_argument,       NULL, 'h'                },
                { "version",        no_argument,       NULL, ARG_VERSION        },
                { "deserialize",    required_argument, NULL, ARG_DESERIALIZE    },
                { "manager-socket", required_argument, NULL, ARG_MANAGER_SOCKET },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_LOG_LEVEL:
                        r = log_set_max_level_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log level \"%s\": %m", optarg);

                        break;

                case ARG_LOG_TARGET:
                        r = log_set_target_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log target \"%s\": %m", optarg);

                        break;

                case ARG_LOG_COLOR:

                        if (optarg) {
                                r = log_show_color_from_string(optarg);
                                if (r < 0)
                                        return log_error_errno(r,
                                                        "Failed to parse log color setting \"%s\": %m",
                                                        optarg);
                        } else
                                log_show_color(true);

                        break;

                case ARG_LOG_LOCATION:
                        if (optarg) {
                                r = log_show_location_from_string(optarg);
                                if (r < 0)
                                        return log_error_errno(r,
                                                        "Failed to parse log location setting \"%s\": %m",
                                                        optarg);
                        } else
                                log_show_location(true);

                        break;

                case ARG_LOG_TIME:

                        if (optarg) {
                                r = log_show_time_from_string(optarg);
                                if (r < 0)
                                        return log_error_errno(r,
                                                        "Failed to parse log time setting \"%s\": %m",
                                                        optarg);
                        } else
                                log_show_time(true);

                        break;

                case ARG_DESERIALIZE: {
                        FILE *f;
                        int fd;

                        fd = parse_fd(optarg);
                        if (fd < 0)
                                return log_error_errno(fd,
                                                "Failed to parse serialization fd \"%s\": %m",
                                                optarg);

                        (void) fd_cloexec(fd, true);

                        f = fdopen(fd, "r");
                        if (!f)
                                return log_error_errno(errno, "Failed to open serialization fd %d: %m", fd);

                        safe_fclose(arg_serialization);
                        arg_serialization = f;

                        break;
                }

                case ARG_MANAGER_SOCKET: {
                        int fd;

                        fd = parse_fd(optarg);
                        if (fd < 0)
                                return log_error_errno(fd,
                                                "Failed to parse manager socket \"%s\": %m",
                                                optarg);

                        (void) fd_cloexec(fd, true);

                        safe_close(arg_manager_socket);
                        arg_manager_socket = fd;

                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (!arg_serialization && arg_manager_socket < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No serialization nor manager socket specified.");

        if (arg_serialization && arg_manager_socket >= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Both serialization and manager socket specified.");

        return 1 /* work to do */;
}

int main(int argc, char *argv[]) {
        _cleanup_fclose_ FILE *serialization = NULL;
        _cleanup_close_ int manager_socket = -EBADF;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unit_freep) Unit *unit = NULL;
        _cleanup_free_ int *fds_array = NULL;
        int exit_status = EXIT_SUCCESS, r;
        size_t n_fds_array = 0;
        _cleanup_(exec_params_serialized_clear) ExecParameters params = {
                .stdin_fd         = -EBADF,
                .stdout_fd        = -EBADF,
                .stderr_fd        = -EBADF,
                .exec_fd          = -EBADF,
                .user_lookup_fd   = -EBADF,
                .bpf_outer_map_fd = -EBADF,
        };
        ExecCommand command = {};
        DynamicCreds dynamic_creds = {
        };
        ExecSharedRuntime shared = {
                .netns_storage_socket = PIPE_EBADF,
                .ipcns_storage_socket = PIPE_EBADF,
        };
        ExecRuntime runtime = {
                .ephemeral_storage_socket = PIPE_EBADF,
                .shared = &shared,
                .dynamic_creds = &dynamic_creds,
        };

        /* We might be starting the journal itself, we'll be told by the caller what to do */
        log_set_always_reopen_console(true);
        log_set_prohibit_ipc(true);
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        /* Now try again if we were told it's fine to use a different target */
        if (log_get_target() != LOG_TARGET_KMSG) {
                log_set_prohibit_ipc(false);
                log_open();
        }

        /* If we are forked directly then we will have all the required FDs already open, create a set to
         * prepare for deserialization. If we are getting a socket instead we'll get them in an array via
         * SCM_RIGHTS. */
        if (arg_serialization) {
                serialization = arg_serialization;

                r = fdset_new_fill(/* filter_cloexec= */ 0, &fdset);
                if (r < 0)
                        return log_error_errno(r, "Failed to create fd set: %m");
        } else if (arg_manager_socket >= 0) {
                _cleanup_close_ int serialization_fd = -EBADF, pidfd = -EBADF;

                manager_socket = arg_manager_socket;

                /* Wait for serialization FD from manager datagram socket */
                r = receive_many_fds(manager_socket, &fds_array, &n_fds_array, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to receive serialization FDs: %m");

                /* There always at the very least the exec FD */
                if (n_fds_array == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Received no FDs from manager socket.");

                /* The memfd with all the data is always the first one */
                serialization_fd = TAKE_FD(fds_array[0]);

                log_debug("Accepting work from worker " PID_FMT, getpid_cached());

                /* Send back pidfd so that systemd knows who took up this job */
                pidfd = pidfd_open(getpid_cached(), 0);
                if (pidfd < 0) {
                        char iov_buffer[DECIMAL_STR_MAX(pid_t) + 1] = {};
                        struct iovec iov = IOVEC_MAKE(iov_buffer, sizeof(iov_buffer) - 1);

                        if (!ERRNO_IS_NOT_SUPPORTED(errno))
                                return log_error_errno(errno, "Failed to open pidfd: %m");

                        /* Fallback to sending the pid */
                        xsprintf(iov_buffer, "%d", getpid_cached());
                        r = send_one_fd_iov(manager_socket, /* fd= */ -EBADF, &iov, 1, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send pid: %m");
                } else {
                        r = send_one_fd(manager_socket, pidfd, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send pidfd: %m");
                }

                serialization = take_fdopen(&serialization_fd, "r");
                if (!serialization)
                        return log_error_errno(errno, "Failed to open serialization fd: %m");
        } else
                assert_not_reached();

        r = exec_deserialize(serialization,
                             fdset,
                             fds_array,
                             n_fds_array,
                             &unit,
                             &command,
                             &params,
                             &runtime);
        if (r < 0) {
                exit_status = log_error_errno(r, "Failed to deserialize: %m");
                goto out;
        }

        /* The worker might have been spawned long before it needs to execute a child, so clear the
         * environment and set it to what the manager says it should be */
        clearenv();
        STRV_FOREACH(e, unit_get_exec_context(unit)->manager_environment) {
                r = putenv(*e);
                if (r < 0)
                        return r;
        }

        arg_serialization = serialization = safe_fclose(serialization);
        arg_manager_socket = manager_socket = safe_close(manager_socket);
        fds_array = mfree(fds_array);
        fdset = fdset_free(fdset);

        r = exec_child(unit,
                       &command,
                       unit_get_exec_context(unit),
                       &params,
                       &runtime,
                       unit_get_cgroup_context(unit),
                       &exit_status);
        if (r < 0) {
                const char *status =
                        exit_status_to_string(exit_status, EXIT_STATUS_LIBC | EXIT_STATUS_SYSTEMD);

                log_unit_struct_errno(unit, LOG_ERR, r,
                                      "MESSAGE_ID=" SD_MESSAGE_SPAWN_FAILED_STR,
                                      LOG_UNIT_INVOCATION_ID(unit),
                                      LOG_UNIT_MESSAGE(unit, "Failed at step %s spawning %s: %m",
                                                       status, command.path),
                                      "EXECUTABLE=%s", command.path);
        }

out:
        /* To make valgrind/msan happy when exec_child fails */
        exec_command_done_array(&command, /* n= */ 1);
        exec_shared_runtime_done(&shared);
        if (dynamic_creds.group != dynamic_creds.user)
                dynamic_user_free(dynamic_creds.group);
        dynamic_user_free(dynamic_creds.user);
        free(runtime.ephemeral_copy);
        safe_close_pair(runtime.ephemeral_storage_socket);

        return exit_status;
}
