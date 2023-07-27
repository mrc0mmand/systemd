/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "af-list.h"
#include "capability-util.h"
#include "cgroup-setup.h"
#include "escape.h"
#include "execute-serialize.h"
#include "hexdecoct.h"
#include "fd-util.h"
#include "fileio.h"
#include "in-addr-prefix-util.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "percent-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "serialize.h"
#include "string-util.h"
#include "strv.h"
#include "unit.h"

static int exec_unit_serialize(const Unit *u, FILE *f) {
        int r;

        assert(f);

        if (!u)
                return 0;

        r = serialize_item(f, "exec-unit-type", unit_type_to_string(u->type));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-unit-id", u->id);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-unit-cgroup-id", "%" PRIu64, u->cgroup_id);
        if (r < 0)
                return r;

        if (!sd_id128_is_null(u->invocation_id)) {
                r = serialize_item_format(f, "exec-unit-invocation-id", SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(u->invocation_id));
                if (r < 0)
                        return r;
        }

        fputc('\n', f); /* End marker */

        return 0;
}

static int exec_unit_deserialize(Unit **ret_unit, FILE *f) {
        _cleanup_(unit_freep) Unit *unit = NULL;
        _cleanup_free_ char *id = NULL;
        sd_id128_t invocation_id = SD_ID128_NULL;
        int r, type = _UNIT_TYPE_INVALID;
        uint64_t cgroup_id = 0;

        assert(ret_unit);
        assert(f);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *val, *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read serialization line: %m");
                if (r == 0)
                        break;

                l = strstrip(line);
                if (isempty(l)) /* end marker */
                        break;

                if ((val = startswith(l, "exec-unit-type="))) {
                        type = unit_type_from_string(val);
                        if (type < 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse unit type: %s", val);
                } else if ((val = startswith(l, "exec-unit-id="))) {
                        r = free_and_strdup(&id, val);
                        if (r < 0)
                                return log_oom_debug();
                } else if ((val = startswith(l, "exec-unit-invocation-id="))) {
                        r = sd_id128_from_string(val, &invocation_id);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to parse invocation ID: %s", val);
                } else if ((val = startswith(l, "exec-unit-cgroup-id="))) {
                        r = safe_atou64(val, &cgroup_id);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to parse cgroup ID: %s", val);
                }
        }

        if (type < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse unit type '%d'", type);

        unit = unit_new(NULL, unit_vtable[type]->object_size);
        if (!unit)
                return log_oom_debug();

        unit->type = type;
        unit->cgroup_id = cgroup_id;
        unit->id = TAKE_PTR(id);

        if (UNIT_VTABLE(unit)->init)
                UNIT_VTABLE(unit)->init(unit);

        r = unit_set_invocation_id(unit, invocation_id);
        if (r < 0)
                return log_debug_errno(r,
                                "Failed to set invocation ID '" SD_ID128_FORMAT_STR "': %m",
                                SD_ID128_FORMAT_VAL(invocation_id));

        *ret_unit = TAKE_PTR(unit);

        return 0;
}

static int exec_cgroup_context_serialize(const CGroupContext *c, FILE *f) {
        _cleanup_free_ char *disable_controllers_str = NULL, *delegate_controllers_str = NULL, *cpuset_cpus = NULL, *cpuset_mems = NULL, *startup_cpuset_cpus = NULL, *startup_cpuset_mems = NULL;
        struct in_addr_prefix *iaai;
        int r;

        assert(f);

        if (!c)
                return 0;

        (void) cg_mask_to_string(c->disable_controllers, &disable_controllers_str);
        (void) cg_mask_to_string(c->delegate_controllers, &delegate_controllers_str);
        cpuset_cpus = cpu_set_to_range_string(&c->cpuset_cpus);
        startup_cpuset_cpus = cpu_set_to_range_string(&c->startup_cpuset_cpus);
        cpuset_mems = cpu_set_to_range_string(&c->cpuset_mems);
        startup_cpuset_mems = cpu_set_to_range_string(&c->startup_cpuset_mems);

        r = serialize_bool_elide(f, "exec-cgroup-context-cpu-acounting", c->cpu_accounting);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-io-accounting", c->io_accounting);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-block-io-accounting", c->blockio_accounting);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-memory-accounting", c->memory_accounting);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-tasks-accounting", c->tasks_accounting);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-ip-accounting", c->ip_accounting);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-memory-oom-group", c->memory_oom_group);
        if (r < 0)
                return r;

        if (c->cpu_weight != CGROUP_WEIGHT_INVALID) {
                r = serialize_item_format(f, "exec-cgroup-context-cpu-weight", "%" PRIu64, c->cpu_weight);
                if (r < 0)
                        return r;
        }

        if (c->startup_cpu_weight != CGROUP_WEIGHT_INVALID) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-cpu-weight", "%" PRIu64, c->startup_cpu_weight);
                if (r < 0)
                        return r;
        }

        if (c->cpu_shares != CGROUP_CPU_SHARES_INVALID) {
                r = serialize_item_format(f, "exec-cgroup-context-cpu-shares", "%" PRIu64, c->cpu_shares);
                if (r < 0)
                        return r;
        }

        if (c->startup_cpu_shares != CGROUP_CPU_SHARES_INVALID) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-cpu-shares", "%" PRIu64, c->startup_cpu_shares);
                if (r < 0)
                        return r;
        }

        if (c->cpu_quota_per_sec_usec != USEC_INFINITY) {
                r = serialize_usec(f, "exec-cgroup-context-cpu-quota-per-sec-usec", c->cpu_quota_per_sec_usec);
                if (r < 0)
                        return r;
        }

        if (c->cpu_quota_period_usec != USEC_INFINITY) {
                r = serialize_usec(f, "exec-cgroup-context-cpu-quota-period-usec", c->cpu_quota_period_usec);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-cgroup-context-allowed-cpus", cpuset_cpus);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-startup-allowed-cpus", startup_cpuset_cpus);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-allowed-memory-nodes", cpuset_mems);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-startup-allowed-memory-nodes", startup_cpuset_mems);
        if (r < 0)
                return r;

        if (c->io_weight != CGROUP_WEIGHT_INVALID) {
                r = serialize_item_format(f, "exec-cgroup-context-io-weight", "%" PRIu64, c->io_weight);
                if (r < 0)
                        return r;
        }

        if (c->startup_io_weight != CGROUP_WEIGHT_INVALID) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-io-weight", "%" PRIu64, c->startup_io_weight);
                if (r < 0)
                        return r;
        }

        if (c->blockio_weight != CGROUP_BLKIO_WEIGHT_INVALID) {
                r = serialize_item_format(f, "exec-cgroup-context-block-io-weight", "%" PRIu64, c->blockio_weight);
                if (r < 0)
                        return r;
        }

        if (c->startup_blockio_weight != CGROUP_BLKIO_WEIGHT_INVALID) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-block-io-weight", "%" PRIu64, c->startup_blockio_weight);
                if (r < 0)
                        return r;
        }

        if (c->default_memory_min > 0) {
                r = serialize_item_format(f, "exec-cgroup-context-default-memory-min", "%" PRIu64, c->default_memory_min);
                if (r < 0)
                        return r;
        }

        if (c->default_memory_low > 0) {
                r = serialize_item_format(f, "exec-cgroup-context-default-memory-low", "%" PRIu64, c->default_memory_low);
                if (r < 0)
                        return r;
        }

        if (c->memory_min > 0) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-min", "%" PRIu64, c->memory_min);
                if (r < 0)
                        return r;
        }

        if (c->memory_low > 0) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-low", "%" PRIu64, c->memory_low);
                if (r < 0)
                        return r;
        }

        if (c->startup_memory_low > 0) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-memory-low", "%" PRIu64, c->startup_memory_low);
                if (r < 0)
                        return r;
        }

        if (c->memory_high != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-high", "%" PRIu64, c->memory_high);
                if (r < 0)
                        return r;
        }

        if (c->startup_memory_high != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-memory-high", "%" PRIu64, c->startup_memory_high);
                if (r < 0)
                        return r;
        }

        if (c->memory_max != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-max", "%" PRIu64, c->memory_max);
                if (r < 0)
                        return r;
        }

        if (c->startup_memory_max != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-memory-max", "%" PRIu64, c->startup_memory_max);
                if (r < 0)
                        return r;
        }

        if (c->memory_swap_max != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-swap-max", "%" PRIu64, c->memory_swap_max);
                if (r < 0)
                        return r;
        }

        if (c->startup_memory_swap_max != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-memory-swap-max", "%" PRIu64, c->startup_memory_swap_max);
                if (r < 0)
                        return r;
        }

        if (c->memory_zswap_max != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-zswap-max", "%" PRIu64, c->memory_zswap_max);
                if (r < 0)
                        return r;
        }

        if (c->startup_memory_zswap_max != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-startup-memory-zswap-max", "%" PRIu64, c->startup_memory_zswap_max);
                if (r < 0)
                        return r;
        }

        if (c->memory_limit != CGROUP_LIMIT_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-memory-limit", "%" PRIu64, c->memory_limit);
                if (r < 0)
                        return r;
        }

        if (c->tasks_max.value != UINT64_MAX) {
                r = serialize_item_format(f, "exec-cgroup-context-tasks-max-value", "%" PRIu64, c->tasks_max.value);
                if (r < 0)
                        return r;
        }

        if (c->tasks_max.scale > 0) {
                r = serialize_item_format(f, "exec-cgroup-context-tasks-max-scale", "%" PRIu64, c->tasks_max.scale);
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-cgroup-context-default-memory-min-set", c->default_memory_min_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-default-memory-low-set", c->default_memory_low_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-default-startup-memory-low-set", c->default_startup_memory_low_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-memory-min-set", c->memory_min_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-memory-low-set", c->memory_low_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-startup-memory-low-set", c->startup_memory_low_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-startup-memory-high-set", c->startup_memory_high_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-startup-memory-max-set", c->startup_memory_max_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-startup-memory-swap-max-set", c->startup_memory_swap_max_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-startup-memory-zswap-max-set", c->startup_memory_zswap_max_set);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-device-policy", cgroup_device_policy_to_string(c->device_policy));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-disable-controllers", disable_controllers_str);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-delegate-controllers", delegate_controllers_str);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-delegate", c->delegate);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-managed-oom-swap", managed_oom_mode_to_string(c->moom_swap));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-managed-oom-memory-pressure", managed_oom_mode_to_string(c->moom_mem_pressure));
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-cgroup-context-managed-oom-memory-pressure-limit", "%" PRIu32, c->moom_mem_pressure_limit);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-managed-oom-preference", managed_oom_preference_to_string(c->moom_preference));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-memory-pressure-watch", cgroup_pressure_watch_to_string(c->memory_pressure_watch));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-cgroup-context-delegate-subgroup", c->delegate_subgroup);
        if (r < 0)
                return r;

        if (c->memory_pressure_threshold_usec != USEC_INFINITY) {
                r = serialize_usec(f, "exec-cgroup-context-memory-pressure-threshold-usec", c->memory_pressure_threshold_usec);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(device_allow, a, c->device_allow) {
                r = serialize_item_format(f, "exec-cgroup-context-device-allow", "%s %s%s%s",
                                          a->path,
                                          a->r ? "r" : "", a->w ? "w" : "", a->m ? "m" : "");
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(device_weights, iw, c->io_device_weights) {
                r = serialize_item_format(f, "exec-cgroup-context-io-device-weight", "%s %" PRIu64,
                                          iw->path,
                                          iw->weight);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(device_latencies, l, c->io_device_latencies) {
                r = serialize_item_format(f, "exec-cgroup-context-io-device-latency-target-usec", "%s " USEC_FMT,
                                          l->path,
                                          l->target_usec);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(device_limits, il, c->io_device_limits)
                for (CGroupIOLimitType type = 0; type < _CGROUP_IO_LIMIT_TYPE_MAX; type++)
                        if (il->limits[type] != cgroup_io_limit_defaults[type]) {
                                _cleanup_free_ char *key = NULL;

                                key = strjoin("exec-cgroup-context-io-device-limit-",
                                              cgroup_io_limit_type_to_string(type));
                                if (!key)
                                        return -ENOMEM;

                                r = serialize_item_format(f, key, "%s %" PRIu64, il->path, il->limits[type]);
                                if (r < 0)
                                        return r;
                        }

        LIST_FOREACH(device_weights, w, c->blockio_device_weights) {
                r = serialize_item_format(f, "exec-cgroup-context-blockio-device-weight", "%s %" PRIu64,
                                          w->path,
                                          w->weight);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {
                if (b->rbps != CGROUP_LIMIT_MAX) {
                        r = serialize_item_format(f, "exec-cgroup-context-blockio-read-bandwidth", "%s %" PRIu64,
                                                  b->path,
                                                  b->rbps);
                        if (r < 0)
                                return r;
                }
                if (b->wbps != CGROUP_LIMIT_MAX) {
                        r = serialize_item_format(f, "exec-cgroup-context-blockio-write-bandwidth", "%s %" PRIu64,
                                                  b->path,
                                                  b->wbps);
                        if (r < 0)
                                return r;
                }
        }

        SET_FOREACH(iaai, c->ip_address_allow) {
                r = serialize_item(f,
                                   "exec-cgroup-context-ip-address-allow",
                                   IN_ADDR_PREFIX_TO_STRING(iaai->family, &iaai->address, iaai->prefixlen));
                if (r < 0)
                        return r;
        }
        SET_FOREACH(iaai, c->ip_address_deny) {
                r = serialize_item(f,
                                   "exec-cgroup-context-ip-address-deny",
                                   IN_ADDR_PREFIX_TO_STRING(iaai->family, &iaai->address, iaai->prefixlen));
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-cgroup-context-ip-address-allow-reduced", c->ip_address_allow_reduced);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-cgroup-context-ip-address-deny-reduced", c->ip_address_deny_reduced);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-cgroup-context-ip-ingress-filter-path=", c->ip_filters_ingress);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-cgroup-context-ip-egress-filter-path=", c->ip_filters_egress);
        if (r < 0)
                return r;

        LIST_FOREACH(programs, p, c->bpf_foreign_programs) {
                r = serialize_item_format(f, "exec-cgroup-context-bpf-program", "%" PRIu32 " %s",
                                          p->attach_type,
                                          p->bpffs_path);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(socket_bind_items, bi, c->socket_bind_allow) {
                fprintf(f, "exec-cgroup-context-socket-bind-allow=");
                cgroup_context_dump_socket_bind_item(bi, f);
                fputc('\n', f);
        }

        LIST_FOREACH(socket_bind_items, bi, c->socket_bind_deny) {
                fprintf(f, "exec-cgroup-context-socket-bind-deny=");
                cgroup_context_dump_socket_bind_item(bi, f);
                fputc('\n', f);
        }

        if (c->restrict_network_interfaces) {
                char *iface;
                SET_FOREACH(iface, c->restrict_network_interfaces) {
                        r = serialize_item(f, "exec-cgroup-context-restrict-network-interfaces", iface);
                        if (r < 0)
                                return r;
                }
        }

        r = serialize_bool_elide(
                        f,
                        "exec-cgroup-context-restrict-network-interfaces-is-allow-list",
                        c->restrict_network_interfaces_is_allow_list);
        if (r < 0)
                return r;

        fputc('\n', f); /* End marker */

        return 0;
}

static int exec_cgroup_context_deserialize(CGroupContext *c, FILE *f) {
        int r;

        assert(c);
        assert(f);

        cgroup_context_init(c);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *val, *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read serialization line: %m");
                if (r == 0)
                        break;

                l = strstrip(line);
                if (isempty(l)) /* end marker */
                        break;

                if ((val = startswith(l, "exec-cgroup-context-cpu-accounting="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->cpu_accounting = r;
                } else if ((val = startswith(l, "exec-cgroup-context-io-accounting="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->io_accounting = r;
                } else if ((val = startswith(l, "exec-cgroup-context-block-io-accounting="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->blockio_accounting = r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-accounting="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->memory_accounting = r;
                } else if ((val = startswith(l, "exec-cgroup-context-tasks-accounting="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->tasks_accounting = r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-accounting="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->ip_accounting = r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-oom-group="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->memory_oom_group = r;
                } else if ((val = startswith(l, "exec-cgroup-context-cpu-weight="))) {
                        r = safe_atou64(val, &c->cpu_weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-cpu-weight="))) {
                        r = safe_atou64(val, &c->startup_cpu_weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-cpu-shares="))) {
                        r = safe_atou64(val, &c->cpu_shares);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-cpu-shares="))) {
                        r = safe_atou64(val, &c->startup_cpu_shares);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-cpu-quota-per-sec-usec="))) {
                        r = deserialize_usec(val, &c->cpu_quota_per_sec_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-cpu-quota-period-usec="))) {
                        r = deserialize_usec(val, &c->cpu_quota_period_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-allowed-cpus="))) {
                        r = parse_cpu_set_full(
                                        val,
                                        &c->cpuset_cpus,
                                        /* warn= */ false,
                                        /* unit= */ NULL,
                                        /* filename= */ NULL,
                                        /* line= */ 0,
                                        /* lvalue= */ NULL);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-allowed-cpus="))) {
                        r = parse_cpu_set_full(
                                        val,
                                        &c->startup_cpuset_cpus,
                                        /* warn= */ false,
                                        /* unit= */ NULL,
                                        /* filename= */ NULL,
                                        /* line= */ 0,
                                        /* lvalue= */ NULL);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-allowed-memory-nodes="))) {
                        r = parse_cpu_set_full(
                                        val,
                                        &c->cpuset_mems,
                                        /* warn= */ false,
                                        /* unit= */ NULL,
                                        /* filename= */ NULL,
                                        /* line= */ 0,
                                        /* lvalue= */ NULL);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-allowed-memory-nodes="))) {
                        r = parse_cpu_set_full(
                                        val,
                                        &c->startup_cpuset_mems,
                                        /* warn= */ false,
                                        /* unit= */ NULL,
                                        /* filename= */ NULL,
                                        /* line= */ 0,
                                        /* lvalue= */ NULL);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-io-weight="))) {
                        r = safe_atou64(val, &c->io_weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-io-weight="))) {
                        r = safe_atou64(val, &c->startup_io_weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-block-io-weight="))) {
                        r = safe_atou64(val, &c->blockio_weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-block-io-weight="))) {
                        r = safe_atou64(val, &c->startup_blockio_weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-default-memory-min="))) {
                        r = safe_atou64(val, &c->default_memory_min);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-default-memory-low="))) {
                        r = safe_atou64(val, &c->default_memory_low);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-min="))) {
                        r = safe_atou64(val, &c->memory_min);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-low="))) {
                        r = safe_atou64(val, &c->memory_low);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-low="))) {
                        r = safe_atou64(val, &c->startup_memory_low);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-high="))) {
                        r = safe_atou64(val, &c->memory_high);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-high="))) {
                        r = safe_atou64(val, &c->startup_memory_high);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-max="))) {
                        r = safe_atou64(val, &c->memory_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-max="))) {
                        r = safe_atou64(val, &c->startup_memory_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-swap-max="))) {
                        r = safe_atou64(val, &c->memory_swap_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-swap-max="))) {
                        r = safe_atou64(val, &c->startup_memory_swap_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-zswap-max="))) {
                        r = safe_atou64(val, &c->memory_zswap_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-zswap-max="))) {
                        r = safe_atou64(val, &c->startup_memory_zswap_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-limit="))) {
                        r = safe_atou64(val, &c->memory_limit);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-tasks-max-value="))) {
                        r = safe_atou64(val, &c->tasks_max.value);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-tasks-max-scale="))) {
                        r = safe_atou64(val, &c->tasks_max.scale);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-default-memory-min-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->default_memory_min_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-default-memory-low-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->default_memory_low_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-default-startup-memory-low-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->default_startup_memory_low_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-min-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->memory_min_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-low-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->memory_low_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-low-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->startup_memory_low_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-high-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->startup_memory_high_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-max-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->startup_memory_max_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-swap-max-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->startup_memory_swap_max_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-startup-memory-zswap-max-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->startup_memory_zswap_max_set = r;
                } else if ((val = startswith(l, "exec-cgroup-context-device-policy="))) {
                        c->device_policy = cgroup_device_policy_from_string(val);
                        if (c->device_policy < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-cgroup-context-disable-controllers="))) {
                        r = cg_mask_from_string(val, &c->disable_controllers);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-delegate-controllers="))) {
                        r = cg_mask_from_string(val, &c->delegate_controllers);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-delegate="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->delegate = r;
                } else if ((val = startswith(l, "exec-cgroup-context-managed-oom-swap="))) {
                        c->moom_swap = managed_oom_mode_from_string(val);
                        if (c->moom_swap < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-cgroup-context-managed-oom-memory-pressure="))) {
                        c->moom_mem_pressure = managed_oom_mode_from_string(val);
                        if (c->moom_mem_pressure < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-cgroup-context-managed-oom-memory-pressure-limit="))) {
                        r = safe_atou32(val, &c->moom_mem_pressure_limit);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-managed-oom-memory-pressure="))) {
                        c->moom_preference = managed_oom_preference_from_string(val);
                        if (c->moom_preference < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-pressure-watch="))) {
                        c->memory_pressure_watch = cgroup_pressure_watch_from_string(val);
                        if (c->memory_pressure_watch < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-cgroup-context-delegate-subgroup="))) {
                        r = free_and_strdup(&c->delegate_subgroup, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-memory-pressure-threshold-usec="))) {
                        r = deserialize_usec(val, &c->memory_pressure_threshold_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-device-allow="))) {
                        _cleanup_free_ char *path = NULL, *rwm = NULL;
                        CGroupDeviceAllow *a = NULL;

                        r = extract_many_words(&val, " ", 0, &path, &rwm, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;
                        if (!isempty(rwm) && !in_charset(rwm, "rwm"))
                                return -EINVAL;


                        LIST_FOREACH(device_allow, b, c->device_allow)
                                if (path_equal(b->path, path)) {
                                        a = b;
                                        break;
                                }

                        if (!a) {
                                a = new0(CGroupDeviceAllow, 1);
                                if (!a)
                                        return -ENOMEM;

                                a->path = TAKE_PTR(path);

                                LIST_PREPEND(device_allow, c->device_allow, a);
                        }

                        if (isempty(rwm))
                                a->r = a->w = a->m = true;
                        else {
                                a->r = strchr(rwm, 'r');
                                a->w = strchr(rwm, 'w');
                                a->m = strchr(rwm, 'm');
                        }
                } else if ((val = startswith(l, "exec-cgroup-context-io-device-weight="))) {
                        _cleanup_free_ char *path = NULL, *weight = NULL;
                        CGroupIODeviceWeight *a = NULL;

                        r = extract_many_words(&val, " ", 0, &path, &weight, NULL);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                continue;

                        LIST_FOREACH(device_weights, b, c->io_device_weights)
                                if (path_equal(b->path, path)) {
                                        a = b;
                                        break;
                                }

                        if (!a) {
                                a = new0(CGroupIODeviceWeight, 1);
                                if (!a)
                                        return -ENOMEM;

                                a->path = TAKE_PTR(path);

                                LIST_PREPEND(device_weights, c->io_device_weights, a);
                        }

                        r = safe_atou64(weight, &a->weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-io-device-latency-target-usec="))) {
                        _cleanup_free_ char *path = NULL, *target = NULL;
                        CGroupIODeviceLatency *a = NULL;

                        r = extract_many_words(&val, " ", 0, &path, &target, NULL);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                continue;

                        LIST_FOREACH(device_latencies, b, c->io_device_latencies)
                                if (path_equal(b->path, path)) {
                                        a = b;
                                        break;
                                }

                        if (!a) {
                                a = new0(CGroupIODeviceLatency, 1);
                                if (!a)
                                        return -ENOMEM;

                                a->path = TAKE_PTR(path);

                                LIST_PREPEND(device_latencies, c->io_device_latencies, a);
                        }

                        r = deserialize_usec(target, &a->target_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-io-device-limit-"))) {
                        _cleanup_free_ char *type = NULL, *path = NULL, *limits = NULL;
                        CGroupIODeviceLimit *limit = NULL;
                        CGroupIOLimitType t;

                        r = extract_many_words(&val, "= ", 0, &type, &path, &limits, NULL);
                        if (r < 0)
                                return r;
                        if (r != 3)
                                continue;

                        t = cgroup_io_limit_type_from_string(type);
                        if (t < 0)
                                return -EINVAL;

                        LIST_FOREACH(device_limits, i, c->io_device_limits)
                                if (path_equal(path, i->path)) {
                                        limit = i;
                                        break;
                                }

                        if (!limit) {
                                limit = new0(CGroupIODeviceLimit, 1);
                                if (!limit)
                                        return log_oom();

                                limit->path = TAKE_PTR(path);
                                for (CGroupIOLimitType i = 0; i < _CGROUP_IO_LIMIT_TYPE_MAX; i++)
                                        limit->limits[i] = cgroup_io_limit_defaults[i];

                                LIST_PREPEND(device_limits, c->io_device_limits, limit);
                        }

                        r = safe_atou64(limits, &limit->limits[t]);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-block-io-device-weight="))) {
                        _cleanup_free_ char *path = NULL, *weight = NULL;
                        CGroupBlockIODeviceWeight *a = NULL;

                        r = extract_many_words(&val, " ", 0, &path, &weight, NULL);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                continue;

                        a = new0(CGroupBlockIODeviceWeight, 1);
                        if (!a)
                                return -ENOMEM;

                        a->path = TAKE_PTR(path);

                        LIST_PREPEND(device_weights, c->blockio_device_weights, a);

                        r = safe_atou64(weight, &a->weight);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-block-io-read-bandwidth="))) {
                        _cleanup_free_ char *path = NULL, *bw = NULL;
                        CGroupBlockIODeviceBandwidth *a = NULL;

                        r = extract_many_words(&val, " ", 0, &path, &bw, NULL);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                continue;

                        LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths)
                                if (path_equal(b->path, path)) {
                                        a = b;
                                        break;
                                }

                        if (!a) {
                                a = new0(CGroupBlockIODeviceBandwidth, 1);
                                if (!a)
                                        return -ENOMEM;

                                a->path = TAKE_PTR(path);
                                a->wbps = CGROUP_LIMIT_MAX;

                                LIST_PREPEND(device_bandwidths, c->blockio_device_bandwidths, a);
                        }

                        r = safe_atou64(bw, &a->rbps);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-block-io-write-bandwidth="))) {
                        _cleanup_free_ char *path = NULL, *bw = NULL;
                        CGroupBlockIODeviceBandwidth *a = NULL;

                        r = extract_many_words(&val, " ", 0, &path, &bw, NULL);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                continue;

                        LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths)
                                if (path_equal(b->path, path)) {
                                        a = b;
                                        break;
                                }

                        if (!a) {
                                a = new0(CGroupBlockIODeviceBandwidth, 1);
                                if (!a)
                                        return -ENOMEM;

                                a->path = TAKE_PTR(path);
                                a->rbps = CGROUP_LIMIT_MAX;

                                LIST_PREPEND(device_bandwidths, c->blockio_device_bandwidths, a);
                        }

                        r = safe_atou64(bw, &a->wbps);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-address-allow="))) {
                        struct in_addr_prefix a;

                        r = in_addr_prefix_from_string_auto(val, &a.family, &a.address, &a.prefixlen);
                        if (r < 0)
                                return r;

                        r = in_addr_prefix_add(&c->ip_address_allow, &a);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-address-deny="))) {
                        struct in_addr_prefix a;

                        r = in_addr_prefix_from_string_auto(val, &a.family, &a.address, &a.prefixlen);
                        if (r < 0)
                                return r;

                        r = in_addr_prefix_add(&c->ip_address_deny, &a);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-address-allow-reduced="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->ip_address_allow_reduced = r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-address-deny-reduced="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->ip_address_deny_reduced = r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-ingress-filter-path="))) {
                        r = deserialize_strv(&c->ip_filters_ingress, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-ip-egress-filter-path="))) {
                        r = deserialize_strv(&c->ip_filters_egress, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-bpf-program="))) {
                        _cleanup_free_ char *type = NULL, *path = NULL;
                        uint32_t t;

                        r = extract_many_words(&val, " ", 0, &type, &path, NULL);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                continue;

                        r = safe_atou32(type, &t);
                        if (r < 0)
                                return r;

                        r = cgroup_add_bpf_foreign_program(c, t, path);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-socket-bind-allow="))) {
                        CGroupSocketBindItem *item;
                        uint16_t nr_ports, port_min;
                        int af, ip_protocol;

                        r = parse_socket_bind_item(val, &af, &ip_protocol, &nr_ports, &port_min);
                        if (r < 0)
                                return r;

                        item = new(CGroupSocketBindItem, 1);
                        if (!item)
                                return log_oom();
                        *item = (CGroupSocketBindItem) {
                                .address_family = af,
                                .ip_protocol = ip_protocol,
                                .nr_ports = nr_ports,
                                .port_min = port_min,
                        };

                        LIST_PREPEND(socket_bind_items, c->socket_bind_allow, item);
                } else if ((val = startswith(l, "exec-cgroup-context-socket-bind-deny="))) {
                        CGroupSocketBindItem *item;
                        uint16_t nr_ports, port_min;
                        int af, ip_protocol;

                        r = parse_socket_bind_item(val, &af, &ip_protocol, &nr_ports, &port_min);
                        if (r < 0)
                                return r;

                        item = new(CGroupSocketBindItem, 1);
                        if (!item)
                                return log_oom();
                        *item = (CGroupSocketBindItem) {
                                .address_family = af,
                                .ip_protocol = ip_protocol,
                                .nr_ports = nr_ports,
                                .port_min = port_min,
                        };

                        LIST_PREPEND(socket_bind_items, c->socket_bind_deny, item);
                } else if ((val = startswith(l, "exec-cgroup-context-restrict-network-interfaces="))) {
                        r = set_ensure_allocated(&c->restrict_network_interfaces, &string_hash_ops);
                        if (r < 0)
                                return r;

                        r = set_put_strdup(&c->restrict_network_interfaces, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-cgroup-context-restrict-network-interfaces-is-allow-list="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->restrict_network_interfaces_is_allow_list = r;
                }
        }

        return 0;
}

static int exec_runtime_serialize(const ExecRuntime *rt,
                FILE *f,
                FDSet *fds,
                int **fds_array,
                size_t *n_fds_array) {

        int r;

        assert(f);
        assert(fds_array);
        assert(n_fds_array);
        assert(fds || *fds_array);
        assert(!(fds && *fds_array));
        assert(!!*fds_array == !!*n_fds_array);

        if (!rt) {
                fputc('\n', f); /* End marker */
                return 0;

        }

        if (rt->shared) {
                r = serialize_item(f, "exec-runtime-id", rt->shared->id);
                if (r < 0)
                        return r;

                r = serialize_item(f, "exec-runtime-tmp-dir", rt->shared->tmp_dir);
                if (r < 0)
                        return r;

                r = serialize_item(f, "exec-runtime-var-tmp-dir", rt->shared->var_tmp_dir);
                if (r < 0)
                        return r;

                if (rt->shared->netns_storage_socket[0] >= 0 && rt->shared->netns_storage_socket[1] >= 0) {
                        int a, b;

                        a = serialize_prepare_fd_array_or_set(rt->shared->netns_storage_socket[0], fds, fds_array, n_fds_array);
                        if (a < 0)
                                return a;

                        b = serialize_prepare_fd_array_or_set(rt->shared->netns_storage_socket[1], fds, fds_array, n_fds_array);
                        if (b < 0)
                                return b;

                        r = serialize_item_format(f, "exec-runtime-netns-storage-socket", "%d %d", a, b);
                        if (r < 0)
                                return r;
                }

                if (rt->shared->ipcns_storage_socket[0] >= 0 && rt->shared->ipcns_storage_socket[1] >= 0) {
                        int a, b;

                        a = serialize_prepare_fd_array_or_set(rt->shared->ipcns_storage_socket[0], fds, fds_array, n_fds_array);
                        if (a < 0)
                                return a;

                        b = serialize_prepare_fd_array_or_set(rt->shared->ipcns_storage_socket[1], fds, fds_array, n_fds_array);
                        if (b < 0)
                                return b; //TODO: should only send one end

                        r = serialize_item_format(f, "exec-runtime-ipcns-storage-socket", "%d %d", a, b);
                        if (r < 0)
                                return r;
                }
        }

        if (rt->dynamic_creds &&
                        rt->dynamic_creds->user &&
                        rt->dynamic_creds->user->storage_socket[0] >= 0 &&
                        rt->dynamic_creds->user->storage_socket[1] >= 0) {
                r = dynamic_user_serialize_one(rt->dynamic_creds->user, "exec-runtime-dynamic-creds-user", f, fds, fds_array, n_fds_array);
                if (r < 0)
                        return r;
        }

        if (rt->dynamic_creds && rt->dynamic_creds->group && rt->dynamic_creds->group == rt->dynamic_creds->user) {
                r = serialize_bool_elide(f, "exec-runtime-dynamic-creds-group-copy", true);
                if (r < 0)
                        return r;
        } else if (rt->dynamic_creds &&
                        rt->dynamic_creds->group &&
                        rt->dynamic_creds->group->storage_socket[0] >= 0 &&
                        rt->dynamic_creds->group->storage_socket[1] >= 0) {
                r = dynamic_user_serialize_one(rt->dynamic_creds->group, "exec-runtime-dynamic-creds-group", f, fds, fds_array, n_fds_array);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-runtime-ephemeral-copy", rt->ephemeral_copy);
        if (r < 0)
                return r;

        if (rt->ephemeral_storage_socket[0] >= 0 && rt->ephemeral_storage_socket[1] >= 0) {
                int a, b;

                a = serialize_prepare_fd_array_or_set(rt->ephemeral_storage_socket[0], fds, fds_array, n_fds_array);
                if (a < 0)
                        return a;

                b = serialize_prepare_fd_array_or_set(rt->ephemeral_storage_socket[1], fds, fds_array, n_fds_array);
                if (b < 0)
                        return b;

                r = serialize_item_format(f, "exec-runtime-ephemeral-storage-socket", "%d %d", a, b);
                if (r < 0)
                        return r;
        }

        fputc('\n', f); /* End marker */

        return 0;
}

static int exec_runtime_deserialize(ExecRuntime *rt,
                FILE *f,
                FDSet *fds,
                int *fds_array,
                size_t n_fds_array) {

        int r;

        assert(rt);
        assert(rt->shared);
        assert(rt->dynamic_creds);
        assert(f);
        assert(!(fds && fds_array));
        assert(!!fds_array == !!n_fds_array);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *val, *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read serialization line: %m");
                if (r == 0)
                        break;

                l = strstrip(line);
                if (isempty(l)) /* end marker */
                        break;

                if ((val = startswith(l, "exec-runtime-id="))) {
                        r = free_and_strdup(&rt->shared->id, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-runtime-tmp-dir="))) {
                        r = free_and_strdup(&rt->shared->tmp_dir, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-runtime-var-tmp-dir="))) {
                        r = free_and_strdup(&rt->shared->var_tmp_dir, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-runtime-netns-storage-socket="))) {
                        for (size_t i = 0; i < 2; ++i) {
                                _cleanup_free_ char *w = NULL;
                                int fd;

                                r = extract_first_word(&val, &w, WHITESPACE, 0);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                fd = deserialize_fd_array_or_set(w, fds, fds_array, n_fds_array);
                                if (fd < 0) {
                                        log_debug_errno(fd, "Failed to deserialize %s value: %s, ignoring.", l, w);
                                        continue;
                                }

                                rt->shared->netns_storage_socket[i] = fd;
                        }
                } else if ((val = startswith(l, "exec-runtime-ipcns-storage-socket="))) {
                        for (size_t i = 0; i < 2; ++i) {
                                _cleanup_free_ char *w = NULL;
                                int fd;

                                r = extract_first_word(&val, &w, WHITESPACE, 0);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                fd = deserialize_fd_array_or_set(w, fds, fds_array, n_fds_array);
                                if (fd < 0) {
                                        log_debug_errno(fd, "Failed to deserialize %s value: %s, ignoring.", l, w);
                                        continue;
                                }

                                rt->shared->ipcns_storage_socket[i] = fd;
                        }
                } else if ((val = startswith(l, "exec-runtime-dynamic-creds-user=")))
                        dynamic_user_deserialize_one(/* m= */ NULL,
                                        val,
                                        fds,
                                        fds_array,
                                        n_fds_array,
                                        &rt->dynamic_creds->user);
                else if ((val = startswith(l, "exec-runtime-dynamic-creds-group=")))
                        dynamic_user_deserialize_one(/* m= */ NULL,
                                        val,
                                        fds,
                                        fds_array,
                                        n_fds_array,
                                        &rt->dynamic_creds->group);
                else if ((val = startswith(l, "exec-runtime-dynamic-creds-groupcopy=yes"))) {
                        assert(rt->dynamic_creds->user);
                        rt->dynamic_creds->group = dynamic_user_ref(rt->dynamic_creds->user);
                } else if ((val = startswith(l, "exec-runtime-ephemeral-copy="))) {
                        r = free_and_strdup(&rt->ephemeral_copy, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-runtime-ephemeral-storage-socket="))) {
                        for (size_t i = 0; i < 2; ++i) {
                                _cleanup_free_ char *w = NULL;
                                int fd;

                                r = extract_first_word(&val, &w, WHITESPACE, 0);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                fd = deserialize_fd_array_or_set(w, fds, fds_array, n_fds_array);
                                if (fd < 0) {
                                        log_debug_errno(fd, "Failed to deserialize %s value: %s, ignoring.", l, w);
                                        continue;
                                }

                                rt->ephemeral_storage_socket[i] = fd;
                        }
                }
        }

        return 0;
}

static int exec_parameters_serialize(const ExecParameters *p,
                FILE *f,
                FDSet *fds,
                int **fds_array,
                size_t *n_fds_array) {

        int r;

        assert(f);
        assert(fds_array);
        assert(n_fds_array);
        assert(fds || *fds_array);
        assert(!(fds && *fds_array));
        assert(!!*fds_array == !!*n_fds_array);

        if (!p)
                return 0;

        r = serialize_strv(f, "exec-parameters-environment", p->environment);
        if (r < 0)
                return r;

        if (p->n_socket_fds) {
                r = serialize_item_format(f, "exec-parameters-n-socket-fds", "%zu", p->n_socket_fds);
                if (r < 0)
                        return r;
        }

        if (p->n_storage_fds) {
                r = serialize_item_format(f, "exec-parameters-n-storage-fds", "%zu", p->n_storage_fds);
                if (r < 0)
                        return r;
        }

        if (p->n_socket_fds + p->n_storage_fds > 0) {
                _cleanup_free_ char *serialized_fds = NULL;

                for (size_t i = 0; i < p->n_socket_fds + p->n_storage_fds; ++i) {
                        int copy = -EBADF;

                        if (p->fds[i] >= 0) {
                                copy = serialize_prepare_fd_array_or_set(p->fds[i], fds, fds_array, n_fds_array);
                                if (copy < 0)
                                        return copy;
                        }

                        if (strextendf(&serialized_fds, "%d ", copy) < 0)
                                return -ENOMEM;
                }

                r = serialize_item(f, "exec-parameters-fds", serialized_fds);
                if (r < 0)
                        return r;
        }

        r = serialize_strv(f, "exec-parameters-fd-names", p->fd_names);
        if (r < 0)
                return r;

        if (p->flags > 0) {
                r = serialize_item_format(f, "exec-parameters-flags", "%u", p->flags);
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-parameters-selinux-context-net", p->selinux_context_net);
        if (r < 0)
                return r;

        if (p->cgroup_supported > 0) {
                r = serialize_item_format(f, "exec-parameters-cgroup-supported", "%u", p->cgroup_supported);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-parameters-cgroup-path", p->cgroup_path);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-parameters-prefix", p->prefix);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-parameters-received-credentials-directory", p->received_credentials_directory);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-parameters-received-encrypted-credentials-directory", p->received_encrypted_credentials_directory);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-parameters-confirm-spawn", p->confirm_spawn);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-parameters-shall-confirm-spawn", p->shall_confirm_spawn);
        if (r < 0)
                return r;

        if (p->watchdog_usec > 0) {
                r = serialize_usec(f, "exec-parameters-watchdog-usec", p->watchdog_usec);
                if (r < 0)
                        return r;
        }

        if (p->idle_pipe) {
                _cleanup_free_ char *serialized_fds = NULL;

                for (size_t i = 0; i < 4; ++i) {
                        int copy = -EBADF;

                        if (p->idle_pipe[i] >= 0) {
                                copy = serialize_prepare_fd_array_or_set(p->idle_pipe[i], fds, fds_array, n_fds_array);
                                if (copy < 0)
                                        return copy;
                        }

                        if (strextendf(&serialized_fds, "%d ", copy) < 0)
                                return -ENOMEM;
                }

                r = serialize_item(f, "exec-parameters-idle-pipe", serialized_fds);
                if (r < 0)
                        return r;
        }

        r = serialize_fd_array_or_set(f, fds, fds_array, n_fds_array, "exec-parameters-stdin-fd", p->stdin_fd);
        if (r < 0)
                return r;

        r = serialize_fd_array_or_set(f, fds, fds_array, n_fds_array, "exec-parameters-stdout-fd", p->stdout_fd);
        if (r < 0)
                return r;

        r = serialize_fd_array_or_set(f, fds, fds_array, n_fds_array, "exec-parameters-stderr-fd", p->stderr_fd);
        if (r < 0)
                return r;

        r = serialize_fd_array_or_set(f, fds, fds_array, n_fds_array, "exec-parameters-exec-fd", p->exec_fd);
        if (r < 0)
                return r;

        r = serialize_fd_array_or_set(f, fds, fds_array, n_fds_array, "exec-parameters-bpf-outer-map-fd", p->bpf_outer_map_fd);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-parameters-notify-socket", p->notify_socket);
        if (r < 0)
                return r;

        LIST_FOREACH(open_files, file, p->open_files) {
                _cleanup_free_ char *ofs = NULL;

                r = open_file_to_string(file, &ofs);
                if (r < 0)
                        return r;

                r = serialize_item(f, "exec-parameters-open-file", ofs);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-parameters-default-smack-process-label", p->default_smack_process_label);
        if (r < 0)
                return r;

        r = serialize_fd_array_or_set(f, fds, fds_array, n_fds_array, "exec-parameters-user-lookup-fd", p->user_lookup_fd);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-parameters-files-env", p->files_env);
        if (r < 0)
                return r;

        fputc('\n', f); /* End marker */

        return 0;
}

static int exec_parameters_deserialize(ExecParameters *p,
                FILE *f,
                FDSet *fds,
                int *fds_array,
                size_t n_fds_array) {

        int r;

        assert(p);
        assert(f);
        assert(!(fds && fds_array));
        assert(!!fds_array == !!n_fds_array);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *val, *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read serialization line: %m");
                if (r == 0)
                        break;

                l = strstrip(line);
                if (isempty(l)) /* end marker */
                        break;

                if ((val = startswith(l, "exec-parameters-environment="))) {
                        r = deserialize_strv(&p->environment, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-n-socket-fds="))) {
                        r = safe_atozu(val, &p->n_socket_fds);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-n-storage-fds="))) {
                        r = safe_atozu(val, &p->n_storage_fds);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-fds="))) {
                        if (p->n_socket_fds + p->n_storage_fds == 0) {
                                log_warning("Got exec-parameters-fds= without prior exec-parameters-n-socket-fds= or exec-parameters-n-storage-fds=, ignoring.");
                                continue;
                        }

                        p->fds = new(int, p->n_socket_fds + p->n_storage_fds);
                        if (!p->fds)
                                return log_oom();

                        for (size_t i = 0; i < p->n_socket_fds + p->n_storage_fds; ++i) {
                                _cleanup_free_ char *w = NULL;
                                int fd;

                                r = extract_first_word(&val, &w, WHITESPACE, 0);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                fd = deserialize_fd_array_or_set(w, fds, fds_array, n_fds_array);
                                if (fd < 0) {
                                        log_debug_errno(fd, "Failed to deserialize %s value: %s, ignoring.", l, w);
                                        continue;
                                }

                                p->fds[i] = fd;
                        }
                } else if ((val = startswith(l, "exec-parameters-fd-names="))) {
                        r = deserialize_strv(&p->fd_names, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-flags="))) {
                        r = safe_atou(val, &p->flags);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-selinux-context-net="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;

                        p->selinux_context_net = r;
                } else if ((val = startswith(l, "exec-parameters-cgroup-supported="))) {
                        r = safe_atou(val, &p->cgroup_supported);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-cgroup-path="))) {
                        r = free_and_strdup((char **)&p->cgroup_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-prefix="))) {
                        r = deserialize_strv(&p->prefix, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-received-credentials-directory="))) {
                        r = free_and_strdup((char **)&p->received_credentials_directory, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-received-encrypted-credentials-directory="))) {
                        r = free_and_strdup((char **)&p->received_encrypted_credentials_directory, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-confirm-spawn="))) {
                        r = free_and_strdup((char **)&p->confirm_spawn, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-shall-confirm-spawn="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;

                        p->shall_confirm_spawn = r;
                } else if ((val = startswith(l, "exec-parameters-watchdog-usec="))) {
                        r = deserialize_usec(val, &p->watchdog_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-idle-pipe="))) {
                        p->idle_pipe = new(int, 4);
                        if (!p->idle_pipe)
                                return log_oom();

                        p->idle_pipe[0] = p->idle_pipe[1] = p->idle_pipe[2] = p->idle_pipe[3] = -EBADF;

                        for (size_t i = 0; i < 4; ++i) {
                                _cleanup_free_ char *w = NULL;
                                int fd;

                                r = extract_first_word(&val, &w, WHITESPACE, 0);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                fd = deserialize_fd_array_or_set(w, fds, fds_array, n_fds_array);
                                if (fd < 0) {
                                        log_debug_errno(fd, "Failed to deserialize %s value: %s, ignoring.", l, w);
                                        continue;
                                }

                                p->idle_pipe[i] = fd;
                        }
                } else if ((val = startswith(l, "exec-parameters-stdin-fd="))) {
                        int fd;

                        fd = deserialize_fd_array_or_set(val, fds, fds_array, n_fds_array);
                        if (fd < 0) {
                                log_debug_errno(fd, "Failed to deserialize %s value: %s, ignoring.", l, val);
                                continue;
                        }

                        p->stdin_fd = fd;
                } else if ((val = startswith(l, "exec-parameters-stdout-fd="))) {
                        int fd;

                        fd = deserialize_fd_array_or_set(val, fds, fds_array, n_fds_array);
                        if (fd < 0) {
                                log_debug_errno(fd, "Failed to deserialize %s value: %s, ignoring.", l, val);
                                continue;
                        }

                        p->stdout_fd = fd;
                } else if ((val = startswith(l, "exec-parameters-stderr-fd="))) {
                        int fd;

                        fd = deserialize_fd_array_or_set(val, fds, fds_array, n_fds_array);
                        if (fd < 0) {
                                log_debug_errno(fd, "Failed to deserialize %s value: %s, ignoring.", l, val);
                                continue;
                        }

                        p->stderr_fd = fd;
                } else if ((val = startswith(l, "exec-parameters-exec-fd="))) {
                        int fd;

                        fd = deserialize_fd_array_or_set(val, fds, fds_array, n_fds_array);
                        if (fd < 0) {
                                log_debug_errno(fd, "Failed to deserialize %s value: %s, ignoring.", l, val);
                                continue;
                        }

                        /* This is special and relies on close-on-exec semantics, make sure it's
                                * there */
                        r = fd_cloexec(fd, true);
                        if (r < 0)
                                return r;

                        p->exec_fd = fd;
                } else if ((val = startswith(l, "exec-parameters-bpf-outer-map-fd="))) {
                        int fd;

                        fd = deserialize_fd_array_or_set(val, fds, fds_array, n_fds_array);
                        if (fd < 0) {
                                log_debug_errno(fd, "Failed to deserialize %s value: %s, ignoring.", l, val);
                                continue;
                        }

                        p->bpf_outer_map_fd = fd;
                } else if ((val = startswith(l, "exec-parameters-notify-socket="))) {
                        r = free_and_strdup((char **)&p->notify_socket, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-open-file="))) {
                        OpenFile *of = NULL;

                        r = open_file_parse(val, &of);
                        if (r < 0)
                                return r;

                        LIST_APPEND(open_files, p->open_files, of);
                } else if ((val = startswith(l, "exec-parameters-default-smack-process-label="))) {
                        r = free_and_strdup((char **)&p->default_smack_process_label, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-parameters-user-lookup-fd="))) {
                        int fd;

                        fd = deserialize_fd_array_or_set(val, fds, fds_array, n_fds_array);
                        if (fd < 0) {
                                log_debug_errno(fd, "Failed to deserialize %s value: %s, ignoring.", l, val);
                                continue;
                        }

                        p->user_lookup_fd = fd;
                } else if ((val = startswith(l, "exec-parameters-files-env="))) {
                        r = deserialize_strv(&p->files_env, val);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int exec_context_serialize(const ExecContext *c, FILE *f) {
        int r;

        assert(f);

        if (!c)
                return 0;

        r = serialize_item_format(f, "exec-context-runtime-scope", "%d", c->runtime_scope);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-environment", c->environment);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-manager-environment", environ);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-environment-files", c->environment_files);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-pass-environment", c->pass_environment);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-unset-environment", c->unset_environment);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-working-directory", c->working_directory);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-root-directory", c->root_directory);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-root-image", c->root_image);
        if (r < 0)
                return r;

        if (c->root_image_options) {
                _cleanup_free_ char *options = NULL;

                LIST_FOREACH(mount_options, o, c->root_image_options)
                        if (!isempty(o->options)) {
                                _cleanup_free_ char *escaped = NULL;

                                escaped = shell_escape(o->options, ":");
                                if (!escaped)
                                        return log_oom_debug();

                                if (!strextend(&options,
                                               " ",
                                               partition_designator_to_string(o->partition_designator),
                                               ":",
                                               escaped))
                                        return log_oom_debug();
                        }

                r = serialize_item(f, "exec-context-root-image-options", options);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-context-root-verity", c->root_verity);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-root-hash-path", c->root_hash_path);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-root-hash-sig-path", c->root_hash_sig_path);
        if (r < 0)
                return r;

        if (c->root_hash) {
                _cleanup_free_ char *encoded = NULL;

                encoded = hexmem(c->root_hash, c->root_hash_size);
                if (!encoded)
                        return log_oom_debug();

                r = serialize_item(f, "exec-context-root-hash", encoded);
                if (r < 0)
                        return r;
        }

        if (c->root_hash_sig) {
                _cleanup_free_ char *encoded = NULL;
                ssize_t len;

                len = base64mem(c->root_hash_sig, c->root_hash_sig_size, &encoded);
                if (len <= 0)
                        return log_oom_debug();

                r = serialize_item(f, "exec-context-root-hash-sig", encoded);
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-context-root-ephemeral", c->root_ephemeral);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-context-umask", "%04o", c->umask);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-non-blocking", c->non_blocking);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-context-private-mounts", "%d", c->private_mounts);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-context-memory-ksm", "%d", c->memory_ksm);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-private-tmp", c->private_tmp);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-private-devices", c->private_devices);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-protect-kernel-tunables", c->protect_kernel_tunables);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-protect-kernel-modules", c->protect_kernel_modules);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-protect-kernel-logs", c->protect_kernel_logs);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-protect-clock", c->protect_clock);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-protect-control-groups", c->protect_control_groups);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-private-network", c->private_network);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-private-users", c->private_users);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-private-ipc", c->private_ipc);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-remove-ipc", c->remove_ipc);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-protect-home", protect_home_to_string(c->protect_home));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-protect-system", protect_system_to_string(c->protect_system));
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-mount-api-vfs", exec_context_get_effective_mount_apivfs(c));
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-mount-api-vfs-set", c->mount_apivfs_set);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-same-pgrp", c->same_pgrp);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-cpu-sched-reset-on-fork", c->cpu_sched_reset_on_fork);
        if (r < 0)
                return r;

        r = serialize_bool(f, "exec-context-ignore-sigpipe", c->ignore_sigpipe);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-memory-deny-write-execute", c->memory_deny_write_execute);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-restrict-realtime", c->restrict_realtime);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-restrict-suid-sgid", c->restrict_suid_sgid);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-keyring-mode", exec_keyring_mode_to_string(c->keyring_mode));
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-protect-hostname", c->protect_hostname);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-protect-proc", protect_proc_to_string(c->protect_proc));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-proc-subset", proc_subset_to_string(c->proc_subset));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-runtime-directory-preserve-mode", exec_preserve_mode_to_string(c->runtime_directory_preserve_mode));
        if (r < 0)
                return r;

        for (ExecDirectoryType dt = 0; dt < _EXEC_DIRECTORY_TYPE_MAX; dt++) {
                _cleanup_free_ char *key = NULL, *value = NULL;

                key = strjoin("exec-context-directories-", exec_directory_type_to_string(dt));
                if (!key)
                        return log_oom_debug();

                r = asprintf(&value, "%04o", c->directories[dt].mode);
                if (r < 0)
                        return log_oom_debug();

                for (size_t i = 0; i < c->directories[dt].n_items; i++) {
                        _cleanup_free_ char *path_escaped = NULL;

                        path_escaped = shell_escape(c->directories[dt].items[i].path, ":");
                        if (!path_escaped)
                                return log_oom_debug();

                        if (!strextend(&value, " ", path_escaped))
                                return log_oom_debug();

                        if (!strextend(&value, ":", yes_no(c->directories[dt].items[i].only_create)))
                                return log_oom_debug();

                        STRV_FOREACH(d, c->directories[dt].items[i].symlinks) {
                                _cleanup_free_ char *link_escaped = NULL;

                                link_escaped = shell_escape(*d, ":");
                                if (!link_escaped)
                                        return log_oom_debug();

                                if (!strextend(&value, ":", link_escaped))
                                        return log_oom_debug();
                        }
                }

                r = serialize_item(f, key, value);
                if (r < 0)
                        return r;
        }

        r = serialize_usec(f, "exec-context-timeout-clean-usec", c->timeout_clean_usec);
        if (r < 0)
                return r;

        if (c->nice_set) {
                r = serialize_item_format(f, "exec-context-nice", "%i", c->nice);
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-context-working-directory-missing-ok", c->working_directory_missing_ok);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-working-directory-home", c->working_directory_home);
        if (r < 0)
                return r;

        if (c->oom_score_adjust_set) {
                r = serialize_item_format(f, "exec-context-oom-score-adjust", "%i", c->oom_score_adjust);
                if (r < 0)
                        return r;
        }

        if (c->coredump_filter_set) {
                r = serialize_item_format(f, "exec-context-coredump-filter", "%"PRIx64, c->coredump_filter);
                if (r < 0)
                        return r;
        }

        for (unsigned i = 0; i < RLIM_NLIMITS; i++)
                if (c->rlimit[i]) {
                        _cleanup_free_ char *key = NULL, *limit = NULL;

                        key = strjoin("exec-context-limit-", rlimit_to_string(i));
                        if (!key)
                                return log_oom_debug();

                        r = rlimit_format(c->rlimit[i], &limit);
                        if (r < 0)
                                return r;

                        r = serialize_item(f, key, limit);
                        if (r < 0)
                                return r;
                }

        if (c->ioprio_set) {
                r = serialize_item_format(f, "exec-context-ioprio", "%d", c->ioprio);
                if (r < 0)
                        return r;
        }

        if (c->cpu_sched_set) {
                _cleanup_free_ char *policy_str = NULL;

                r = sched_policy_to_string_alloc(c->cpu_sched_policy, &policy_str);
                if (r >= 0) {
                        r = serialize_item(f, "exec-context-cpu-scheduling-policy", policy_str);
                        if (r < 0)
                                return r;
                }

                r = serialize_item_format(f, "exec-context-cpu-scheduling-priority", "%i", c->cpu_sched_priority);
                if (r < 0)
                        return r;

                r = serialize_bool_elide(f, "exec-context-cpu-scheduling-reset-on-fork", c->cpu_sched_reset_on_fork);
                if (r < 0)
                        return r;
        }

        if (c->cpu_set.set) {
                _cleanup_free_ char *affinity = NULL;

                affinity = cpu_set_to_range_string(&c->cpu_set);
                if (!affinity)
                        return log_oom_debug();

                r = serialize_item(f, "exec-context-cpu-affinity", affinity);
                if (r < 0)
                        return r;
        }

        if (mpol_is_valid(numa_policy_get_type(&c->numa_policy))) {
                _cleanup_free_ char *nodes = NULL;

                nodes = cpu_set_to_range_string(&c->numa_policy.nodes);
                if (!nodes)
                        return log_oom_debug();

                if (nodes) {
                        r = serialize_item(f, "exec-context-numa-mask", nodes);
                        if (r < 0)
                                return r;
                }

                r = serialize_item_format(f, "exec-context-numa-policy", "%d", c->numa_policy.type);
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-context-cpu-affinity-from-numa", c->cpu_affinity_from_numa);
        if (r < 0)
                return r;

        if (c->timer_slack_nsec != NSEC_INFINITY) {
                r = serialize_item_format(f, "exec-context-timer-slack-nsec", NSEC_FMT, c->timer_slack_nsec);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-context-std-input", exec_input_to_string(c->std_input));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-std-output", exec_output_to_string(c->std_output));
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-std-error", exec_output_to_string(c->std_error));
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-stdio-as-fds", c->stdio_as_fds);
        if (r < 0)
                return r;

        if (c->std_input == EXEC_INPUT_NAMED_FD) {
                r = serialize_item(f, "exec-context-std-input-fd-name", c->stdio_fdname[STDIN_FILENO]);
                if (r < 0)
                        return r;
        }

        if (c->std_output == EXEC_OUTPUT_NAMED_FD) {
                r = serialize_item(f, "exec-context-std-output-fd-name", c->stdio_fdname[STDOUT_FILENO]);
                if (r < 0)
                        return r;
        }

        if (c->std_error == EXEC_OUTPUT_NAMED_FD) {
                r = serialize_item(f, "exec-context-std-error-fd-name", c->stdio_fdname[STDERR_FILENO]);
                if (r < 0)
                        return r;
        }

        if (c->std_input == EXEC_INPUT_FILE) {
                r = serialize_item(f, "exec-context-std-input-file", c->stdio_file[STDIN_FILENO]);
                if (r < 0)
                        return r;
        }

        if (c->std_output == EXEC_OUTPUT_FILE) {
                r = serialize_item(f, "exec-context-std-output-file", c->stdio_file[STDOUT_FILENO]);
                if (r < 0)
                        return r;
        }

        if (c->std_output == EXEC_OUTPUT_FILE_APPEND) {
                r = serialize_item(f, "exec-context-std-output-file-append", c->stdio_file[STDOUT_FILENO]);
                if (r < 0)
                        return r;
        }

        if (c->std_output == EXEC_OUTPUT_FILE_TRUNCATE) {
                r = serialize_item(f, "exec-context-std-output-file-truncate", c->stdio_file[STDOUT_FILENO]);
                if (r < 0)
                        return r;
        }

        if (c->std_error == EXEC_OUTPUT_FILE) {
                r = serialize_item(f, "exec-context-std-error-file", c->stdio_file[STDERR_FILENO]);
                if (r < 0)
                        return r;
        }

        if (c->std_error == EXEC_OUTPUT_FILE_APPEND) {
                r = serialize_item(f, "exec-context-std-error-file-append", c->stdio_file[STDERR_FILENO]);
                if (r < 0)
                        return r;
        }

        if (c->std_error == EXEC_OUTPUT_FILE_TRUNCATE) {
                r = serialize_item(f, "exec-context-std-error-file-truncate", c->stdio_file[STDERR_FILENO]);
                if (r < 0)
                        return r;
        }

        if (c->stdin_data_size > 0 && c->stdin_data) {
                _cleanup_free_ char *data = NULL;

                data = hexmem(c->stdin_data, c->stdin_data_size);
                if (!data)
                        return log_oom_debug();

                r = serialize_item(f, "exec-context-stdin-data", data);
                if (r < 0)
                        return r;
        }

        if (c->tty_path) {
                r = serialize_item(f, "exec-context-tty-path", c->tty_path);
                if (r < 0)
                        return r;

                r = serialize_bool_elide(f, "exec-context-tty-reset", c->tty_reset);
                if (r < 0)
                        return r;

                r = serialize_bool_elide(f, "exec-context-tty-vhangup", c->tty_vhangup);
                if (r < 0)
                        return r;

                r = serialize_bool_elide(f, "exec-context-tty-vt-disallocate", c->tty_vt_disallocate);
                if (r < 0)
                        return r;

                r = serialize_item_format(f, "exec-context-tty-rows", "%u", c->tty_rows);
                if (r < 0)
                        return r;

                r = serialize_item_format(f, "exec-context-tty-columns", "%u", c->tty_cols);
                if (r < 0)
                        return r;
        }

        r = serialize_item_format(f, "exec-context-syslog-priority", "%i", c->syslog_priority);
        if (r < 0)
                return r;

        r = serialize_bool(f, "exec-context-syslog-level-prefix", c->syslog_level_prefix);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-syslog-identifier", c->syslog_identifier);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-context-log-level-max", "%d", c->log_level_max);
        if (r < 0)
                return r;

        if (c->log_ratelimit_interval_usec > 0) {
                r = serialize_usec(f, "exec-context-log-ratelimit-interval-usec", c->log_ratelimit_interval_usec);
                if (r < 0)
                        return r;
        }

        if (c->log_ratelimit_burst > 0) {
                r = serialize_item_format(f, "exec-context-log-ratelimit-burst", "%u", c->log_ratelimit_burst);
                if (r < 0)
                        return r;
        }

        if (!set_isempty(c->log_filter_allowed_patterns)) {
                _cleanup_free_ char *allowed_pattern = NULL;

                r = set_strjoin(c->log_filter_allowed_patterns, " ", /* wrap_with_separator= */ false, &allowed_pattern);
                if (r < 0)
                        return r;

                r = serialize_item(f, "exec-context-log-filter-allowed-patterns", allowed_pattern);
                if (r < 0)
                        return r;
        }

        if (!set_isempty(c->log_filter_denied_patterns)) {
                _cleanup_free_ char *denied_pattern = NULL;

                r = set_strjoin(c->log_filter_denied_patterns, " ", /* wrap_with_separator= */ false, &denied_pattern);
                if (r < 0)
                        return r;

                r = serialize_item(f, "exec-context-log-filter-denied-patterns", denied_pattern);
                if (r < 0)
                        return r;
        }

        for (size_t j = 0; j < c->n_log_extra_fields; j++) {
                r = serialize_item(f, "exec-context-log-extra-fields", c->log_extra_fields[j].iov_base);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-context-log-namespace", c->log_namespace);
        if (r < 0)
                return r;

        if (c->secure_bits) {
                r = serialize_item_format(f, "exec-context-secure-bits", "%d", c->secure_bits);
                if (r < 0)
                        return r;
        }

        if (c->capability_bounding_set != CAP_MASK_UNSET) {
                r = serialize_item_format(f, "exec-context-capability-bounding-set", "%" PRIu64, c->capability_bounding_set);
                if (r < 0)
                        return r;
        }

        if (c->capability_ambient_set != 0) {
                r = serialize_item_format(f, "exec-context-capability-ambient-set", "%" PRIu64, c->capability_ambient_set);
                if (r < 0)
                        return r;
        }

        if (c->user) {
                r = serialize_item(f, "exec-context-user", c->user);
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-context-group", c->group);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-dynamic-user", c->dynamic_user);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-supplementary-groups", c->supplementary_groups);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-pam-name", c->pam_name);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-read-write-paths", c->read_write_paths);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-read-only-paths", c->read_only_paths);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-inaccessible-paths", c->inaccessible_paths);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-exec-paths", c->exec_paths);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-no-exec-paths", c->no_exec_paths);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-context-exec-search-path", c->exec_search_path);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-context-mount-propagation-flag", "%lu", c->mount_propagation_flag);
        if (r < 0)
                return r;

        for (size_t i = 0; i < c->n_bind_mounts; i++) {
                r = serialize_item_format(f,
                                          c->bind_mounts[i].read_only ? "exec-context-bind-read-only-path" : "exec-context-bind-path",
                                          "%s%s:%s:%s",
                                          c->bind_mounts[i].ignore_enoent ? "-" : "",
                                          c->bind_mounts[i].source,
                                          c->bind_mounts[i].destination,
                                          c->bind_mounts[i].recursive ? "rbind" : "norbind");
                if (r < 0)
                        return r;
        }

        for (size_t i = 0; i < c->n_temporary_filesystems; i++) {
                const TemporaryFileSystem *t = c->temporary_filesystems + i;
                _cleanup_free_ char *escaped = NULL;

                if (!isempty(t->options)) {
                        escaped = shell_escape(t->options, ":");
                        if (!escaped)
                                return log_oom_debug();
                }

                r = serialize_item_format(f, "exec-context-temporary-filesystems", "%s%s%s",
                                          t->path,
                                          isempty(escaped) ? "" : ":",
                                          strempty(escaped));
                if (r < 0)
                        return r;
        }

        r = serialize_item(f, "exec-context-utmp-id", c->utmp_id);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-context-utmp-mode", "%d", c->utmp_mode);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-no-new-privileges", c->no_new_privileges);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-selinux-context-ignore", c->selinux_context_ignore);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-apparmor-profile-ignore", c->apparmor_profile_ignore);
        if (r < 0)
                return r;

        r = serialize_bool_elide(f, "exec-context-smack-process-label-ignore", c->smack_process_label_ignore);
        if (r < 0)
                return r;

        if (c->selinux_context) {
                r = serialize_item_format(f, "exec-context-selinux-context",
                                          "%s%s",
                                          c->selinux_context_ignore ? "-" : "",
                                          c->selinux_context);
                if (r < 0)
                        return r;
        }

        if (c->apparmor_profile) {
                r = serialize_item_format(f, "exec-context-apparmor-profile",
                                          "%s%s",
                                          c->apparmor_profile_ignore ? "-" : "",
                                          c->apparmor_profile);
                if (r < 0)
                        return r;
        }

        if (c->smack_process_label) {
                r = serialize_item_format(f, "exec-context-smack-process-label",
                                          "%s%s",
                                          c->smack_process_label_ignore ? "-" : "",
                                          c->smack_process_label);
                if (r < 0)
                        return r;
        }

        if (c->personality != PERSONALITY_INVALID) {
                r = serialize_item(f, "exec-context-personality", personality_to_string(c->personality));
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-context-lock-personality", c->lock_personality);
        if (r < 0)
                return r;

#if HAVE_SECCOMP
        if (!hashmap_isempty(c->syscall_filter)) {
                void *errno_num, *id;
                HASHMAP_FOREACH_KEY(errno_num, id, c->syscall_filter) {
                        r = serialize_item_format(f, "exec-context-syscall-filter", "%d %d", PTR_TO_INT(id) - 1, PTR_TO_INT(errno_num));
                        if (r < 0)
                                return r;
                }
        }

        if (!set_isempty(c->syscall_archs)) {
                void *id;
                SET_FOREACH(id, c->syscall_archs) {
                        r = serialize_item_format(f, "exec-context-syscall-archs", "%u", PTR_TO_UINT(id) - 1);
                        if (r < 0)
                                return r;
                }
        }

        if (c->syscall_errno > 0) {
                r = serialize_item_format(f, "exec-context-syscall-errno", "%d", c->syscall_errno);
                if (r < 0)
                        return r;
        }

        r = serialize_bool_elide(f, "exec-context-syscall-allow-list", c->syscall_allow_list);
        if (r < 0)
                return r;

        if (!hashmap_isempty(c->syscall_log)) {
                void *errno_num, *id;
                HASHMAP_FOREACH_KEY(errno_num, id, c->syscall_log) {
                        r = serialize_item_format(f, "exec-context-syscall-log", "%d %d", PTR_TO_INT(id) - 1, PTR_TO_INT(errno_num));
                        if (r < 0)
                                return r;
                }
        }

        r = serialize_bool_elide(f, "exec-context-syscall-log-allow-list", c->syscall_log_allow_list);
        if (r < 0)
                return r;
#endif

        if (c->restrict_namespaces != NAMESPACE_FLAGS_INITIAL) {
                r = serialize_item_format(f, "exec-context-restrict-namespaces", "%lu", c->restrict_namespaces);
                if (r < 0)
                        return r;
        }

#if HAVE_LIBBPF
        if (exec_context_restrict_filesystems_set(c)) {
                char *fs;
                SET_FOREACH(fs, c->restrict_filesystems) {
                        r = serialize_item(f, "exec-context-restrict-filesystems", fs);
                        if (r < 0)
                                return r;
                }
        }

        r = serialize_bool_elide(f, "exec-context-restrict-filesystems-allow-list", c->restrict_filesystems_allow_list);
        if (r < 0)
                return r;
#endif

        if (!set_isempty(c->address_families)) {
                void *afp;

                SET_FOREACH(afp, c->address_families) {
                        int af = PTR_TO_INT(afp);

                        if (af <= 0 || af >= af_max())
                                continue;

                        r = serialize_item_format(f, "exec-context-address-families", "%d", af);
                        if (r < 0)
                                return r;
                }
        }

        r = serialize_bool_elide(f, "exec-context-address-families-allow-list", c->address_families_allow_list);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-network-namespace-path", c->network_namespace_path);
        if (r < 0)
                return r;

        r = serialize_item(f, "exec-context-ipc-namespace-path", c->ipc_namespace_path);
        if (r < 0)
                return r;

        for (size_t i = 0; i < c->n_mount_images; i++) {
                _cleanup_free_ char *s = NULL;

                s = strjoin(c->mount_images[i].ignore_enoent ? "-" : "",
                            c->mount_images[i].source,
                            " ",
                            c->mount_images[i].destination);
                if (!s)
                        return -ENOMEM;

                LIST_FOREACH(mount_options, o, c->mount_images[i].mount_options) {
                        _cleanup_free_ char *escaped = NULL;

                        if (isempty(o->options))
                                continue;

                        escaped = shell_escape(o->options, ":");
                        if (!escaped)
                                return log_oom_debug();

                        if (!strextend(&s,
                                       " ",
                                       partition_designator_to_string(o->partition_designator),
                                       ":",
                                       escaped))
                                return -ENOMEM;
                }

                r = serialize_item(f, "exec-context-mount-image", s);
                if (r < 0)
                        return r;
        }

        for (size_t i = 0; i < c->n_extension_images; i++) {
                _cleanup_free_ char *s = NULL;

                s = strjoin(c->extension_images[i].ignore_enoent ? "-" : "",
                            c->extension_images[i].source);
                if (!s)
                        return -ENOMEM;

                LIST_FOREACH(mount_options, o, c->extension_images[i].mount_options) {
                        _cleanup_free_ char *escaped = NULL;

                        if (isempty(o->options))
                                continue;

                        escaped = shell_escape(o->options, ":");
                        if (!escaped)
                                return log_oom_debug();

                        if (!strextend(&s,
                                       " ",
                                       partition_designator_to_string(o->partition_designator),
                                       ":",
                                       escaped))
                                return -ENOMEM;
                }

                r = serialize_item(f, "exec-context-extension-image", s);
                if (r < 0)
                        return r;
        }

        r = serialize_strv(f, "exec-context-extension-directories", c->extension_directories);
        if (r < 0)
                return r;

        ExecSetCredential *sc;
        HASHMAP_FOREACH(sc, c->set_credentials) {
                _cleanup_free_ char *data = NULL;

                data = hexmem(sc->data, sc->size);
                if (!data)
                        return -ENOMEM;

                r = serialize_item_format(f, "exec-context-set-credentials", "%s %s %s", sc->id, yes_no(sc->encrypted), data);
                if (r < 0)
                        return r;
        }

        ExecLoadCredential *lc;
        HASHMAP_FOREACH(lc, c->load_credentials) {
                r = serialize_item_format(f, "exec-context-load-credentials", "%s %s %s", lc->id, yes_no(lc->encrypted), lc->path);
                if (r < 0)
                        return r;
        }

        if (!set_isempty(c->import_credentials)) {
                char *ic;
                SET_FOREACH(ic, c->import_credentials) {
                        r = serialize_item(f, "exec-context-import-credentials", ic);
                        if (r < 0)
                                return r;
                }
        }

        if (c->root_image_policy) {
                _cleanup_free_ char *policy = NULL;

                r = image_policy_to_string(c->root_image_policy, false, &policy);
                if (r < 0)
                        return r;

                r = serialize_item(f, "exec-context-root-image-policy", policy);
                if (r < 0)
                        return r;
        }

        if (c->mount_image_policy) {
                _cleanup_free_ char *policy = NULL;

                r = image_policy_to_string(c->mount_image_policy, false, &policy);
                if (r < 0)
                        return r;

                r = serialize_item(f, "exec-context-mount-image-policy", policy);
                if (r < 0)
                        return r;
        }

        if (c->extension_image_policy) {
                _cleanup_free_ char *policy = NULL;

                r = image_policy_to_string(c->extension_image_policy, false, &policy);
                if (r < 0)
                        return r;

                r = serialize_item(f, "exec-context-extension-image-policy", policy);
                if (r < 0)
                        return r;
        }

        fputc('\n', f); /* End marker */

        return 0;
}

static int exec_context_deserialize(ExecContext *c, FILE *f) {
        int r;

        assert(c);
        assert(f);

        exec_context_init(c);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *val, *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read serialization line: %m");
                if (r == 0)
                        break;

                l = strstrip(line);
                if (isempty(l)) /* end marker */
                        break;

                if ((val = startswith(l, "exec-context-runtime-scope="))) {
                        r = safe_atoi(val, &c->runtime_scope);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-environment="))) {
                        r = deserialize_strv(&c->environment, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-manager-environment="))) {
                        r = deserialize_strv(&c->manager_environment, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-environment-files="))) {
                        r = deserialize_strv(&c->environment_files, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-pass-environment="))) {
                        r = deserialize_strv(&c->pass_environment, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-unset-environment="))) {
                        r = deserialize_strv(&c->unset_environment, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-working-directory="))) {
                        r = free_and_strdup(&c->working_directory, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-directory="))) {
                        r = free_and_strdup(&c->root_directory, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-image="))) {
                        r = free_and_strdup(&c->root_image, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-image-options="))) {
                        for (;;) {
                                _cleanup_free_ char *word = NULL, *mount_options = NULL, *partition = NULL;
                                PartitionDesignator partition_designator;
                                MountOptions *o = NULL;
                                const char *p;

                                r = extract_first_word(&val, &word, NULL, 0);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                p = word;
                                r = extract_many_words(&p, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &partition, &mount_options, NULL);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;

                                partition_designator = partition_designator_from_string(partition);
                                if (partition_designator < 0)
                                        return -EINVAL;

                                o = new(MountOptions, 1);
                                if (!o)
                                        return log_oom();
                                *o = (MountOptions) {
                                        .partition_designator = partition_designator,
                                        .options = TAKE_PTR(mount_options),
                                };
                                LIST_APPEND(mount_options, c->root_image_options, o);
                        }
                } else if ((val = startswith(l, "exec-context-root-verity="))) {
                        r = free_and_strdup(&c->root_verity, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-hash-path="))) {
                        r = free_and_strdup(&c->root_hash_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-hash-sig-path="))) {
                        r = free_and_strdup(&c->root_hash_sig_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-hash="))) {
                        c->root_hash = mfree(c->root_hash);
                        r = unhexmem(val, strlen(val), &c->root_hash, &c->root_hash_size);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-hash-sig="))) {
                        c->root_hash_sig = mfree(c->root_hash_sig);
                        r= unbase64mem(val, strlen(val), &c->root_hash_sig, &c->root_hash_sig_size);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-ephemeral="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->root_ephemeral = r;
                } else if ((val = startswith(l, "exec-context-umask="))) {
                        r = parse_mode(val, &c->umask);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-private-non-blocking="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->non_blocking = r;
                } else if ((val = startswith(l, "exec-context-private-mounts="))) {
                        r = safe_atoi(val, &c->private_mounts);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-memory-ksm="))) {
                        r = safe_atoi(val, &c->memory_ksm);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-private-tmp="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->private_tmp = r;
                } else if ((val = startswith(l, "exec-context-private-devices="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->private_devices = r;
                } else if ((val = startswith(l, "exec-context-protect-kernel-tunables="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->protect_kernel_tunables = r;
                } else if ((val = startswith(l, "exec-context-protect-kernel-modules="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->protect_kernel_modules = r;
                } else if ((val = startswith(l, "exec-context-protect-kernel-logs="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->protect_kernel_logs = r;
                } else if ((val = startswith(l, "exec-context-protect-clock="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->protect_clock = r;
                } else if ((val = startswith(l, "exec-context-protect-control-groups="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->protect_control_groups = r;
                } else if ((val = startswith(l, "exec-context-private-network="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->private_network = r;
                } else if ((val = startswith(l, "exec-context-private-users="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->private_users = r;
                } else if ((val = startswith(l, "exec-context-private-ipc="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->private_ipc = r;
                } else if ((val = startswith(l, "exec-context-remove-ipc="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->remove_ipc = r;
                } else if ((val = startswith(l, "exec-context-protect-home="))) {
                        c->protect_home = protect_home_from_string(val);
                        if (c->protect_home < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-protect-system="))) {
                        c->protect_system = protect_system_from_string(val);
                        if (c->protect_system < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-mount-api-vfs="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->mount_apivfs = r;
                } else if ((val = startswith(l, "exec-context-mount-api-vfs-set="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->mount_apivfs_set = r;
                } else if ((val = startswith(l, "exec-context-same-pgrp="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->same_pgrp = r;
                } else if ((val = startswith(l, "exec-context-cpu-sched-reset-on-fork="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->cpu_sched_reset_on_fork = r;
                } else if ((val = startswith(l, "exec-context-non-blocking="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        r = c->non_blocking;
                } else if ((val = startswith(l, "exec-context-ignore-sigpipe="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->ignore_sigpipe = r;
                } else if ((val = startswith(l, "exec-context-memory-deny-write-execute="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->memory_deny_write_execute = r;
                } else if ((val = startswith(l, "exec-context-restrict-realtime="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->restrict_realtime = r;
                } else if ((val = startswith(l, "exec-context-restrict-suid-sgid="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->restrict_suid_sgid = r;
                } else if ((val = startswith(l, "exec-context-keyring-mode="))) {
                        c->keyring_mode = exec_keyring_mode_from_string(val);
                        if (c->keyring_mode < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-protect-hostname="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->protect_hostname = r;
                } else if ((val = startswith(l, "exec-context-protect-proc="))) {
                        c->protect_proc = protect_proc_from_string(val);
                        if (c->protect_proc < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-proc-subset="))) {
                        c->proc_subset = proc_subset_from_string(val);
                        if (c->proc_subset < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-runtime-directory-preserve-mode="))) {
                        c->runtime_directory_preserve_mode = exec_preserve_mode_from_string(val);
                        if (c->runtime_directory_preserve_mode < 0)
                                return -EINVAL;
                } else if ((val = startswith(l, "exec-context-directories-"))) {
                        _cleanup_free_ char *type = NULL, *mode = NULL;
                        ExecDirectoryType dt;

                        r = extract_many_words(&val, "= ", 0, &type, &mode, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        dt = exec_directory_type_from_string(type);
                        if (dt < 0)
                                return -EINVAL;

                        r = parse_mode(mode, &c->directories[dt].mode);
                        if (r < 0)
                                return r;

                        for (;;) {
                                _cleanup_free_ char *tuple = NULL, *path = NULL, *only_create = NULL;
                                const char *p;

                                r = extract_first_word(&val, &tuple, WHITESPACE, EXTRACT_RETAIN_ESCAPE);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                p = tuple;
                                r = extract_many_words(&p, ":", EXTRACT_UNESCAPE_SEPARATORS, &path, &only_create, NULL);
                                if (r < 0)
                                        return r;
                                if (r < 2)
                                        continue;

                                r = exec_directory_add(&c->directories[dt], path, NULL);
                                if (r < 0)
                                        return r;

                                r = parse_boolean(only_create);
                                if (r < 0)
                                        return r;
                                c->directories[dt].items[c->directories[dt].n_items - 1].only_create = r;

                                if (isempty(p))
                                        continue;

                                for (;;) {
                                        _cleanup_free_ char *link = NULL;

                                        r = extract_first_word(&p, &link, ":", EXTRACT_UNESCAPE_SEPARATORS);
                                        if (r < 0)
                                                return r;
                                        if (r == 0)
                                                break;

                                        r = strv_consume(&c->directories[dt].items[c->directories[dt].n_items - 1].symlinks, TAKE_PTR(link));
                                        if (r < 0)
                                                return r;
                                }
                        }
                } else if ((val = startswith(l, "exec-context-timeout-clean-usec="))) {
                        r = deserialize_usec(val, &c->timeout_clean_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-nice="))) {
                        r = safe_atoi(val, &c->nice);
                        if (r < 0)
                                return r;
                        c->nice_set = true;
                } else if ((val = startswith(l, "exec-context-working-directory-missing-ok="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->working_directory_missing_ok = r;
                } else if ((val = startswith(l, "exec-context-working-directory-home="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->working_directory_home = r;
                } else if ((val = startswith(l, "exec-context-oom-score-adjust="))) {
                        r = safe_atoi(val, &c->oom_score_adjust);
                        if (r < 0)
                                return r;
                        c->oom_score_adjust_set = true;
                } else if ((val = startswith(l, "exec-context-coredump-filter="))) {
                        r = safe_atoux64(val, &c->coredump_filter);
                        if (r < 0)
                                return r;
                        c->coredump_filter_set = true;
                } else if ((val = startswith(l, "exec-context-limit-"))) {
                        _cleanup_free_ char *limit = NULL;
                        int type;

                        r = extract_first_word(&val, &limit, "=", 0);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        type = rlimit_from_string(limit);
                        if (type < 0)
                                return -EINVAL;

                        if (!c->rlimit[type]) {
                                c->rlimit[type] = new0(struct rlimit, 1);
                                if (!c->rlimit[type])
                                        return log_oom();
                        }

                        r = rlimit_parse(type, val, c->rlimit[type]);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-ioprio="))) {
                        r = safe_atoi(val, &c->ioprio);
                        if (r < 0)
                                return r;
                        c->ioprio_set = true;
                } else if ((val = startswith(l, "exec-context-cpu-scheduling-policy="))) {
                        r = sched_policy_from_string(val);
                        if (r < 0)
                                return r;
                        c->cpu_sched_set = true;
                } else if ((val = startswith(l, "exec-context-cpu-scheduling-priority="))) {
                        r = safe_atoi(val, &c->cpu_sched_priority);
                        if (r < 0)
                                return r;
                        c->cpu_sched_set = true;
                } else if ((val = startswith(l, "exec-context-cpu-scheduling-reset-on-fork="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->cpu_sched_reset_on_fork = r;
                        c->cpu_sched_set = true;
                } else if ((val = startswith(l, "exec-context-cpu-affinity="))) {
                        r = parse_cpu_set(val, &c->cpu_set);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-numa-mask="))) {
                        r = parse_cpu_set(val, &c->numa_policy.nodes);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-numa-policy="))) {
                        r = safe_atoi(val, &c->numa_policy.type);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-cpu-affinity-from-numa="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->cpu_affinity_from_numa = r;
                } else if ((val = startswith(l, "exec-context-timer-slack-nsec="))) {
                        r = deserialize_usec(val, (usec_t *)&c->timer_slack_nsec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-input="))) {
                        c->std_input = exec_input_from_string(val);
                        if (c->std_input < 0)
                                return c->std_input;
                } else if ((val = startswith(l, "exec-context-std-output="))) {
                        c->std_output = exec_output_from_string(val);
                        if (c->std_output < 0)
                                return c->std_output;
                } else if ((val = startswith(l, "exec-context-std-error="))) {
                        c->std_error = exec_output_from_string(val);
                        if (c->std_error < 0)
                                return c->std_error;
                } else if ((val = startswith(l, "exec-context-stdio-as-fds="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->stdio_as_fds = r;
                } else if ((val = startswith(l, "exec-context-std-input-fd-name="))) {
                        r = free_and_strdup(&c->stdio_fdname[STDIN_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-output-fd-name="))) {
                        r = free_and_strdup(&c->stdio_fdname[STDOUT_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-error-fd-name="))) {
                        r = free_and_strdup(&c->stdio_fdname[STDERR_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-input-file="))) {
                        r = free_and_strdup(&c->stdio_file[STDIN_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-output-file="))) {
                        r = free_and_strdup(&c->stdio_file[STDOUT_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-output-file-append="))) {
                        r = free_and_strdup(&c->stdio_file[STDOUT_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-output-file-truncate="))) {
                        r = free_and_strdup(&c->stdio_file[STDOUT_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-error-file="))) {
                        r = free_and_strdup(&c->stdio_file[STDERR_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-error-file-append="))) {
                        r = free_and_strdup(&c->stdio_file[STDERR_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-std-error-file-truncate="))) {
                        r = free_and_strdup(&c->stdio_file[STDERR_FILENO], val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-stdin-data="))) {
                        r = unhexmem(val, strlen(val), &c->stdin_data, &c->stdin_data_size);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-tty-path="))) {
                        r = free_and_strdup(&c->tty_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-tty-reset="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->tty_reset = r;
                } else if ((val = startswith(l, "exec-context-tty-vhangup="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->tty_vhangup = r;
                } else if ((val = startswith(l, "exec-context-tty-vt-disallocate="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->tty_vt_disallocate = r;
                } else if ((val = startswith(l, "exec-context-tty-rows="))) {
                        r = safe_atou(val, &c->tty_rows);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-tty-columns="))) {
                        r = safe_atou(val, &c->tty_cols);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-syslog-priority="))) {
                        r = safe_atoi(val, &c->syslog_priority);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-syslog-level-prefix="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->syslog_level_prefix = r;
                } else if ((val = startswith(l, "exec-context-syslog-identifier="))) {
                        r = free_and_strdup(&c->syslog_identifier, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-log-level-max="))) {
                        r = safe_atoi(val, &c->log_level_max);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-log-ratelimit-interval-usec="))) {
                        r = deserialize_usec(val, &c->log_ratelimit_interval_usec);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-log-ratelimit-burst="))) {
                        r = safe_atou(val, &c->log_ratelimit_burst);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-log-filter-allowed-patterns="))) {
                        r = set_ensure_allocated(&c->log_filter_allowed_patterns, &string_hash_ops);
                        if (r < 0)
                                return r;

                        r = set_put_strsplit(c->log_filter_allowed_patterns, val, " ", 0);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-log-filter-denied-patterns="))) {
                        r = set_ensure_allocated(&c->log_filter_denied_patterns, &string_hash_ops);
                        if (r < 0)
                                return r;

                        r = set_put_strsplit(c->log_filter_denied_patterns, val, " ", 0);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-log-extra-fields="))) {
                        if (!GREEDY_REALLOC(c->log_extra_fields, c->n_log_extra_fields + 1))
                                return log_oom();

                        c->log_extra_fields[c->n_log_extra_fields++].iov_base = strdup(val);
                        if (!c->log_extra_fields[c->n_log_extra_fields-1].iov_base)
                                return log_oom();
                } else if ((val = startswith(l, "exec-context-log-namespace="))) {
                        r = free_and_strdup(&c->log_namespace, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-secure-bits="))) {
                        r = safe_atoi(val, &c->secure_bits);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-capability-bounding-set="))) {
                        r = safe_atou64(val, &c->capability_bounding_set);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-capability-ambient-set="))) {
                        r = safe_atou64(val, &c->capability_ambient_set);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-user="))) {
                        r = free_and_strdup(&c->user, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-group="))) {
                        r = free_and_strdup(&c->group, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-dynamic-user="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->dynamic_user = r;
                } else if ((val = startswith(l, "exec-context-supplementary-groups="))) {
                        r = deserialize_strv(&c->supplementary_groups, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-pam-name="))) {
                        r = free_and_strdup(&c->pam_name, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-read-write-paths="))) {
                        r = deserialize_strv(&c->read_write_paths, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-read-only-paths="))) {
                        r = deserialize_strv(&c->read_only_paths, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-inaccessible-paths="))) {
                        r = deserialize_strv(&c->inaccessible_paths, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-exec-paths="))) {
                        r = deserialize_strv(&c->exec_paths, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-no-exec-paths="))) {
                        r = deserialize_strv(&c->no_exec_paths, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-exec-search-path="))) {
                        r = deserialize_strv(&c->exec_search_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-mount-propagation-flag="))) {
                        r = safe_atolu(val, &c->mount_propagation_flag);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-bind-read-only-path="))) {
                        _cleanup_free_ char *source = NULL, *destination = NULL;
                        bool rbind = true, ignore_enoent = false;
                        char *s = NULL, *d = NULL;

                        r = extract_first_word(&val, &source, ":" WHITESPACE, EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS);
                        if (r < 0)
                                return -1;
                        if (r == 0)
                                continue;

                        s = source;
                        if (s[0] == '-') {
                                ignore_enoent = true;
                                s++;
                        }

                        if (val && val[-1] == ':') {
                                r = extract_first_word(&val, &destination, ":" WHITESPACE, EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;

                                d = destination;

                                if (val && val[-1] == ':') {
                                        _cleanup_free_ char *options = NULL;

                                        r = extract_first_word(&val, &options, NULL, EXTRACT_UNQUOTE);
                                        if (r < 0)
                                                return -r;

                                        if (isempty(options) || streq(options, "rbind"))
                                                rbind = true;
                                        else if (streq(options, "norbind"))
                                                rbind = false;
                                        else
                                                continue;
                                }
                        } else
                                d = s;

                        r = bind_mount_add(&c->bind_mounts, &c->n_bind_mounts,
                                        &(BindMount) {
                                                .source = s,
                                                .destination = d,
                                                .read_only = true,
                                                .recursive = rbind,
                                                .ignore_enoent = ignore_enoent,
                                        });
                        if (r < 0)
                                return log_oom();
                } else if ((val = startswith(l, "exec-context-bind-path="))) {
                        _cleanup_free_ char *source = NULL, *destination = NULL;
                        bool rbind = true, ignore_enoent = false;
                        char *s = NULL, *d = NULL;

                        r = extract_first_word(&val, &source, ":" WHITESPACE, EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS);
                        if (r < 0)
                                return -1;
                        if (r == 0)
                                continue;

                        s = source;
                        if (s[0] == '-') {
                                ignore_enoent = true;
                                s++;
                        }

                        if (val && val[-1] == ':') {
                                r = extract_first_word(&val, &destination, ":" WHITESPACE, EXTRACT_UNQUOTE|EXTRACT_DONT_COALESCE_SEPARATORS);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;

                                d = destination;

                                if (val && val[-1] == ':') {
                                        _cleanup_free_ char *options = NULL;

                                        r = extract_first_word(&val, &options, NULL, EXTRACT_UNQUOTE);
                                        if (r < 0)
                                                return -r;

                                        if (isempty(options) || streq(options, "rbind"))
                                                rbind = true;
                                        else if (streq(options, "norbind"))
                                                rbind = false;
                                        else
                                                continue;
                                }
                        } else
                                d = s;

                        r = bind_mount_add(&c->bind_mounts, &c->n_bind_mounts,
                                        &(BindMount) {
                                                .source = s,
                                                .destination = d,
                                                .read_only = false,
                                                .recursive = rbind,
                                                .ignore_enoent = ignore_enoent,
                                        });
                        if (r < 0)
                                return log_oom();
                } else if ((val = startswith(l, "exec-context-temporary-filesystems="))) {
                        _cleanup_free_ char *path = NULL, *options = NULL;

                        r = extract_many_words(&val, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &path, &options, NULL);
                        if (r < 0)
                                return r;
                        if (r < 1)
                                continue;

                        r = temporary_filesystem_add(&c->temporary_filesystems, &c->n_temporary_filesystems, path, options);
                        if (r < 0)
                                return log_oom_debug();
                } else if ((val = startswith(l, "exec-context-utmp-id="))) {
                        r = free_and_strdup(&c->utmp_id, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-utmp-mode="))) {
                        r = safe_atoi(val, &c->utmp_mode);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-no-new-privileges="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->no_new_privileges = r;
                } else if ((val = startswith(l, "exec-context-selinux-context-ignore="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->selinux_context_ignore = r;
                } else if ((val = startswith(l, "exec-context-apparmor-profile-ignore="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->apparmor_profile_ignore = r;
                } else if ((val = startswith(l, "exec-context-smack-process-label-ignore="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->smack_process_label_ignore = r;
                } else if ((val = startswith(l, "exec-context-selinux-context="))) {
                        if (val[0] == '-') {
                                c->selinux_context_ignore = true;
                                val++;
                        }

                        r = free_and_strdup(&c->selinux_context, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-apparmor-profile="))) {
                        if (val[0] == '-') {
                                c->apparmor_profile_ignore = true;
                                val++;
                        }

                        r = free_and_strdup(&c->apparmor_profile, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-smack-process-label="))) {
                        if (val[0] == '-') {
                                c->smack_process_label_ignore = true;
                                val++;
                        }

                        r = free_and_strdup(&c->smack_process_label, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-personality=")))
                        c->personality = personality_from_string(val);
                else if ((val = startswith(l, "exec-context-lock-personality="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->lock_personality = r;
#if HAVE_SECCOMP
                } else if ((val = startswith(l, "exec-context-syscall-filter="))) {
                        _cleanup_free_ char *s_id = NULL, *s_errno_num = NULL;
                        int id, errno_num;

                        r = extract_many_words(&val, NULL, 0, &s_id, &s_errno_num, NULL);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                continue;

                        r = safe_atoi(s_id, &id);
                        if (r < 0)
                                return r;

                        r = safe_atoi(s_errno_num, &errno_num);
                        if (r < 0)
                                return r;

                        r = hashmap_ensure_put(&c->syscall_filter, NULL, INT_TO_PTR(id + 1), INT_TO_PTR(errno_num));
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-syscall-archs="))) {
                        unsigned int id;

                        r = safe_atou(val, &id);
                        if (r < 0)
                                return r;

                        r = set_ensure_put(&c->syscall_archs, NULL, UINT_TO_PTR(id + 1));
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-syscall-errno="))) {
                        r = safe_atoi(val, &c->syscall_errno);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-syscall-allow-list="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->syscall_allow_list = r;
                } else if ((val = startswith(l, "exec-context-syscall-log="))) {
                        _cleanup_free_ char *s_id = NULL, *s_errno_num = NULL;
                        int id, errno_num;

                        r = extract_many_words(&val, " ", 0, &s_id, &s_errno_num, NULL);
                        if (r < 0)
                                return r;
                        if (r != 2)
                                continue;

                        r = safe_atoi(s_id, &id);
                        if (r < 0)
                                return r;

                        r = safe_atoi(s_errno_num, &errno_num);
                        if (r < 0)
                                return r;

                        r = hashmap_ensure_put(&c->syscall_log, NULL, INT_TO_PTR(id + 1), INT_TO_PTR(errno_num));
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-syscall-log-allow-list="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->syscall_log_allow_list = r;
#endif
                } else if ((val = startswith(l, "exec-context-restrict-namespaces="))) {
                        r = safe_atolu(val, &c->restrict_namespaces);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-restrict-filesystems="))) {
                        r = set_ensure_allocated(&c->restrict_filesystems, &string_hash_ops);
                        if (r < 0)
                                return r;

                        r = set_put_strdup(&c->restrict_filesystems, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-restrict-filesystems-allow-list="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->restrict_filesystems_allow_list = r;
                } else if ((val = startswith(l, "exec-context-address-families="))) {
                        int af;

                        r = safe_atoi(val, &af);
                        if (r < 0)
                                return r;

                        r = set_ensure_put(&c->address_families, NULL, INT_TO_PTR(af));
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-address-families-allow-list="))) {
                        r = parse_boolean(val);
                        if (r < 0)
                                return r;
                        c->address_families_allow_list = r;
                } else if ((val = startswith(l, "exec-context-network-namespace-path="))) {
                        r = free_and_strdup(&c->network_namespace_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-ipc-namespace-path="))) {
                        r = free_and_strdup(&c->ipc_namespace_path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-mount-image="))) {
                        _cleanup_(mount_options_free_allp) MountOptions *options = NULL;
                        _cleanup_free_ char *source = NULL, *destination = NULL;
                        bool permissive = false;
                        char *s;

                        r = extract_many_words(&val, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE, &source, &destination, NULL);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        s = source;
                        if (s[0] == '-') {
                                permissive = true;
                                s++;
                        }

                        if (isempty(destination))
                                continue;

                        for (;;) {
                                _cleanup_free_ char *tuple = NULL, *partition = NULL, *opts = NULL;
                                PartitionDesignator partition_designator;
                                MountOptions *o = NULL;
                                const char *p;

                                r = extract_first_word(&val, &tuple, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                p = tuple;
                                r = extract_many_words(&p, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &partition, &opts, NULL);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;
                                if (r == 1) {
                                        o = new(MountOptions, 1);
                                        if (!o)
                                                return log_oom();
                                        *o = (MountOptions) {
                                                .partition_designator = PARTITION_ROOT,
                                                .options = TAKE_PTR(partition),
                                        };
                                        LIST_APPEND(mount_options, options, o);

                                        continue;
                                }

                                partition_designator = partition_designator_from_string(partition);
                                if (partition_designator < 0)
                                        continue;

                                o = new(MountOptions, 1);
                                if (!o)
                                        return log_oom();
                                *o = (MountOptions) {
                                        .partition_designator = partition_designator,
                                        .options = TAKE_PTR(opts),
                                };
                                LIST_APPEND(mount_options, options, o);
                        }

                        r = mount_image_add(&c->mount_images, &c->n_mount_images,
                                        &(MountImage) {
                                                .source = s,
                                                .destination = destination,
                                                .mount_options = options,
                                                .ignore_enoent = permissive,
                                                .type = MOUNT_IMAGE_DISCRETE,
                                        });
                        if (r < 0)
                                return log_oom();
                } else if ((val = startswith(l, "exec-context-extension-image="))) {
                        _cleanup_(mount_options_free_allp) MountOptions *options = NULL;
                        _cleanup_free_ char *source = NULL;
                        bool permissive = false;
                        char *s;

                        r = extract_first_word(&val, &source, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        s = source;
                        if (s[0] == '-') {
                                permissive = true;
                                s++;
                        }

                        for (;;) {
                                _cleanup_free_ char *tuple = NULL, *partition = NULL, *opts = NULL;
                                PartitionDesignator partition_designator;
                                MountOptions *o = NULL;
                                const char *p;

                                r = extract_first_word(&val, &tuple, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        break;

                                p = tuple;
                                r = extract_many_words(&p, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS, &partition, &opts, NULL);
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        continue;
                                if (r == 1) {
                                        o = new(MountOptions, 1);
                                        if (!o)
                                                return log_oom();
                                        *o = (MountOptions) {
                                                .partition_designator = PARTITION_ROOT,
                                                .options = TAKE_PTR(partition),
                                        };
                                        LIST_APPEND(mount_options, options, o);

                                        continue;
                                }

                                partition_designator = partition_designator_from_string(partition);
                                if (partition_designator < 0)
                                        continue;

                                o = new(MountOptions, 1);
                                if (!o)
                                        return log_oom();
                                *o = (MountOptions) {
                                        .partition_designator = partition_designator,
                                        .options = TAKE_PTR(opts),
                                };
                                LIST_APPEND(mount_options, options, o);
                        }

                        r = mount_image_add(&c->extension_images, &c->n_extension_images,
                                        &(MountImage) {
                                                .source = s,
                                                .mount_options = options,
                                                .ignore_enoent = permissive,
                                                .type = MOUNT_IMAGE_EXTENSION,
                                        });
                        if (r < 0)
                                return log_oom();
                } else if ((val = startswith(l, "exec-context-extension-directories="))) {
                        r = deserialize_strv(&c->extension_directories, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-set-credentials="))) {
                        _cleanup_(exec_set_credential_freep) ExecSetCredential *sc = NULL;
                        _cleanup_free_ char *id = NULL, *encrypted = NULL, *data = NULL;

                        r = extract_many_words(&val, " ", 0, &id, &encrypted, &data, NULL);
                        if (r < 0)
                                return r;
                        if (r != 3)
                                continue;

                        r = parse_boolean(encrypted);
                        if (r < 0)
                                return r;

                        sc = new(ExecSetCredential, 1);
                        if (!sc)
                                return -ENOMEM;

                        *sc = (ExecSetCredential) {
                                .id =  TAKE_PTR(id),
                                .encrypted = r,
                        };

                        r = unhexmem(data, strlen(data), &sc->data, &sc->size);
                        if (r < 0)
                                return r;

                        r = hashmap_ensure_put(&c->set_credentials, &exec_set_credential_hash_ops, sc->id, sc);
                        if (r < 0)
                                return r;

                        TAKE_PTR(sc);
                } else if ((val = startswith(l, "exec-context-load-credentials="))) {
                        _cleanup_(exec_load_credential_freep) ExecLoadCredential *lc = NULL;
                        _cleanup_free_ char *id = NULL, *encrypted = NULL, *path = NULL;

                        r = extract_many_words(&val, " ", 0, &id, &encrypted, &path, NULL);
                        if (r < 0)
                                return r;
                        if (r != 3)
                                continue;

                        r = parse_boolean(encrypted);
                        if (r < 0)
                                return r;

                        lc = new(ExecLoadCredential, 1);
                        if (!lc)
                                return -ENOMEM;

                        *lc = (ExecLoadCredential) {
                                .id =  TAKE_PTR(id),
                                .path = TAKE_PTR(path),
                                .encrypted = r,
                        };

                        r = hashmap_ensure_put(&c->load_credentials, &exec_load_credential_hash_ops, lc->id, lc);
                        if (r < 0)
                                return r;

                        TAKE_PTR(lc);
                } else if ((val = startswith(l, "exec-context-import-credentials="))) {
                        r = set_ensure_allocated(&c->import_credentials, &string_hash_ops);
                        if (r < 0)
                                return r;

                        r = set_put_strdup(&c->import_credentials, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-root-image-policy="))) {
                        r = image_policy_from_string(val, &c->root_image_policy);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-mount-image-policy="))) {
                        r = image_policy_from_string(val, &c->mount_image_policy);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-context-extension-image-policy="))) {
                        r = image_policy_from_string(val, &c->extension_image_policy);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int exec_command_serialize(const ExecCommand *c, FILE *f) {
        int r;

        assert(c);
        assert(f);

        r = serialize_item(f, "exec-command-path", c->path);
        if (r < 0)
                return r;

        r = serialize_strv(f, "exec-command-argv", c->argv);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-command-flags", "%d", c->flags);
        if (r < 0)
                return r;

        r = serialize_dual_timestamp(f, "exec-status-start-timestamp", &c->exec_status.start_timestamp);
        if (r < 0)
                return r;

        r = serialize_dual_timestamp(f, "exec-status-exit-timestamp", &c->exec_status.exit_timestamp);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-status-pid", PID_FMT, c->exec_status.pid);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-status-code", "%d", c->exec_status.code);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "exec-status-status", "%d", c->exec_status.status);
        if (r < 0)
                return r;

        fputc('\n', f); /* End marker */

        return 0;
}

static int exec_command_deserialize(ExecCommand *c, FILE *f) {
        int r;

        assert(c);
        assert(f);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *val, *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read serialization line: %m");
                if (r == 0)
                        break;

                l = strstrip(line);
                if (isempty(l)) /* end marker */
                        break;

                if ((val = startswith(l, "exec-command-path="))) {
                        r = free_and_strdup(&c->path, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-command-argv="))) {
                        r = deserialize_strv(&c->argv, val);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-command-flags="))) {
                        unsigned long u;

                        r = safe_atolu(val, &u);
                        if (r < 0)
                                return r;

                        c->flags = u;
                } else if ((val = startswith(l, "exec-status-start-timestamp="))) {
                        r = deserialize_dual_timestamp(val, &c->exec_status.start_timestamp);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-status-exit-timestamp="))) {
                        r = deserialize_dual_timestamp(val, &c->exec_status.exit_timestamp);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-status-pid="))) {
                        r = safe_atoi(val, &c->exec_status.pid);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-status-code="))) {
                        r = safe_atoi(val, &c->exec_status.code);
                        if (r < 0)
                                return r;
                } else if ((val = startswith(l, "exec-status-status="))) {
                        r = safe_atoi(val, &c->exec_status.status);
                        if (r < 0)
                                return r;
                } else
                        log_warning("Failed to parse serialization line: %s", l);

        }

        return 0;
}

int exec_serialize(FILE *f,
                FDSet *fds,
                int **fds_array,
                size_t *n_fds_array,
                const Unit *u,
                const ExecContext *ctx,
                const ExecCommand *cmd,
                const ExecParameters *p,
                const ExecRuntime *rt,
                const CGroupContext *cg) {

        int r;

        assert(f);
        assert(fds_array);
        assert(n_fds_array);
        assert(fds || *fds_array);
        assert(!(fds && *fds_array));
        assert(!!*fds_array == !!*n_fds_array);

        r = exec_unit_serialize(u, f);
        if (r < 0)
                return log_debug_errno(r, "Failed to serialize unit: %m");

        r = exec_context_serialize(ctx, f);
        if (r < 0)
                return log_debug_errno(r, "Failed to serialize context: %m");

        r = exec_command_serialize(cmd, f);
        if (r < 0)
                return log_debug_errno(r, "Failed to serialize command: %m");

        r = exec_parameters_serialize(p, f, fds, fds_array, n_fds_array);
        if (r < 0)
                return log_debug_errno(r, "Failed to serialize parameters: %m");

        r = exec_runtime_serialize(rt, f, fds, fds_array, n_fds_array);
        if (r < 0)
                return log_debug_errno(r, "Failed to serialize runtime: %m");

        r = exec_cgroup_context_serialize(cg, f);
        if (r < 0)
                return log_debug_errno(r, "Failed to serialize cgroup context: %m");

        return 0;
}

int exec_deserialize(FILE *f,
                FDSet *fds,
                int *fds_array,
                size_t n_fds_array,
                Unit **ret_unit,
                ExecCommand *c,
                ExecParameters *p,
                ExecRuntime *rt) {

        int r;

        assert(f);
        assert(!(fds && fds_array));
        assert(!!fds_array == !!n_fds_array);
        assert(ret_unit);

        r = exec_unit_deserialize(ret_unit, f);
        if (r < 0)
                return log_debug_errno(r, "Failed to deserialize unit: %m");

        r = exec_context_deserialize(unit_get_exec_context(*ret_unit), f);
        if (r < 0)
                return log_debug_errno(r, "Failed to deserialize context: %m");

        r = exec_command_deserialize(c, f);
        if (r < 0)
                return log_debug_errno(r, "Failed to deserialize command: %m");

        r = exec_parameters_deserialize(p, f, fds, fds_array, n_fds_array);
        if (r < 0)
                return log_debug_errno(r, "Failed to deserialize parameters: %m");

        r = exec_runtime_deserialize(rt, f, fds, fds_array, n_fds_array);
        if (r < 0)
                return log_debug_errno(r, "Failed to deserialize runtime: %m");

        r = exec_cgroup_context_deserialize(unit_get_cgroup_context(*ret_unit), f);
        if (r < 0)
                return log_debug_errno(r, "Failed to deserialize cgroup context: %m");

        return 0;
}
