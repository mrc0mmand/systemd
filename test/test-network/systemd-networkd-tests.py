#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
# systemd-networkd tests

# These tests can be executed in the systemd mkosi image when booted in QEMU. After booting the QEMU VM,
# simply run this file which can be found in the VM at /usr/lib/systemd/tests/testdata/test-network/systemd-networkd-tests.py.

import argparse
import os
import sys
import unittest

import common


def setUpModule():
    common.rm_rf(common.networkd_ci_temp_dir)
    common.cp_r(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'conf'), common.networkd_ci_temp_dir)

    common.clear_network_units()
    common.clear_networkd_conf_dropins()
    common.clear_udev_rules()

    common.copy_udev_rule('00-debug-net.rules')

    # Save current state
    common.save_active_units()
    common.save_existing_links()
    common.save_routes()
    common.save_routing_policy_rules()
    common.save_timezone()

    common.create_service_dropin(
            'systemd-networkd', common.networkd_bin,
            f'{common.networkctl_bin} reload',
            ['[Service]', 'Restart=no', '[Unit]', 'StartLimitIntervalSec=0'])
    common.create_service_dropin('systemd-resolved', common.resolved_bin)
    common.create_service_dropin('systemd-timesyncd', common.timesyncd_bin)

    # TODO: also run udevd with sanitizers, valgrind, or coverage
    #common.create_service_dropin('systemd-udevd', common.udevd_bin,
    #                      f'{common.udevadm_bin} control --reload --timeout 0')
    common.create_unit_dropin(
        'systemd-udevd.service',
        [
            '[Service]',
            'ExecStart=',
            f'ExecStart=!!{common.udevd_bin}',
            'ExecReload=',
            f'ExecReload={common.udevadm_bin} control --reload --timeout 0',
        ]
    )
    common.create_unit_dropin(
        'systemd-networkd.socket',
        [
            '[Unit]',
            'StartLimitIntervalSec=0',
        ]
    )

    common.check_output('systemctl daemon-reload')
    print(common.check_output('systemctl cat systemd-networkd.service'))
    print(common.check_output('systemctl cat systemd-resolved.service'))
    print(common.check_output('systemctl cat systemd-timesyncd.service'))
    print(common.check_output('systemctl cat systemd-udevd.service'))
    common.check_output('systemctl restart systemd-resolved.service')
    common.check_output('systemctl restart systemd-timesyncd.service')
    common.check_output('systemctl restart systemd-udevd.service')

def tearDownModule():
    common.rm_rf(common.networkd_ci_temp_dir)
    common.clear_udev_rules()
    common.clear_network_units()
    common.clear_networkd_conf_dropins()

    common.restore_timezone()

    common.rm_rf('/run/systemd/system/systemd-networkd.service.d')
    common.rm_rf('/run/systemd/system/systemd-networkd.socket.d')
    common.rm_rf('/run/systemd/system/systemd-resolved.service.d')
    common.rm_rf('/run/systemd/system/systemd-timesyncd.service.d')
    common.rm_rf('/run/systemd/system/systemd-udevd.service.d')
    common.check_output('systemctl daemon-reload')
    common.check_output('systemctl restart systemd-udevd.service')
    common.restore_active_units()

def load_tests(loader, standard_tests, pattern):
    if not pattern:
        pattern = "*_tests.py"

    package_tests = loader.discover(start_dir=os.path.dirname(__file__), pattern=pattern)
    standard_tests.addTests(package_tests)
    return standard_tests

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', help='Path to build dir', dest='build_dir')
    parser.add_argument('--networkd', help='Path to systemd-networkd', dest='networkd_bin')
    parser.add_argument('--resolved', help='Path to systemd-resolved', dest='resolved_bin')
    parser.add_argument('--timesyncd', help='Path to systemd-timesyncd', dest='timesyncd_bin')
    parser.add_argument('--udevd', help='Path to systemd-udevd', dest='udevd_bin')
    parser.add_argument('--wait-online', help='Path to systemd-networkd-wait-online', dest='wait_online_bin')
    parser.add_argument('--networkctl', help='Path to networkctl', dest='networkctl_bin')
    parser.add_argument('--resolvectl', help='Path to resolvectl', dest='resolvectl_bin')
    parser.add_argument('--timedatectl', help='Path to timedatectl', dest='timedatectl_bin')
    parser.add_argument('--udevadm', help='Path to udevadm', dest='udevadm_bin')
    parser.add_argument('--valgrind', help='Enable valgrind', dest='use_valgrind', type=bool, nargs='?', const=True, default=common.use_valgrind)
    parser.add_argument('--debug', help='Generate debugging logs', dest='enable_debug', type=bool, nargs='?', const=True, default=common.enable_debug)
    parser.add_argument('--asan-options', help='ASAN options', dest='asan_options')
    parser.add_argument('--lsan-options', help='LSAN options', dest='lsan_options')
    parser.add_argument('--ubsan-options', help='UBSAN options', dest='ubsan_options')
    parser.add_argument('--with-coverage', help='Loosen certain sandbox restrictions to make gcov happy', dest='with_coverage', type=bool, nargs='?', const=True, default=common.with_coverage)
    ns, unknown_args = parser.parse_known_args(namespace=unittest)

    if ns.build_dir:
        if ns.networkd_bin or ns.resolved_bin or ns.timesyncd_bin or ns.udevd_bin or \
           ns.wait_online_bin or ns.networkctl_bin or ns.resolvectl_bin or ns.timedatectl_bin or ns.udevadm_bin:
            print('WARNING: --networkd, --resolved, --timesyncd, --udevd, --wait-online, --networkctl, --resolvectl, --timedatectl, or --udevadm options are ignored when --build-dir is specified.')
        common.networkd_bin = os.path.join(ns.build_dir, 'systemd-networkd')
        common.resolved_bin = os.path.join(ns.build_dir, 'systemd-resolved')
        common.timesyncd_bin = os.path.join(ns.build_dir, 'systemd-timesyncd')
        common.udevd_bin = os.path.join(ns.build_dir, 'systemd-udevd')
        common.wait_online_bin = os.path.join(ns.build_dir, 'systemd-networkd-wait-online')
        common.networkctl_bin = os.path.join(ns.build_dir, 'networkctl')
        common.resolvectl_bin = os.path.join(ns.build_dir, 'resolvectl')
        common.timedatectl_bin = os.path.join(ns.build_dir, 'timedatectl')
        common.udevadm_bin = os.path.join(ns.build_dir, 'udevadm')
    else:
        if ns.networkd_bin:
            common.networkd_bin = ns.networkd_bin
        if ns.resolved_bin:
            common.resolved_bin = ns.resolved_bin
        if ns.timesyncd_bin:
            common.timesyncd_bin = ns.timesyncd_bin
        if ns.udevd_bin:
            common.udevd_bin = ns.udevd_bin
        if ns.wait_online_bin:
            common.wait_online_bin = ns.wait_online_bin
        if ns.networkctl_bin:
            common.networkctl_bin = ns.networkctl_bin
        if ns.resolvectl_bin:
            common.resolvectl_bin = ns.resolvectl_bin
        if ns.timedatectl_bin:
            common.timedatectl_bin = ns.timedatectl_bin
        if ns.udevadm_bin:
            common.udevadm_bin = ns.udevadm_bin

    common.use_valgrind = ns.use_valgrind
    common.enable_debug = ns.enable_debug
    common.asan_options = ns.asan_options
    common.lsan_options = ns.lsan_options
    common.ubsan_options = ns.ubsan_options
    common.with_coverage = ns.with_coverage

    if common.use_valgrind:
        # Do not forget the trailing space.
        common.valgrind_cmd = 'valgrind --track-origins=yes --leak-check=full --show-leak-kinds=all '

    common.networkctl_cmd = common.valgrind_cmd.split() + [common.networkctl_bin]
    common.resolvectl_cmd = common.valgrind_cmd.split() + [common.resolvectl_bin]
    common.timedatectl_cmd = common.valgrind_cmd.split() + [common.timedatectl_bin]
    common.udevadm_cmd = common.valgrind_cmd.split() + [common.udevadm_bin]
    common.wait_online_cmd = common.valgrind_cmd.split() + [common.wait_online_bin]

    if common.asan_options:
        common.env.update({'ASAN_OPTIONS': common.asan_options})
    if common.lsan_options:
        common.env.update({'LSAN_OPTIONS': common.lsan_options})
    if common.ubsan_options:
        common.env.update({'UBSAN_OPTIONS': common.ubsan_options})
    if common.use_valgrind:
        common.env.update({'SYSTEMD_MEMPOOL': '0'})

    common.wait_online_env = common.env.copy()
    if common.enable_debug:
        common.wait_online_env.update({'SYSTEMD_LOG_LEVEL': 'debug'})

    sys.argv[1:] = unknown_args
    unittest.main(verbosity=3)
