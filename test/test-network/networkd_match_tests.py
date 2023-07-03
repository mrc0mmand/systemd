# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import unittest

import common


class NetworkdMatchTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    @common.expectedFailureIfAlternativeNameIsNotAvailable()
    def test_match(self):
        common.copy_network_unit(
                '12-dummy-mac.netdev',
                '12-dummy-match-mac-01.network',
                '12-dummy-match-mac-02.network',
                '12-dummy-match-renamed.network',
                '12-dummy-match-altname.network',
                '12-dummy-altname.link')
        common.start_networkd()

        self.wait_online(['dummy98:routable'])
        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'dummy98', env=common.env)
        self.assertIn('Network File: /run/systemd/network/12-dummy-match-mac-01.network', output)
        output = common.check_output('ip -4 address show dev dummy98')
        self.assertIn('10.0.0.1/16', output)

        common.check_output('ip link set dev dummy98 down')
        common.check_output('ip link set dev dummy98 address 12:34:56:78:9a:02')

        self.wait_address('dummy98', '10.0.0.2/16', ipv='-4', timeout_sec=10)
        self.wait_online(['dummy98:routable'])
        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'dummy98', env=common.env)
        self.assertIn('Network File: /run/systemd/network/12-dummy-match-mac-02.network', output)

        common.check_output('ip link set dev dummy98 down')
        common.check_output('ip link set dev dummy98 name dummy98-1')

        self.wait_address('dummy98-1', '10.0.1.2/16', ipv='-4', timeout_sec=10)
        self.wait_online(['dummy98-1:routable'])
        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'dummy98-1', env=common.env)
        self.assertIn('Network File: /run/systemd/network/12-dummy-match-renamed.network', output)

        common.check_output('ip link set dev dummy98-1 down')
        common.check_output('ip link set dev dummy98-1 name dummy98-2')
        common.check_output(*common.udevadm_cmd, 'trigger', '--action=add', '/sys/class/net/dummy98-2')

        self.wait_address('dummy98-2', '10.0.2.2/16', ipv='-4', timeout_sec=10)
        self.wait_online(['dummy98-2:routable'])
        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'dummy98-2', env=common.env)
        self.assertIn('Network File: /run/systemd/network/12-dummy-match-altname.network', output)

    def test_match_udev_property(self):
        common.copy_network_unit('12-dummy.netdev', '13-not-match-udev-property.network', '14-match-udev-property.network')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'dummy98', env=common.env)
        print(output)
        self.assertRegex(output, 'Network File: /run/systemd/network/14-match-udev-property')
