# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import unittest

import common


class NetworkdL2TPTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    @common.expectedFailureIfModuleIsNotAvailable('l2tp_eth', 'l2tp_netlink')
    def test_l2tp_udp(self):
        common.copy_network_unit(
                '11-dummy.netdev', '25-l2tp-dummy.network',
                '25-l2tp-udp.netdev', '25-l2tp.network')
        common.start_networkd()

        self.wait_online(['test1:routable', 'l2tp-ses1:degraded', 'l2tp-ses2:degraded'])

        output = common.check_output('ip l2tp show tunnel tunnel_id 10')
        print(output)
        self.assertRegex(output, "Tunnel 10, encap UDP")
        self.assertRegex(output, "From 192.168.30.100 to 192.168.30.101")
        self.assertRegex(output, "Peer tunnel 11")
        self.assertRegex(output, "UDP source / dest ports: 3000/4000")
        self.assertRegex(output, "UDP checksum: enabled")

        output = common.check_output('ip l2tp show session tid 10 session_id 15')
        print(output)
        self.assertRegex(output, "Session 15 in tunnel 10")
        self.assertRegex(output, "Peer session 16, tunnel 11")
        self.assertRegex(output, "interface name: l2tp-ses1")

        output = common.check_output('ip l2tp show session tid 10 session_id 17')
        print(output)
        self.assertRegex(output, "Session 17 in tunnel 10")
        self.assertRegex(output, "Peer session 18, tunnel 11")
        self.assertRegex(output, "interface name: l2tp-ses2")

    @common.expectedFailureIfModuleIsNotAvailable('l2tp_eth', 'l2tp_ip', 'l2tp_netlink')
    def test_l2tp_ip(self):
        common.copy_network_unit(
                '11-dummy.netdev', '25-l2tp-dummy.network',
                '25-l2tp-ip.netdev', '25-l2tp.network')
        common.start_networkd()

        self.wait_online(['test1:routable', 'l2tp-ses3:degraded', 'l2tp-ses4:degraded'])

        output = common.check_output('ip l2tp show tunnel tunnel_id 10')
        print(output)
        self.assertRegex(output, "Tunnel 10, encap IP")
        self.assertRegex(output, "From 192.168.30.100 to 192.168.30.101")
        self.assertRegex(output, "Peer tunnel 12")

        output = common.check_output('ip l2tp show session tid 10 session_id 25')
        print(output)
        self.assertRegex(output, "Session 25 in tunnel 10")
        self.assertRegex(output, "Peer session 26, tunnel 12")
        self.assertRegex(output, "interface name: l2tp-ses3")

        output = common.check_output('ip l2tp show session tid 10 session_id 27')
        print(output)
        self.assertRegex(output, "Session 27 in tunnel 10")
        self.assertRegex(output, "Peer session 28, tunnel 12")
        self.assertRegex(output, "interface name: l2tp-ses4")
