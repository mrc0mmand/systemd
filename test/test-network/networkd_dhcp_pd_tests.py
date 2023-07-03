# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import os
import time
import unittest

import common


class NetworkdDHCPPDTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_dhcp6pd(self):
        common.copy_network_unit(
                '25-veth.netdev', '25-dhcp6pd-server.network', '25-dhcp6pd-upstream.network',
                '25-veth-downstream-veth97.netdev', '25-dhcp-pd-downstream-veth97.network', '25-dhcp-pd-downstream-veth97-peer.network',
                '25-veth-downstream-veth98.netdev', '25-dhcp-pd-downstream-veth98.network', '25-dhcp-pd-downstream-veth98-peer.network',
                '11-dummy.netdev', '25-dhcp-pd-downstream-test1.network',
                '25-dhcp-pd-downstream-dummy97.network',
                '12-dummy.netdev', '25-dhcp-pd-downstream-dummy98.network',
                '13-dummy.netdev', '25-dhcp-pd-downstream-dummy99.network')

        common.start_networkd()
        self.wait_online(['veth-peer:routable'])
        common.start_isc_dhcpd(conf_file='isc-dhcpd-dhcp6pd.conf', ipv='-6')
        self.wait_online(['veth99:routable', 'test1:routable', 'dummy98:routable', 'dummy99:degraded',
                          'veth97:routable', 'veth97-peer:routable', 'veth98:routable', 'veth98-peer:routable'])

        print('### ip -6 address show dev veth-peer scope global')
        output = common.check_output('ip -6 address show dev veth-peer scope global')
        print(output)
        self.assertIn('inet6 3ffe:501:ffff:100::1/64 scope global', output)

        # Link     Subnet IDs
        # test1:   0x00
        # dummy97: 0x01 (The link will appear later)
        # dummy98: 0x00
        # dummy99: auto -> 0x02 (No address assignment)
        # veth97:  0x08
        # veth98:  0x09
        # veth99:  0x10

        print('### ip -6 address show dev veth99 scope global')
        output = common.check_output('ip -6 address show dev veth99 scope global')
        print(output)
        # IA_NA
        self.assertRegex(output, 'inet6 3ffe:501:ffff:100::[0-9]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)')
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]10:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic')
        # address in IA_PD (Token=eui64)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]10:1034:56ff:fe78:9abc/64 (metric 256 |)scope global dynamic')
        # address in IA_PD (temporary)
        # Note that the temporary addresses may appear after the link enters configured state
        self.wait_address('veth99', 'inet6 3ffe:501:ffff:[2-9a-f]10:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev test1 scope global')
        output = common.check_output('ip -6 address show dev test1 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]00:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('test1', 'inet6 3ffe:501:ffff:[2-9a-f]00:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev dummy98 scope global')
        output = common.check_output('ip -6 address show dev dummy98 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]00:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('dummy98', 'inet6 3ffe:501:ffff:[2-9a-f]00:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev dummy99 scope global')
        output = common.check_output('ip -6 address show dev dummy99 scope global')
        print(output)
        # Assign=no
        self.assertNotRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]02')

        print('### ip -6 address show dev veth97 scope global')
        output = common.check_output('ip -6 address show dev veth97 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]08:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (Token=eui64)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]08:1034:56ff:fe78:9ace/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('veth97', 'inet6 3ffe:501:ffff:[2-9a-f]08:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev veth97-peer scope global')
        output = common.check_output('ip -6 address show dev veth97-peer scope global')
        print(output)
        # NDisc address (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]08:1a:2b:3c:4e/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (Token=eui64)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]08:1034:56ff:fe78:9acf/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (temporary)
        self.wait_address('veth97-peer', 'inet6 3ffe:501:ffff:[2-9a-f]08:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev veth98 scope global')
        output = common.check_output('ip -6 address show dev veth98 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]09:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (Token=eui64)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]09:1034:56ff:fe78:9abe/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('veth98', 'inet6 3ffe:501:ffff:[2-9a-f]09:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev veth98-peer scope global')
        output = common.check_output('ip -6 address show dev veth98-peer scope global')
        print(output)
        # NDisc address (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]09:1a:2b:3c:4e/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (Token=eui64)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]09:1034:56ff:fe78:9abf/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (temporary)
        self.wait_address('veth98-peer', 'inet6 3ffe:501:ffff:[2-9a-f]09:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 route show type unreachable')
        output = common.check_output('ip -6 route show type unreachable')
        print(output)
        self.assertRegex(output, 'unreachable 3ffe:501:ffff:[2-9a-f]00::/56 dev lo proto dhcp')

        print('### ip -6 route show dev veth99')
        output = common.check_output('ip -6 route show dev veth99')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]10::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev test1')
        output = common.check_output('ip -6 route show dev test1')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]00::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev dummy98')
        output = common.check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]00::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev dummy99')
        output = common.check_output('ip -6 route show dev dummy99')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]02::/64 proto dhcp metric [0-9]* expires')

        print('### ip -6 route show dev veth97')
        output = common.check_output('ip -6 route show dev veth97')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]08::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev veth97-peer')
        output = common.check_output('ip -6 route show dev veth97-peer')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]08::/64 proto ra metric [0-9]* expires')

        print('### ip -6 route show dev veth98')
        output = common.check_output('ip -6 route show dev veth98')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]09::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev veth98-peer')
        output = common.check_output('ip -6 route show dev veth98-peer')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]09::/64 proto ra metric [0-9]* expires')

        # Test case for a downstream which appears later
        common.check_output('ip link add dummy97 type dummy')
        self.wait_online(['dummy97:routable'])

        print('### ip -6 address show dev dummy97 scope global')
        output = common.check_output('ip -6 address show dev dummy97 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]01:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('dummy97', 'inet6 3ffe:501:ffff:[2-9a-f]01:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 route show dev dummy97')
        output = common.check_output('ip -6 route show dev dummy97')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]01::/64 proto kernel metric [0-9]* expires')

        # Test case for reconfigure
        common.networkctl_reconfigure('dummy98', 'dummy99')
        self.wait_online(['dummy98:routable', 'dummy99:degraded'])

        print('### ip -6 address show dev dummy98 scope global')
        output = common.check_output('ip -6 address show dev dummy98 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]00:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('dummy98', 'inet6 3ffe:501:ffff:[2-9a-f]00:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev dummy99 scope global')
        output = common.check_output('ip -6 address show dev dummy99 scope global')
        print(output)
        # Assign=no
        self.assertNotRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]02')

        print('### ip -6 route show dev dummy98')
        output = common.check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]00::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev dummy99')
        output = common.check_output('ip -6 route show dev dummy99')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]02::/64 proto dhcp metric [0-9]* expires')

        self.check_netlabel('dummy98', '3ffe:501:ffff:[2-9a-f]00::/64')

    def verify_dhcp4_6rd(self, tunnel_name):
        print('### ip -4 address show dev veth-peer scope global')
        output = common.check_output('ip -4 address show dev veth-peer scope global')
        print(output)
        self.assertIn('inet 10.0.0.1/8 brd 10.255.255.255 scope global veth-peer', output)

        # Link     Subnet IDs
        # test1:   0x00
        # dummy97: 0x01 (The link will appear later)
        # dummy98: 0x00
        # dummy99: auto -> 0x0[23] (No address assignment)
        # 6rd-XXX: auto -> 0x0[23]
        # veth97:  0x08
        # veth98:  0x09
        # veth99:  0x10

        print('### ip -4 address show dev veth99 scope global')
        output = common.check_output('ip -4 address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, 'inet 10.100.100.[0-9]*/8 (metric 1024 |)brd 10.255.255.255 scope global dynamic veth99')

        print('### ip -6 address show dev veth99 scope global')
        output = common.check_output('ip -6 address show dev veth99 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+10:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (Token=eui64)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+10:1034:56ff:fe78:9abc/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        # Note that the temporary addresses may appear after the link enters configured state
        self.wait_address('veth99', 'inet6 2001:db8:6464:[0-9a-f]+10:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev test1 scope global')
        output = common.check_output('ip -6 address show dev test1 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+00:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('test1', 'inet6 2001:db8:6464:[0-9a-f]+00:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev dummy98 scope global')
        output = common.check_output('ip -6 address show dev dummy98 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+00:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('dummy98', 'inet6 2001:db8:6464:[0-9a-f]+00:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev dummy99 scope global')
        output = common.check_output('ip -6 address show dev dummy99 scope global')
        print(output)
        # Assign=no
        self.assertNotRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+0[23]')

        print('### ip -6 address show dev veth97 scope global')
        output = common.check_output('ip -6 address show dev veth97 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+08:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (Token=eui64)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+08:1034:56ff:fe78:9ace/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('veth97', 'inet6 2001:db8:6464:[0-9a-f]+08:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev veth97-peer scope global')
        output = common.check_output('ip -6 address show dev veth97-peer scope global')
        print(output)
        # NDisc address (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+08:1a:2b:3c:4e/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (Token=eui64)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+08:1034:56ff:fe78:9acf/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (temporary)
        self.wait_address('veth97-peer', 'inet6 2001:db8:6464:[0-9a-f]+08:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev veth98 scope global')
        output = common.check_output('ip -6 address show dev veth98 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+09:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (Token=eui64)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+09:1034:56ff:fe78:9abe/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('veth98', 'inet6 2001:db8:6464:[0-9a-f]+09:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev veth98-peer scope global')
        output = common.check_output('ip -6 address show dev veth98-peer scope global')
        print(output)
        # NDisc address (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+09:1a:2b:3c:4e/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (Token=eui64)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+09:1034:56ff:fe78:9abf/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (temporary)
        self.wait_address('veth98-peer', 'inet6 2001:db8:6464:[0-9a-f]+09:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 route show type unreachable')
        output = common.check_output('ip -6 route show type unreachable')
        print(output)
        self.assertRegex(output, 'unreachable 2001:db8:6464:[0-9a-f]+00::/56 dev lo proto dhcp')

        print('### ip -6 route show dev veth99')
        output = common.check_output('ip -6 route show dev veth99')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+10::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev test1')
        output = common.check_output('ip -6 route show dev test1')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+00::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev dummy98')
        output = common.check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+00::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev dummy99')
        output = common.check_output('ip -6 route show dev dummy99')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+0[23]::/64 proto dhcp metric [0-9]* expires')

        print('### ip -6 route show dev veth97')
        output = common.check_output('ip -6 route show dev veth97')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+08::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev veth97-peer')
        output = common.check_output('ip -6 route show dev veth97-peer')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+08::/64 proto ra metric [0-9]* expires')

        print('### ip -6 route show dev veth98')
        output = common.check_output('ip -6 route show dev veth98')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+09::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev veth98-peer')
        output = common.check_output('ip -6 route show dev veth98-peer')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+09::/64 proto ra metric [0-9]* expires')

        print('### ip -6 address show dev dummy97 scope global')
        output = common.check_output('ip -6 address show dev dummy97 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+01:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('dummy97', 'inet6 2001:db8:6464:[0-9a-f]+01:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 route show dev dummy97')
        output = common.check_output('ip -6 route show dev dummy97')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+01::/64 proto kernel metric [0-9]* expires')

        print(f'### ip -d link show dev {tunnel_name}')
        output = common.check_output(f'ip -d link show dev {tunnel_name}')
        print(output)
        self.assertIn('link/sit 10.100.100.', output)
        self.assertIn('local 10.100.100.', output)
        self.assertIn('ttl 64', output)
        self.assertIn('6rd-prefix 2001:db8::/32', output)
        self.assertIn('6rd-relay_prefix 10.0.0.0/8', output)

        print(f'### ip -6 address show dev {tunnel_name}')
        output = common.check_output(f'ip -6 address show dev {tunnel_name}')
        print(output)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+0[23]:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global dynamic')
        self.assertRegex(output, 'inet6 ::10.100.100.[0-9]+/96 scope global')

        print(f'### ip -6 route show dev {tunnel_name}')
        output = common.check_output(f'ip -6 route show dev {tunnel_name}')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+0[23]::/64 proto kernel metric [0-9]* expires')
        self.assertRegex(output, '::/96 proto kernel metric [0-9]*')

        print('### ip -6 route show default')
        output = common.check_output('ip -6 route show default')
        print(output)
        self.assertIn('default', output)
        self.assertIn(f'via ::10.0.0.1 dev {tunnel_name}', output)

    def test_dhcp4_6rd(self):
        common.copy_network_unit(
                '25-veth.netdev', '25-dhcp4-6rd-server.network', '25-dhcp4-6rd-upstream.network',
                '25-veth-downstream-veth97.netdev', '25-dhcp-pd-downstream-veth97.network', '25-dhcp-pd-downstream-veth97-peer.network',
                '25-veth-downstream-veth98.netdev', '25-dhcp-pd-downstream-veth98.network', '25-dhcp-pd-downstream-veth98-peer.network',
                '11-dummy.netdev', '25-dhcp-pd-downstream-test1.network',
                '25-dhcp-pd-downstream-dummy97.network',
                '12-dummy.netdev', '25-dhcp-pd-downstream-dummy98.network',
                '13-dummy.netdev', '25-dhcp-pd-downstream-dummy99.network',
                '80-6rd-tunnel.network')

        common.start_networkd()
        self.wait_online(['veth-peer:routable'])

        # ipv4masklen: 8
        # 6rd-prefix: 2001:db8::/32
        # br-addresss: 10.0.0.1

        common.start_dnsmasq(
                '--dhcp-option=212,08:20:20:01:0d:b8:00:00:00:00:00:00:00:00:00:00:00:00:0a:00:00:01',
                ipv4_range='10.100.100.100,10.100.100.200',
                ipv4_router='10.0.0.1')
        self.wait_online(['veth99:routable', 'test1:routable', 'dummy98:routable', 'dummy99:degraded',
                          'veth97:routable', 'veth97-peer:routable', 'veth98:routable', 'veth98-peer:routable'])

        # Test case for a downstream which appears later
        common.check_output('ip link add dummy97 type dummy')
        self.wait_online(['dummy97:routable'])

        # Find tunnel name
        tunnel_name = None
        for name in os.listdir('/sys/class/net/'):
            if name.startswith('6rd-'):
                tunnel_name = name
                break

        self.wait_online([f'{tunnel_name}:routable'])

        self.verify_dhcp4_6rd(tunnel_name)

        # Test case for reconfigure
        common.networkctl_reconfigure('dummy98', 'dummy99')
        self.wait_online(['dummy98:routable', 'dummy99:degraded'])

        self.verify_dhcp4_6rd(tunnel_name)

        print('Wait for the DHCP lease to be renewed/rebind')
        time.sleep(120)

        self.wait_online(['veth99:routable', 'test1:routable', 'dummy97:routable', 'dummy98:routable', 'dummy99:degraded',
                          'veth97:routable', 'veth97-peer:routable', 'veth98:routable', 'veth98-peer:routable'])

        self.verify_dhcp4_6rd(tunnel_name)
