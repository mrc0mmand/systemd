# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import unittest

import common


class NetworkdIPv6PrefixTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_ipv6_route_prefix(self):
        common.copy_network_unit(
                '25-veth.netdev', '25-ipv6ra-prefix-client.network', '25-ipv6ra-prefix.network',
                '12-dummy.netdev', '25-ipv6ra-uplink.network')

        common.start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable', 'dummy98:routable'])

        output = common.check_output('ip address show dev veth-peer')
        print(output)
        self.assertIn('inet6 2001:db8:0:1:', output)
        self.assertNotIn('inet6 2001:db8:0:2:', output)
        self.assertNotIn('inet6 2001:db8:0:3:', output)

        output = common.check_output('ip -6 route show dev veth-peer')
        print(output)
        self.assertIn('2001:db8:0:1::/64 proto ra', output)
        self.assertNotIn('2001:db8:0:2::/64 proto ra', output)
        self.assertNotIn('2001:db8:0:3::/64 proto ra', output)
        self.assertIn('2001:db0:fff::/64 via ', output)
        self.assertNotIn('2001:db1:fff::/64 via ', output)
        self.assertNotIn('2001:db2:fff::/64 via ', output)

        output = common.check_output('ip address show dev veth99')
        print(output)
        self.assertNotIn('inet6 2001:db8:0:1:', output)
        self.assertIn('inet6 2001:db8:0:2:1a:2b:3c:4d', output)
        self.assertIn('inet6 2001:db8:0:2:fa:de:ca:fe', output)
        self.assertNotIn('inet6 2001:db8:0:3:', output)

        output = common.check_output(*common.resolvectl_cmd, 'dns', 'veth-peer', env=common.env)
        print(output)
        self.assertRegex(output, '2001:db8:1:1::2')

        output = common.check_output(*common.resolvectl_cmd, 'domain', 'veth-peer', env=common.env)
        print(output)
        self.assertIn('example.com', output)

        # TODO: check json string
        common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

    def test_ipv6_route_prefix_deny_list(self):
        common.copy_network_unit(
                '25-veth.netdev', '25-ipv6ra-prefix-client-deny-list.network', '25-ipv6ra-prefix.network',
                '12-dummy.netdev', '25-ipv6ra-uplink.network')

        common.start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable', 'dummy98:routable'])

        output = common.check_output('ip address show dev veth-peer')
        print(output)
        self.assertIn('inet6 2001:db8:0:1:', output)
        self.assertNotIn('inet6 2001:db8:0:2:', output)

        output = common.check_output('ip -6 route show dev veth-peer')
        print(output)
        self.assertIn('2001:db8:0:1::/64 proto ra', output)
        self.assertNotIn('2001:db8:0:2::/64 proto ra', output)
        self.assertIn('2001:db0:fff::/64 via ', output)
        self.assertNotIn('2001:db1:fff::/64 via ', output)

        output = common.check_output('ip address show dev veth99')
        print(output)
        self.assertNotIn('inet6 2001:db8:0:1:', output)
        self.assertIn('inet6 2001:db8:0:2:', output)

        output = common.check_output(*common.resolvectl_cmd, 'dns', 'veth-peer', env=common.env)
        print(output)
        self.assertRegex(output, '2001:db8:1:1::2')

        output = common.check_output(*common.resolvectl_cmd, 'domain', 'veth-peer', env=common.env)
        print(output)
        self.assertIn('example.com', output)
