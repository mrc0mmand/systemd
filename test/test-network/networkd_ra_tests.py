# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import os
import unittest

import common


class NetworkdRATests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_ipv6_prefix_delegation(self):
        common.copy_network_unit('25-veth.netdev', '25-ipv6-prefix.network', '25-ipv6-prefix-veth.network')
        common.start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:degraded'])

        output = common.check_output(*common.resolvectl_cmd, 'dns', 'veth99', env=common.env)
        print(output)
        self.assertRegex(output, 'fe80::')
        self.assertRegex(output, '2002:da8:1::1')

        output = common.check_output(*common.resolvectl_cmd, 'domain', 'veth99', env=common.env)
        print(output)
        self.assertIn('hogehoge.test', output)

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'veth99', env=common.env)
        print(output)
        self.assertRegex(output, '2002:da8:1:0')

        self.check_netlabel('veth99', '2002:da8:1::/64')
        self.check_netlabel('veth99', '2002:da8:2::/64')

    def test_ipv6_token_static(self):
        common.copy_network_unit('25-veth.netdev', '25-ipv6-prefix.network', '25-ipv6-prefix-veth-token-static.network')
        common.start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:degraded'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'veth99', env=common.env)
        print(output)
        self.assertRegex(output, '2002:da8:1:0:1a:2b:3c:4d')
        self.assertRegex(output, '2002:da8:1:0:fa:de:ca:fe')
        self.assertRegex(output, '2002:da8:2:0:1a:2b:3c:4d')
        self.assertRegex(output, '2002:da8:2:0:fa:de:ca:fe')

    def test_ipv6_token_prefixstable(self):
        common.copy_network_unit('25-veth.netdev', '25-ipv6-prefix.network', '25-ipv6-prefix-veth-token-prefixstable.network')
        common.start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:degraded'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'veth99', env=common.env)
        print(output)
        self.assertIn('2002:da8:1:0:b47e:7975:fc7a:7d6e', output)
        self.assertIn('2002:da8:2:0:1034:56ff:fe78:9abc', output) # EUI64

    def test_ipv6_token_prefixstable_without_address(self):
        common.copy_network_unit('25-veth.netdev', '25-ipv6-prefix.network', '25-ipv6-prefix-veth-token-prefixstable-without-address.network')
        common.start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:degraded'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'veth99', env=common.env)
        print(output)
        self.assertIn('2002:da8:1:0:b47e:7975:fc7a:7d6e', output)
        self.assertIn('2002:da8:2:0:f689:561a:8eda:7443', output)

    def test_router_preference(self):
        common.copy_network_unit(
                '25-veth-client.netdev',
                '25-veth-router-high.netdev',
                '25-veth-router-low.netdev',
                '26-bridge.netdev',
                '25-veth-bridge.network',
                '25-veth-client.network',
                '25-veth-router-high.network',
                '25-veth-router-low.network',
                '25-bridge99.network')
        common.start_networkd()
        self.wait_online(['client-p:enslaved',
                          'router-high:degraded', 'router-high-p:enslaved',
                          'router-low:degraded', 'router-low-p:enslaved',
                          'bridge99:routable'])

        common.networkctl_reconfigure('client')
        self.wait_online(['client:routable'])

        self.wait_address('client', '2002:da8:1:99:1034:56ff:fe78:9a00/64', ipv='-6', timeout_sec=10)
        self.wait_address('client', '2002:da8:1:98:1034:56ff:fe78:9a00/64', ipv='-6', timeout_sec=10)
        self.wait_route('client', 'default via fe80::1034:56ff:fe78:9a99 proto ra metric 512', ipv='-6', timeout_sec=10)
        self.wait_route('client', 'default via fe80::1034:56ff:fe78:9a98 proto ra metric 2048', ipv='-6', timeout_sec=10)

        output = common.check_output('ip -6 route show dev client default via fe80::1034:56ff:fe78:9a99')
        print(output)
        self.assertIn('pref high', output)
        output = common.check_output('ip -6 route show dev client default via fe80::1034:56ff:fe78:9a98')
        print(output)
        self.assertIn('pref low', output)

        with open(os.path.join(common.network_unit_dir, '25-veth-client.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[Link]\nMACAddress=12:34:56:78:9a:01\n[IPv6AcceptRA]\nRouteMetric=100:200:300\n')

        common.networkctl_reload()
        self.wait_online(['client:routable'])

        self.wait_address('client', '2002:da8:1:99:1034:56ff:fe78:9a01/64', ipv='-6', timeout_sec=10)
        self.wait_address('client', '2002:da8:1:98:1034:56ff:fe78:9a01/64', ipv='-6', timeout_sec=10)
        self.wait_route('client', 'default via fe80::1034:56ff:fe78:9a99 proto ra metric 100', ipv='-6', timeout_sec=10)
        self.wait_route('client', 'default via fe80::1034:56ff:fe78:9a98 proto ra metric 300', ipv='-6', timeout_sec=10)

        output = common.check_output('ip -6 route show dev client default via fe80::1034:56ff:fe78:9a99')
        print(output)
        self.assertIn('pref high', output)
        output = common.check_output('ip -6 route show dev client default via fe80::1034:56ff:fe78:9a98')
        print(output)
        self.assertIn('pref low', output)
