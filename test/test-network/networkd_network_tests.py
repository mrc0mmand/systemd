# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import time
import unittest

import common


class NetworkdNetworkTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_address_static(self):
        # test for #22515. The address will be removed and replaced with /64 prefix.
        common.check_output('ip link add dummy98 type dummy')
        common.check_output('ip link set dev dummy98 up')
        common.check_output('ip -6 address add 2001:db8:0:f101::15/128 dev dummy98')
        self.wait_address('dummy98', '2001:db8:0:f101::15/128', ipv='-6')
        common.check_output('ip -4 address add 10.3.2.3/16 brd 10.3.255.250 scope global label dummy98:hoge dev dummy98')
        self.wait_address('dummy98', '10.3.2.3/16 brd 10.3.255.250', ipv='-4')

        common.copy_network_unit('25-address-static.network', '12-dummy.netdev')
        common.start_networkd()

        self.wait_online(['dummy98:routable'])

        output = common.check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertIn('inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98', output)
        self.assertIn('inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98', output)
        self.assertIn('inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98', output)
        self.assertIn('inet 10.7.8.9/16 brd 10.7.255.255 scope link deprecated dummy98', output)
        self.assertIn('inet 10.8.8.1/16 scope global dummy98', output)
        self.assertIn('inet 10.8.8.2/16 brd 10.8.8.128 scope global secondary dummy98', output)
        self.assertRegex(output, 'inet 10.9.0.1/16 (metric 128 |)brd 10.9.255.255 scope global dummy98')

        # test for ENOBUFS issue #17012
        for i in range(1, 254):
            self.assertIn(f'inet 10.3.3.{i}/16 brd 10.3.255.255', output)

        # invalid sections
        self.assertNotIn('10.10.0.1/16', output)
        self.assertNotIn('10.10.0.2/16', output)

        output = common.check_output('ip -4 address show dev dummy98 label 32')
        self.assertIn('inet 10.3.2.3/16 brd 10.3.255.255 scope global 32', output)

        output = common.check_output('ip -4 address show dev dummy98 label 33')
        self.assertIn('inet 10.4.2.3 peer 10.4.2.4/16 scope global 33', output)

        output = common.check_output('ip -4 address show dev dummy98 label 34')
        self.assertRegex(output, r'inet 192.168.[0-9]*.1/24 brd 192.168.[0-9]*.255 scope global 34')

        output = common.check_output('ip -4 address show dev dummy98 label 35')
        self.assertRegex(output, r'inet 172.[0-9]*.0.1/16 brd 172.[0-9]*.255.255 scope global 35')

        output = common.check_output('ip -4 route show dev dummy98')
        print(output)
        self.assertIn('10.9.0.0/16 proto kernel scope link src 10.9.0.1 metric 128', output)

        output = common.check_output('ip -6 address show dev dummy98')
        print(output)
        self.assertIn('inet6 2001:db8:0:f101::15/64 scope global', output)
        self.assertIn('inet6 2001:db8:0:f101::16/64 scope global', output)
        self.assertIn('inet6 2001:db8:0:f102::15/64 scope global', output)
        self.assertIn('inet6 2001:db8:0:f102::16/64 scope global', output)
        self.assertIn('inet6 2001:db8:0:f103::20 peer 2001:db8:0:f103::10/128 scope global', output)
        self.assertIn('inet6 2001:db8:1:f101::1/64 scope global deprecated', output)
        self.assertRegex(output, r'inet6 fd[0-9a-f:]*1/64 scope global')

        self.check_netlabel('dummy98', r'10\.4\.3\.0/24')

        # Tests for #20891.
        # 1. set preferred lifetime forever to drop the deprecated flag for testing #20891.
        common.check_output('ip address change 10.7.8.9/16 dev dummy98 preferred_lft forever')
        common.check_output('ip address change 2001:db8:1:f101::1/64 dev dummy98 preferred_lft forever')
        output = common.check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertNotIn('deprecated', output)
        output = common.check_output('ip -6 address show dev dummy98')
        print(output)
        self.assertNotIn('deprecated', output)

        # 2. reconfigure the interface.
        common.networkctl_reconfigure('dummy98')
        self.wait_online(['dummy98:routable'])

        # 3. check the deprecated flag is set for the address configured with PreferredLifetime=0
        output = common.check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertIn('inet 10.7.8.9/16 brd 10.7.255.255 scope link deprecated dummy98', output)
        output = common.check_output('ip -6 address show dev dummy98')
        print(output)
        self.assertIn('inet6 2001:db8:1:f101::1/64 scope global deprecated', output)

        # test for ENOBUFS issue #17012
        output = common.check_output('ip -4 address show dev dummy98')
        for i in range(1, 254):
            self.assertIn(f'inet 10.3.3.{i}/16 brd 10.3.255.255', output)

        # TODO: check json string
        common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

    def test_address_ipv4acd(self):
        common.check_output('ip netns add ns99')
        common.check_output('ip link add veth99 type veth peer veth-peer')
        common.check_output('ip link set veth-peer netns ns99')
        common.check_output('ip link set veth99 up')
        common.check_output('ip netns exec ns99 ip link set veth-peer up')
        common.check_output('ip netns exec ns99 ip address add 192.168.100.10/24 dev veth-peer')

        common.copy_network_unit('25-address-ipv4acd-veth99.network', copy_dropins=False)
        common.start_networkd()
        self.wait_online(['veth99:routable'])

        output = common.check_output('ip -4 address show dev veth99')
        print(output)
        self.assertNotIn('192.168.100.10/24', output)
        self.assertIn('192.168.100.11/24', output)

        common.copy_network_unit('25-address-ipv4acd-veth99.network.d/conflict-address.conf')
        common.networkctl_reload()
        self.wait_operstate('veth99', operstate='routable', setup_state='configuring', setup_timeout=10)

        output = common.check_output('ip -4 address show dev veth99')
        print(output)
        self.assertNotIn('192.168.100.10/24', output)
        self.assertIn('192.168.100.11/24', output)

    def test_address_peer_ipv4(self):
        # test for issue #17304
        common.copy_network_unit('25-address-peer-ipv4.network', '12-dummy.netdev')

        for trial in range(2):
            if trial == 0:
                common.start_networkd()
            else:
                common.start_networkd()

            self.wait_online(['dummy98:routable'])

            output = common.check_output('ip -4 address show dev dummy98')
            self.assertIn('inet 100.64.0.1 peer 100.64.0.2/32 scope global', output)

    @common.expectedFailureIfModuleIsNotAvailable('vrf')
    def test_prefix_route(self):
        common.copy_network_unit(
                '25-prefix-route-with-vrf.network', '12-dummy.netdev',
                '25-prefix-route-without-vrf.network', '11-dummy.netdev',
                '25-vrf.netdev', '25-vrf.network')
        for trial in range(2):
            if trial == 0:
                common.start_networkd()
            else:
                common.start_networkd()

            self.wait_online(['dummy98:routable', 'test1:routable', 'vrf99:carrier'])

            output = common.check_output('ip route show table 42 dev dummy98')
            print('### ip route show table 42 dev dummy98')
            print(output)
            self.assertRegex(output, 'local 10.20.22.1 proto kernel scope host src 10.20.22.1')
            self.assertRegex(output, '10.20.33.0/24 proto kernel scope link src 10.20.33.1')
            self.assertRegex(output, 'local 10.20.33.1 proto kernel scope host src 10.20.33.1')
            self.assertRegex(output, 'broadcast 10.20.33.255 proto kernel scope link src 10.20.33.1')
            self.assertRegex(output, 'local 10.20.44.1 proto kernel scope host src 10.20.44.1')
            self.assertRegex(output, 'local 10.20.55.1 proto kernel scope host src 10.20.55.1')
            self.assertRegex(output, 'broadcast 10.20.55.255 proto kernel scope link src 10.20.55.1')
            output = common.check_output('ip -6 route show table 42 dev dummy98')
            print('### ip -6 route show table 42 dev dummy98')
            print(output)
            if trial == 0:
                # Kernel's bug?
                self.assertRegex(output, 'local fdde:11:22::1 proto kernel metric 0 pref medium')
            #self.assertRegex(output, 'fdde:11:22::1 proto kernel metric 256 pref medium')
            self.assertRegex(output, 'local fdde:11:33::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'fdde:11:33::/64 proto kernel metric 256 pref medium')
            self.assertRegex(output, 'local fdde:11:44::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'local fdde:11:55::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'fe80::/64 proto kernel metric 256 pref medium')
            self.assertRegex(output, 'ff00::/8 (proto kernel )?metric 256 (linkdown )?pref medium')

            print()

            output = common.check_output('ip route show dev test1')
            print('### ip route show dev test1')
            print(output)
            self.assertRegex(output, '10.21.33.0/24 proto kernel scope link src 10.21.33.1')
            output = common.check_output('ip route show table local dev test1')
            print('### ip route show table local dev test1')
            print(output)
            self.assertRegex(output, 'local 10.21.22.1 proto kernel scope host src 10.21.22.1')
            self.assertRegex(output, 'local 10.21.33.1 proto kernel scope host src 10.21.33.1')
            self.assertRegex(output, 'broadcast 10.21.33.255 proto kernel scope link src 10.21.33.1')
            self.assertRegex(output, 'local 10.21.44.1 proto kernel scope host src 10.21.44.1')
            self.assertRegex(output, 'local 10.21.55.1 proto kernel scope host src 10.21.55.1')
            self.assertRegex(output, 'broadcast 10.21.55.255 proto kernel scope link src 10.21.55.1')
            output = common.check_output('ip -6 route show dev test1')
            print('### ip -6 route show dev test1')
            print(output)
            self.assertRegex(output, 'fdde:12:22::1 proto kernel metric 256 pref medium')
            self.assertRegex(output, 'fdde:12:33::/64 proto kernel metric 256 pref medium')
            self.assertRegex(output, 'fe80::/64 proto kernel metric 256 pref medium')
            output = common.check_output('ip -6 route show table local dev test1')
            print('### ip -6 route show table local dev test1')
            print(output)
            self.assertRegex(output, 'local fdde:12:22::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'local fdde:12:33::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'local fdde:12:44::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'local fdde:12:55::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'ff00::/8 (proto kernel )?metric 256 (linkdown )?pref medium')

    def test_configure_without_carrier(self):
        common.copy_network_unit('11-dummy.netdev')
        common.start_networkd()
        self.wait_operstate('test1', 'off', '')
        common.check_output('ip link set dev test1 up carrier off')

        common.copy_network_unit('25-test1.network.d/configure-without-carrier.conf', copy_dropins=False)
        common.start_networkd()
        self.wait_online(['test1:no-carrier'])

        carrier_map = {'on': '1', 'off': '0'}
        routable_map = {'on': 'routable', 'off': 'no-carrier'}
        for carrier in ['off', 'on', 'off']:
            with self.subTest(carrier=carrier):
                if carrier_map[carrier] != common.read_link_attr('test1', 'carrier'):
                    common.check_output(f'ip link set dev test1 carrier {carrier}')
                self.wait_online([f'test1:{routable_map[carrier]}:{routable_map[carrier]}'])

                output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'test1', env=common.env)
                print(output)
                self.assertRegex(output, '192.168.0.15')
                self.assertRegex(output, '192.168.0.1')
                self.assertRegex(output, routable_map[carrier])

    def test_configure_without_carrier_yes_ignore_carrier_loss_no(self):
        common.copy_network_unit('11-dummy.netdev')
        common.start_networkd()
        self.wait_operstate('test1', 'off', '')
        common.check_output('ip link set dev test1 up carrier off')

        common.copy_network_unit('25-test1.network')
        common.start_networkd()
        self.wait_online(['test1:no-carrier'])

        carrier_map = {'on': '1', 'off': '0'}
        routable_map = {'on': 'routable', 'off': 'no-carrier'}
        for (carrier, have_config) in [('off', True), ('on', True), ('off', False)]:
            with self.subTest(carrier=carrier, have_config=have_config):
                if carrier_map[carrier] != common.read_link_attr('test1', 'carrier'):
                    common.check_output(f'ip link set dev test1 carrier {carrier}')
                self.wait_online([f'test1:{routable_map[carrier]}:{routable_map[carrier]}'])

                output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'test1', env=common.env)
                print(output)
                if have_config:
                    self.assertRegex(output, '192.168.0.15')
                    self.assertRegex(output, '192.168.0.1')
                else:
                    self.assertNotRegex(output, '192.168.0.15')
                    self.assertNotRegex(output, '192.168.0.1')
                self.assertRegex(output, routable_map[carrier])

    def test_routing_policy_rule(self):
        common.copy_network_unit('25-routing-policy-rule-test1.network', '11-dummy.netdev')
        common.start_networkd()
        self.wait_online(['test1:degraded'])

        output = common.check_output('ip rule list iif test1 priority 111')
        print(output)
        self.assertRegex(output, '111:')
        self.assertRegex(output, 'from 192.168.100.18')
        self.assertRegex(output, r'tos (0x08|throughput)\s')
        self.assertRegex(output, 'iif test1')
        self.assertRegex(output, 'oif test1')
        self.assertRegex(output, 'lookup 7')

        output = common.check_output('ip rule list iif test1 priority 101')
        print(output)
        self.assertRegex(output, '101:')
        self.assertRegex(output, 'from all')
        self.assertRegex(output, 'iif test1')
        self.assertRegex(output, 'lookup 9')

        output = common.check_output('ip -6 rule list iif test1 priority 100')
        print(output)
        self.assertRegex(output, '100:')
        self.assertRegex(output, 'from all')
        self.assertRegex(output, 'iif test1')
        self.assertRegex(output, 'lookup 8')

        output = common.check_output('ip rule list iif test1 priority 102')
        print(output)
        self.assertRegex(output, '102:')
        self.assertRegex(output, 'from 0.0.0.0/8')
        self.assertRegex(output, 'iif test1')
        self.assertRegex(output, 'lookup 10')

        # TODO: check json string
        common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

    def test_routing_policy_rule_issue_11280(self):
        common.copy_network_unit(
                '25-routing-policy-rule-test1.network', '11-dummy.netdev',
                '25-routing-policy-rule-dummy98.network', '12-dummy.netdev')

        for trial in range(3):
            common.restart_networkd(show_logs=(trial > 0))
            self.wait_online(['test1:degraded', 'dummy98:degraded'])

            output = common.check_output('ip rule list table 7')
            print(output)
            self.assertRegex(output, '111:	from 192.168.100.18 tos (0x08|throughput) iif test1 oif test1 lookup 7')

            output = common.check_output('ip rule list table 8')
            print(output)
            self.assertRegex(output, '112:	from 192.168.101.18 tos (0x08|throughput) iif dummy98 oif dummy98 lookup 8')

    def test_routing_policy_rule_reconfigure(self):
        common.copy_network_unit('25-routing-policy-rule-reconfigure2.network', '11-dummy.netdev')
        common.start_networkd()
        self.wait_online(['test1:degraded'])

        output = common.check_output('ip rule list table 1011')
        print(output)
        self.assertIn('10111:	from all fwmark 0x3f3 lookup 1011', output)
        self.assertIn('10112:	from all oif test1 lookup 1011', output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)
        self.assertIn('10114:	from 192.168.8.254 lookup 1011', output)

        output = common.check_output('ip -6 rule list table 1011')
        print(output)
        self.assertIn('10112:	from all oif test1 lookup 1011', output)

        common.copy_network_unit('25-routing-policy-rule-reconfigure1.network', '11-dummy.netdev')
        common.networkctl_reload()
        self.wait_online(['test1:degraded'])

        output = common.check_output('ip rule list table 1011')
        print(output)
        self.assertIn('10111:	from all fwmark 0x3f3 lookup 1011', output)
        self.assertIn('10112:	from all oif test1 lookup 1011', output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)
        self.assertIn('10114:	from 192.168.8.254 lookup 1011', output)

        output = common.check_output('ip -6 rule list table 1011')
        print(output)
        self.assertNotIn('10112:	from all oif test1 lookup 1011', output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)

        common.call('ip rule delete priority 10111')
        common.call('ip rule delete priority 10112')
        common.call('ip rule delete priority 10113')
        common.call('ip rule delete priority 10114')
        common.call('ip -6 rule delete priority 10113')

        output = common.check_output('ip rule list table 1011')
        print(output)
        self.assertEqual(output, '')

        output = common.check_output('ip -6 rule list table 1011')
        print(output)
        self.assertEqual(output, '')

        common.networkctl_reconfigure('test1')
        self.wait_online(['test1:degraded'])

        output = common.check_output('ip rule list table 1011')
        print(output)
        self.assertIn('10111:	from all fwmark 0x3f3 lookup 1011', output)
        self.assertIn('10112:	from all oif test1 lookup 1011', output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)
        self.assertIn('10114:	from 192.168.8.254 lookup 1011', output)

        output = common.check_output('ip -6 rule list table 1011')
        print(output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)

    @common.expectedFailureIfRoutingPolicyPortRangeIsNotAvailable()
    def test_routing_policy_rule_port_range(self):
        common.copy_network_unit('25-fibrule-port-range.network', '11-dummy.netdev')
        common.start_networkd()
        self.wait_online(['test1:degraded'])

        output = common.check_output('ip rule')
        print(output)
        self.assertRegex(output, '111')
        self.assertRegex(output, 'from 192.168.100.18')
        self.assertRegex(output, '1123-1150')
        self.assertRegex(output, '3224-3290')
        self.assertRegex(output, 'tcp')
        self.assertRegex(output, 'lookup 7')

    @common.expectedFailureIfRoutingPolicyIPProtoIsNotAvailable()
    def test_routing_policy_rule_invert(self):
        common.copy_network_unit('25-fibrule-invert.network', '11-dummy.netdev')
        common.start_networkd()
        self.wait_online(['test1:degraded'])

        output = common.check_output('ip rule')
        print(output)
        self.assertRegex(output, '111')
        self.assertRegex(output, 'not.*?from.*?192.168.100.18')
        self.assertRegex(output, 'tcp')
        self.assertRegex(output, 'lookup 7')

    @common.expectedFailureIfRoutingPolicyUIDRangeIsNotAvailable()
    def test_routing_policy_rule_uidrange(self):
        common.copy_network_unit('25-fibrule-uidrange.network', '11-dummy.netdev')
        common.start_networkd()
        self.wait_online(['test1:degraded'])

        output = common.check_output('ip rule')
        print(output)
        self.assertRegex(output, '111')
        self.assertRegex(output, 'from 192.168.100.18')
        self.assertRegex(output, 'lookup 7')
        self.assertRegex(output, 'uidrange 100-200')

    def _test_route_static(self, manage_foreign_routes):
        if not manage_foreign_routes:
            common.copy_networkd_conf_dropin('networkd-manage-foreign-routes-no.conf')

        common.copy_network_unit('25-route-static.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'dummy98', env=common.env)
        print(output)

        print('### ip -6 route show dev dummy98')
        output = common.check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertIn('2001:1234:5:8fff:ff:ff:ff:ff proto static', output)
        self.assertIn('2001:1234:5:8f63::1 proto kernel', output)
        self.assertIn('2001:1234:5:afff:ff:ff:ff:ff via fe80:0:222:4dff:ff:ff:ff:ff proto static', output)

        print('### ip -6 route show default')
        output = common.check_output('ip -6 route show default')
        print(output)
        self.assertIn('default', output)
        self.assertIn('via 2001:1234:5:8fff:ff:ff:ff:ff', output)

        print('### ip -4 route show dev dummy98')
        output = common.check_output('ip -4 route show dev dummy98')
        print(output)
        self.assertIn('149.10.124.48/28 proto kernel scope link src 149.10.124.58', output)
        self.assertIn('149.10.124.64 proto static scope link', output)
        self.assertIn('169.254.0.0/16 proto static scope link metric 2048', output)
        self.assertIn('192.168.1.1 proto static scope link initcwnd 20', output)
        self.assertIn('192.168.1.2 proto static scope link initrwnd 30', output)
        self.assertIn('192.168.1.3 proto static scope link advmss 30', output)
        self.assertIn('multicast 149.10.123.4 proto static', output)

        print('### ip -4 route show dev dummy98 default')
        output = common.check_output('ip -4 route show dev dummy98 default')
        print(output)
        self.assertIn('default via 149.10.125.65 proto static onlink', output)
        self.assertIn('default via 149.10.124.64 proto static', output)
        self.assertIn('default proto static', output)

        print('### ip -4 route show table local dev dummy98')
        output = common.check_output('ip -4 route show table local dev dummy98')
        print(output)
        self.assertIn('local 149.10.123.1 proto static scope host', output)
        self.assertIn('anycast 149.10.123.2 proto static scope link', output)
        self.assertIn('broadcast 149.10.123.3 proto static scope link', output)

        print('### ip -4 route show type blackhole')
        output = common.check_output('ip -4 route show type blackhole')
        print(output)
        self.assertIn('blackhole 202.54.1.2 proto static', output)

        print('### ip -4 route show type unreachable')
        output = common.check_output('ip -4 route show type unreachable')
        print(output)
        self.assertIn('unreachable 202.54.1.3 proto static', output)

        print('### ip -4 route show type prohibit')
        output = common.check_output('ip -4 route show type prohibit')
        print(output)
        self.assertIn('prohibit 202.54.1.4 proto static', output)

        print('### ip -6 route show type blackhole')
        output = common.check_output('ip -6 route show type blackhole')
        print(output)
        self.assertIn('blackhole 2001:1234:5678::2 dev lo proto static', output)

        print('### ip -6 route show type unreachable')
        output = common.check_output('ip -6 route show type unreachable')
        print(output)
        self.assertIn('unreachable 2001:1234:5678::3 dev lo proto static', output)

        print('### ip -6 route show type prohibit')
        output = common.check_output('ip -6 route show type prohibit')
        print(output)
        self.assertIn('prohibit 2001:1234:5678::4 dev lo proto static', output)

        print('### ip route show 192.168.10.1')
        output = common.check_output('ip route show 192.168.10.1')
        print(output)
        self.assertIn('192.168.10.1 proto static', output)
        self.assertIn('nexthop via 149.10.124.59 dev dummy98 weight 10', output)
        self.assertIn('nexthop via 149.10.124.60 dev dummy98 weight 5', output)

        print('### ip route show 192.168.10.2')
        output = common.check_output('ip route show 192.168.10.2')
        print(output)
        # old ip command does not show IPv6 gateways...
        self.assertIn('192.168.10.2 proto static', output)
        self.assertIn('nexthop', output)
        self.assertIn('dev dummy98 weight 10', output)
        self.assertIn('dev dummy98 weight 5', output)

        print('### ip -6 route show 2001:1234:5:7fff:ff:ff:ff:ff')
        output = common.check_output('ip -6 route show 2001:1234:5:7fff:ff:ff:ff:ff')
        print(output)
        # old ip command does not show 'nexthop' keyword and weight...
        self.assertIn('2001:1234:5:7fff:ff:ff:ff:ff', output)
        self.assertIn('via 2001:1234:5:8fff:ff:ff:ff:ff dev dummy98', output)
        self.assertIn('via 2001:1234:5:9fff:ff:ff:ff:ff dev dummy98', output)

        # TODO: check json string
        common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

        common.copy_network_unit('25-address-static.network')
        common.networkctl_reload()
        self.wait_online(['dummy98:routable'])

        # check all routes managed by Manager are removed
        print('### ip -4 route show type blackhole')
        output = common.check_output('ip -4 route show type blackhole')
        print(output)
        self.assertEqual(output, '')

        print('### ip -4 route show type unreachable')
        output = common.check_output('ip -4 route show type unreachable')
        print(output)
        self.assertEqual(output, '')

        print('### ip -4 route show type prohibit')
        output = common.check_output('ip -4 route show type prohibit')
        print(output)
        self.assertEqual(output, '')

        print('### ip -6 route show type blackhole')
        output = common.check_output('ip -6 route show type blackhole')
        print(output)
        self.assertEqual(output, '')

        print('### ip -6 route show type unreachable')
        output = common.check_output('ip -6 route show type unreachable')
        print(output)
        self.assertEqual(output, '')

        print('### ip -6 route show type prohibit')
        output = common.check_output('ip -6 route show type prohibit')
        print(output)
        self.assertEqual(output, '')

        common.remove_network_unit('25-address-static.network')
        common.networkctl_reload()
        self.wait_online(['dummy98:routable'])

        # check all routes managed by Manager are reconfigured
        print('### ip -4 route show type blackhole')
        output = common.check_output('ip -4 route show type blackhole')
        print(output)
        self.assertIn('blackhole 202.54.1.2 proto static', output)

        print('### ip -4 route show type unreachable')
        output = common.check_output('ip -4 route show type unreachable')
        print(output)
        self.assertIn('unreachable 202.54.1.3 proto static', output)

        print('### ip -4 route show type prohibit')
        output = common.check_output('ip -4 route show type prohibit')
        print(output)
        self.assertIn('prohibit 202.54.1.4 proto static', output)

        print('### ip -6 route show type blackhole')
        output = common.check_output('ip -6 route show type blackhole')
        print(output)
        self.assertIn('blackhole 2001:1234:5678::2 dev lo proto static', output)

        print('### ip -6 route show type unreachable')
        output = common.check_output('ip -6 route show type unreachable')
        print(output)
        self.assertIn('unreachable 2001:1234:5678::3 dev lo proto static', output)

        print('### ip -6 route show type prohibit')
        output = common.check_output('ip -6 route show type prohibit')
        print(output)
        self.assertIn('prohibit 2001:1234:5678::4 dev lo proto static', output)

        common.remove_link('dummy98')
        time.sleep(2)

        # check all routes managed by Manager are removed
        print('### ip -4 route show type blackhole')
        output = common.check_output('ip -4 route show type blackhole')
        print(output)
        self.assertEqual(output, '')

        print('### ip -4 route show type unreachable')
        output = common.check_output('ip -4 route show type unreachable')
        print(output)
        self.assertEqual(output, '')

        print('### ip -4 route show type prohibit')
        output = common.check_output('ip -4 route show type prohibit')
        print(output)
        self.assertEqual(output, '')

        print('### ip -6 route show type blackhole')
        output = common.check_output('ip -6 route show type blackhole')
        print(output)
        self.assertEqual(output, '')

        print('### ip -6 route show type unreachable')
        output = common.check_output('ip -6 route show type unreachable')
        print(output)
        self.assertEqual(output, '')

        print('### ip -6 route show type prohibit')
        output = common.check_output('ip -6 route show type prohibit')
        print(output)
        self.assertEqual(output, '')

        self.tearDown()

    def test_route_static(self):
        first = True
        for manage_foreign_routes in [True, False]:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_route_static(manage_foreign_routes={manage_foreign_routes})')
            with self.subTest(manage_foreign_routes=manage_foreign_routes):
                self._test_route_static(manage_foreign_routes)

    @common.expectedFailureIfRTA_VIAIsNotSupported()
    def test_route_via_ipv6(self):
        common.copy_network_unit('25-route-via-ipv6.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'dummy98', env=common.env)
        print(output)

        print('### ip -6 route show dev dummy98')
        output = common.check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertRegex(output, '2001:1234:5:8fff:ff:ff:ff:ff proto static')
        self.assertRegex(output, '2001:1234:5:8f63::1 proto kernel')

        print('### ip -4 route show dev dummy98')
        output = common.check_output('ip -4 route show dev dummy98')
        print(output)
        self.assertRegex(output, '149.10.124.48/28 proto kernel scope link src 149.10.124.58')
        self.assertRegex(output, '149.10.124.66 via inet6 2001:1234:5:8fff:ff:ff:ff:ff proto static')

    @common.expectedFailureIfModuleIsNotAvailable('tcp_dctcp')
    def test_route_congctl(self):
        common.copy_network_unit('25-route-congctl.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        print('### ip -6 route show dev dummy98 2001:1234:5:8fff:ff:ff:ff:ff')
        output = common.check_output('ip -6 route show dev dummy98 2001:1234:5:8fff:ff:ff:ff:ff')
        print(output)
        self.assertIn('2001:1234:5:8fff:ff:ff:ff:ff proto static', output)
        self.assertIn('congctl dctcp', output)

        print('### ip -4 route show dev dummy98 149.10.124.66')
        output = common.check_output('ip -4 route show dev dummy98 149.10.124.66')
        print(output)
        self.assertIn('149.10.124.66 proto static', output)
        self.assertIn('congctl dctcp', output)

    @common.expectedFailureIfModuleIsNotAvailable('vrf')
    def test_route_vrf(self):
        common.copy_network_unit(
                '25-route-vrf.network', '12-dummy.netdev',
                '25-vrf.netdev', '25-vrf.network')
        common.start_networkd()
        self.wait_online(['dummy98:routable', 'vrf99:carrier'])

        output = common.check_output('ip route show vrf vrf99')
        print(output)
        self.assertRegex(output, 'default via 192.168.100.1')

        output = common.check_output('ip route show')
        print(output)
        self.assertNotRegex(output, 'default via 192.168.100.1')

    def test_gateway_reconfigure(self):
        common.copy_network_unit('25-gateway-static.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])
        print('### ip -4 route show dev dummy98 default')
        output = common.check_output('ip -4 route show dev dummy98 default')
        print(output)
        self.assertIn('default via 149.10.124.59 proto static', output)
        self.assertNotIn('149.10.124.60', output)

        common.remove_network_unit('25-gateway-static.network')
        common.copy_network_unit('25-gateway-next-static.network')
        common.networkctl_reload()
        self.wait_online(['dummy98:routable'])
        print('### ip -4 route show dev dummy98 default')
        output = common.check_output('ip -4 route show dev dummy98 default')
        print(output)
        self.assertNotIn('149.10.124.59', output)
        self.assertIn('default via 149.10.124.60 proto static', output)

    def test_ip_route_ipv6_src_route(self):
        # a dummy device does not make the addresses go through tentative state, so we
        # reuse a bond from an earlier test, which does make the addresses go through
        # tentative state, and do our test on that
        common.copy_network_unit('23-active-slave.network', '25-route-ipv6-src.network', '25-bond-active-backup-slave.netdev', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:enslaved', 'bond199:routable'])

        output = common.check_output('ip -6 route list dev bond199')
        print(output)
        self.assertIn('abcd::/16 via 2001:1234:56:8f63::1:1 proto static src 2001:1234:56:8f63::2', output)

    def test_route_preferred_source_with_existing_address(self):
        # See issue #28009.
        common.copy_network_unit('25-route-preferred-source.network', '12-dummy.netdev')
        common.start_networkd()

        for i in range(3):
            if i != 0:
                common.networkctl_reconfigure('dummy98')

            self.wait_online(['dummy98:routable'])

            output = common.check_output('ip -6 route list dev dummy98')
            print(output)
            self.assertIn('abcd::/16 via 2001:1234:56:8f63::1:1 proto static src 2001:1234:56:8f63::1', output)

    def test_ip_link_mac_address(self):
        common.copy_network_unit('25-address-link-section.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:degraded'])

        output = common.check_output('ip link show dummy98')
        print(output)
        self.assertRegex(output, '00:01:02:aa:bb:cc')

    def test_ip_link_unmanaged(self):
        common.copy_network_unit('25-link-section-unmanaged.network', '12-dummy.netdev')
        common.start_networkd()

        self.wait_operstate('dummy98', 'off', setup_state='unmanaged')

    def test_ipv6_address_label(self):
        common.copy_network_unit('25-ipv6-address-label-section.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:degraded'])

        output = common.check_output('ip addrlabel list')
        print(output)
        self.assertRegex(output, '2004:da8:1::/64')

    def test_ipv6_proxy_ndp(self):
        common.copy_network_unit('25-ipv6-proxy-ndp.network', '12-dummy.netdev')
        common.start_networkd()

        self.wait_online(['dummy98:routable'])

        output = common.check_output('ip neighbor show proxy dev dummy98')
        print(output)
        for i in range(1, 5):
            self.assertRegex(output, f'2607:5300:203:5215:{i}::1 *proxy')

    def test_neighbor_section(self):
        common.copy_network_unit('25-neighbor-section.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:degraded'], timeout='40s')

        print('### ip neigh list dev dummy98')
        output = common.check_output('ip neigh list dev dummy98')
        print(output)
        self.assertRegex(output, '192.168.10.1.*00:00:5e:00:02:65.*PERMANENT')
        self.assertRegex(output, '2004:da8:1::1.*00:00:5e:00:02:66.*PERMANENT')

        # TODO: check json string
        common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

    def test_neighbor_reconfigure(self):
        common.copy_network_unit('25-neighbor-section.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:degraded'], timeout='40s')

        print('### ip neigh list dev dummy98')
        output = common.check_output('ip neigh list dev dummy98')
        print(output)
        self.assertRegex(output, '192.168.10.1.*00:00:5e:00:02:65.*PERMANENT')
        self.assertRegex(output, '2004:da8:1::1.*00:00:5e:00:02:66.*PERMANENT')

        common.remove_network_unit('25-neighbor-section.network')
        common.copy_network_unit('25-neighbor-next.network')
        common.networkctl_reload()
        self.wait_online(['dummy98:degraded'], timeout='40s')
        print('### ip neigh list dev dummy98')
        output = common.check_output('ip neigh list dev dummy98')
        print(output)
        self.assertNotRegex(output, '192.168.10.1.*00:00:5e:00:02:65.*PERMANENT')
        self.assertRegex(output, '192.168.10.1.*00:00:5e:00:02:66.*PERMANENT')
        self.assertNotRegex(output, '2004:da8:1::1.*PERMANENT')

    def test_neighbor_gre(self):
        common.copy_network_unit(
                '25-neighbor-ip.network', '25-neighbor-ipv6.network', '25-neighbor-ip-dummy.network',
                '12-dummy.netdev', '25-gre-tunnel-remote-any.netdev', '25-ip6gre-tunnel-remote-any.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:degraded', 'gretun97:routable', 'ip6gretun97:routable'], timeout='40s')

        output = common.check_output('ip neigh list dev gretun97')
        print(output)
        self.assertRegex(output, '10.0.0.22 lladdr 10.65.223.239 PERMANENT')

        output = common.check_output('ip neigh list dev ip6gretun97')
        print(output)
        self.assertRegex(output, '2001:db8:0:f102::17 lladdr 2a:?00:ff:?de:45:?67:ed:?de:[0:]*:49:?88 PERMANENT')

        # TODO: check json string
        common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

    def test_link_local_addressing(self):
        common.copy_network_unit(
                '25-link-local-addressing-yes.network', '11-dummy.netdev',
                '25-link-local-addressing-no.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['test1:degraded', 'dummy98:carrier'])

        output = common.check_output('ip address show dev test1')
        print(output)
        self.assertRegex(output, 'inet .* scope link')
        self.assertRegex(output, 'inet6 .* scope link')

        output = common.check_output('ip address show dev dummy98')
        print(output)
        self.assertNotRegex(output, 'inet6* .* scope link')

        # Documentation/networking/ip-sysctl.txt
        #
        # addr_gen_mode - INTEGER
        # Defines how link-local and autoconf addresses are generated.
        #
        # 0: generate address based on EUI64 (default)
        # 1: do no generate a link-local address, use EUI64 for addresses generated
        #    from autoconf
        # 2: generate stable privacy addresses, using the secret from
        #    stable_secret (RFC7217)
        # 3: generate stable privacy addresses, using a random secret if unset

        self.check_ipv6_sysctl_attr('test1', 'stable_secret', '0123:4567:89ab:cdef:0123:4567:89ab:cdef')
        self.check_ipv6_sysctl_attr('test1', 'addr_gen_mode', '2')
        self.check_ipv6_sysctl_attr('dummy98', 'addr_gen_mode', '1')

    def test_link_local_addressing_ipv6ll(self):
        common.copy_network_unit('26-link-local-addressing-ipv6.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:degraded'])

        # An IPv6LL address exists by default.
        output = common.check_output('ip address show dev dummy98')
        print(output)
        self.assertRegex(output, 'inet6 .* scope link')

        common.copy_network_unit('25-link-local-addressing-no.network')
        common.networkctl_reload()
        self.wait_online(['dummy98:carrier'])

        # Check if the IPv6LL address is removed.
        output = common.check_output('ip address show dev dummy98')
        print(output)
        self.assertNotRegex(output, 'inet6 .* scope link')

        common.remove_network_unit('25-link-local-addressing-no.network')
        common.networkctl_reload()
        self.wait_online(['dummy98:degraded'])

        # Check if a new IPv6LL address is assigned.
        output = common.check_output('ip address show dev dummy98')
        print(output)
        self.assertRegex(output, 'inet6 .* scope link')

    def test_sysctl(self):
        common.copy_networkd_conf_dropin('25-global-ipv6-privacy-extensions.conf')
        common.copy_network_unit('25-sysctl.network', '12-dummy.netdev', copy_dropins=False)
        common.start_networkd()
        self.wait_online(['dummy98:degraded'])

        self.check_ipv6_sysctl_attr('dummy98', 'forwarding', '1')
        self.check_ipv6_sysctl_attr('dummy98', 'use_tempaddr', '1')
        self.check_ipv6_sysctl_attr('dummy98', 'dad_transmits', '3')
        self.check_ipv6_sysctl_attr('dummy98', 'hop_limit', '5')
        self.check_ipv6_sysctl_attr('dummy98', 'proxy_ndp', '1')
        self.check_ipv4_sysctl_attr('dummy98', 'forwarding', '1')
        self.check_ipv4_sysctl_attr('dummy98', 'proxy_arp', '1')
        self.check_ipv4_sysctl_attr('dummy98', 'accept_local', '1')

        common.copy_network_unit('25-sysctl.network.d/25-ipv6-privacy-extensions.conf')
        common.networkctl_reload()
        self.wait_online(['dummy98:degraded'])

        self.check_ipv6_sysctl_attr('dummy98', 'use_tempaddr', '2')

    def test_sysctl_disable_ipv6(self):
        common.copy_network_unit('25-sysctl-disable-ipv6.network', '12-dummy.netdev')

        print('## Disable ipv6')
        common.check_output('sysctl net.ipv6.conf.all.disable_ipv6=1')
        common.check_output('sysctl net.ipv6.conf.default.disable_ipv6=1')

        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('ip -4 address show dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.2.3.4/16 brd 10.2.255.255 scope global dummy98')
        output = common.check_output('ip -6 address show dummy98')
        print(output)
        self.assertRegex(output, 'inet6 2607:5300:203:3906::/64 scope global')
        self.assertRegex(output, 'inet6 .* scope link')
        output = common.check_output('ip -4 route show dev dummy98')
        print(output)
        self.assertRegex(output, '10.2.0.0/16 proto kernel scope link src 10.2.3.4')
        output = common.check_output('ip -6 route show default')
        print(output)
        self.assertRegex(output, 'default')
        self.assertRegex(output, 'via 2607:5300:203:39ff:ff:ff:ff:ff')

        common.remove_link('dummy98')

        print('## Enable ipv6')
        common.check_output('sysctl net.ipv6.conf.all.disable_ipv6=0')
        common.check_output('sysctl net.ipv6.conf.default.disable_ipv6=0')

        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('ip -4 address show dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.2.3.4/16 brd 10.2.255.255 scope global dummy98')
        output = common.check_output('ip -6 address show dummy98')
        print(output)
        self.assertRegex(output, 'inet6 2607:5300:203:3906::/64 scope global')
        self.assertRegex(output, 'inet6 .* scope link')
        output = common.check_output('ip -4 route show dev dummy98')
        print(output)
        self.assertRegex(output, '10.2.0.0/16 proto kernel scope link src 10.2.3.4')
        output = common.check_output('ip -6 route show default')
        print(output)
        self.assertRegex(output, 'via 2607:5300:203:39ff:ff:ff:ff:ff')

    def test_bind_carrier(self):
        common.copy_network_unit('25-bind-carrier.network', '11-dummy.netdev')
        common.start_networkd()

        # no bound interface.
        self.wait_operstate('test1', 'off', setup_state='configuring')
        output = common.check_output('ip address show test1')
        print(output)
        self.assertNotIn('UP,LOWER_UP', output)
        self.assertIn('DOWN', output)
        self.assertNotIn('192.168.10', output)

        # add one bound interface. The interface will be up.
        common.check_output('ip link add dummy98 type dummy')
        common.check_output('ip link set dummy98 up')
        self.wait_online(['test1:routable'])
        output = common.check_output('ip address show test1')
        print(output)
        self.assertIn('UP,LOWER_UP', output)
        self.assertIn('inet 192.168.10.30/24 brd 192.168.10.255 scope global test1', output)

        # add another bound interface. The interface is still up.
        common.check_output('ip link add dummy99 type dummy')
        common.check_output('ip link set dummy99 up')
        self.wait_operstate('dummy99', 'degraded', setup_state='unmanaged')
        output = common.check_output('ip address show test1')
        print(output)
        self.assertIn('UP,LOWER_UP', output)
        self.assertIn('inet 192.168.10.30/24 brd 192.168.10.255 scope global test1', output)

        # remove one of the bound interfaces. The interface is still up
        common.remove_link('dummy98')
        output = common.check_output('ip address show test1')
        print(output)
        self.assertIn('UP,LOWER_UP', output)
        self.assertIn('inet 192.168.10.30/24 brd 192.168.10.255 scope global test1', output)

        # bring down the remaining bound interface. The interface will be down.
        common.check_output('ip link set dummy99 down')
        self.wait_operstate('test1', 'off')
        self.wait_address_dropped('test1', r'192.168.10', ipv='-4', timeout_sec=10)
        output = common.check_output('ip address show test1')
        print(output)
        self.assertNotIn('UP,LOWER_UP', output)
        self.assertIn('DOWN', output)
        self.assertNotIn('192.168.10', output)

        # bring up the bound interface. The interface will be up.
        common.check_output('ip link set dummy99 up')
        self.wait_online(['test1:routable'])
        output = common.check_output('ip address show test1')
        print(output)
        self.assertIn('UP,LOWER_UP', output)
        self.assertIn('inet 192.168.10.30/24 brd 192.168.10.255 scope global test1', output)

        # remove the remaining bound interface. The interface will be down.
        common.remove_link('dummy99')
        self.wait_operstate('test1', 'off')
        self.wait_address_dropped('test1', r'192.168.10', ipv='-4', timeout_sec=10)
        output = common.check_output('ip address show test1')
        print(output)
        self.assertNotIn('UP,LOWER_UP', output)
        self.assertIn('DOWN', output)
        self.assertNotIn('192.168.10', output)

        # re-add one bound interface. The interface will be up.
        common.check_output('ip link add dummy98 type dummy')
        common.check_output('ip link set dummy98 up')
        self.wait_online(['test1:routable'])
        output = common.check_output('ip address show test1')
        print(output)
        self.assertIn('UP,LOWER_UP', output)
        self.assertIn('inet 192.168.10.30/24 brd 192.168.10.255 scope global test1', output)

    def _test_activation_policy(self, interface, test):
        conffile = '25-activation-policy.network'
        if test:
            conffile = f'{conffile}.d/{test}.conf'
        if interface == 'vlan99':
            common.copy_network_unit('21-vlan.netdev', '21-vlan-test1.network')
        common.copy_network_unit('11-dummy.netdev', conffile, copy_dropins=False)
        common.start_networkd()

        always = test.startswith('always')
        initial_up = test != 'manual' and not test.endswith('down') # note: default is up
        expect_up = initial_up
        next_up = not expect_up

        if test.endswith('down'):
            self.wait_activated(interface)

        for iteration in range(4):
            with self.subTest(iteration=iteration, expect_up=expect_up):
                operstate = 'routable' if expect_up else 'off'
                setup_state = 'configured' if expect_up else ('configuring' if iteration == 0 else None)
                self.wait_operstate(interface, operstate, setup_state=setup_state, setup_timeout=20)

                if expect_up:
                    self.assertIn('UP', common.check_output(f'ip link show {interface}'))
                    self.assertIn('192.168.10.30/24', common.check_output(f'ip address show {interface}'))
                    self.assertIn('default via 192.168.10.1', common.check_output(f'ip route show dev {interface}'))
                else:
                    self.assertIn('DOWN', common.check_output(f'ip link show {interface}'))

            if next_up:
                common.check_output(f'ip link set dev {interface} up')
            else:
                common.check_output(f'ip link set dev {interface} down')
            expect_up = initial_up if always else next_up
            next_up = not next_up
            if always:
                time.sleep(1)

    def test_activation_policy(self):
        first = True
        for interface in ['test1', 'vlan99']:
            for test in ['up', 'always-up', 'manual', 'always-down', 'down', '']:
                if first:
                    first = False
                else:
                    self.tearDown()

                print(f'### test_activation_policy(interface={interface}, test={test})')
                with self.subTest(interface=interface, test=test):
                    self._test_activation_policy(interface, test)

    def _test_activation_policy_required_for_online(self, policy, required):
        conffile = '25-activation-policy.network'
        units = ['11-dummy.netdev', '12-dummy.netdev', '12-dummy.network', conffile]
        if policy:
            units += [f'{conffile}.d/{policy}.conf']
        if required:
            units += [f'{conffile}.d/required-{required}.conf']
        common.copy_network_unit(*units, copy_dropins=False)
        common.start_networkd()

        if policy.endswith('down'):
            self.wait_activated('test1')

        if policy.endswith('down') or policy == 'manual':
            self.wait_operstate('test1', 'off', setup_state='configuring')
        else:
            self.wait_online(['test1'])

        if policy == 'always-down':
            # if always-down, required for online is forced to no
            expected = False
        elif required:
            # otherwise if required for online is specified, it should match that
            expected = required == 'yes'
        elif policy:
            # otherwise if only policy specified, required for online defaults to
            # true if policy is up, always-up, or bound
            expected = policy.endswith('up') or policy == 'bound'
        else:
            # default is true, if neither are specified
            expected = True

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'test1', env=common.env)
        print(output)

        yesno = 'yes' if expected else 'no'
        self.assertRegex(output, f'Required For Online: {yesno}')

    def test_activation_policy_required_for_online(self):
        first = True
        for policy in ['up', 'always-up', 'manual', 'always-down', 'down', 'bound', '']:
            for required in ['yes', 'no', '']:
                if first:
                    first = False
                else:
                    self.tearDown()

                print(f'### test_activation_policy_required_for_online(policy={policy}, required={required})')
                with self.subTest(policy=policy, required=required):
                    self._test_activation_policy_required_for_online(policy, required)

    def test_domain(self):
        common.copy_network_unit('12-dummy.netdev', '24-search-domain.network')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'dummy98', env=common.env)
        print(output)
        self.assertRegex(output, 'Address: 192.168.42.100')
        self.assertRegex(output, 'DNS: 192.168.42.1')
        self.assertRegex(output, 'Search Domains: one')

    def test_keep_configuration_static(self):
        common.check_output('ip link add name dummy98 type dummy')
        common.check_output('ip address add 10.1.2.3/16 dev dummy98')
        common.check_output('ip address add 10.2.3.4/16 dev dummy98 valid_lft 600 preferred_lft 500')
        output = common.check_output('ip address show dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.1.2.3/16 scope global dummy98')
        self.assertRegex(output, 'inet 10.2.3.4/16 scope global dynamic dummy98')
        output = common.check_output('ip route show dev dummy98')
        print(output)

        common.copy_network_unit('24-keep-configuration-static.network')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('ip address show dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.1.2.3/16 scope global dummy98')
        self.assertNotRegex(output, 'inet 10.2.3.4/16 scope global dynamic dummy98')

    @common.expectedFailureIfNexthopIsNotAvailable()
    def test_nexthop(self):
        def check_nexthop(self):
            self.wait_online(['veth99:routable', 'veth-peer:routable', 'dummy98:routable'])

            output = common.check_output('ip nexthop list dev veth99')
            print(output)
            self.assertIn('id 1 via 192.168.5.1 dev veth99', output)
            self.assertIn('id 2 via 2001:1234:5:8f63::2 dev veth99', output)
            self.assertIn('id 3 dev veth99', output)
            self.assertIn('id 4 dev veth99', output)
            self.assertRegex(output, 'id 5 via 192.168.10.1 dev veth99 .*onlink')
            self.assertIn('id 8 via fe80:0:222:4dff:ff:ff:ff:ff dev veth99', output)
            self.assertRegex(output, r'id [0-9]* via 192.168.5.2 dev veth99')

            output = common.check_output('ip nexthop list dev dummy98')
            print(output)
            self.assertIn('id 20 via 192.168.20.1 dev dummy98', output)

            # kernel manages blackhole nexthops on lo
            output = common.check_output('ip nexthop list dev lo')
            print(output)
            self.assertIn('id 6 blackhole', output)
            self.assertIn('id 7 blackhole', output)

            # group nexthops are shown with -0 option
            output = common.check_output('ip -0 nexthop list id 21')
            print(output)
            self.assertRegex(output, r'id 21 group (1,3/20|20/1,3)')

            output = common.check_output('ip route show dev veth99 10.10.10.10')
            print(output)
            self.assertEqual('10.10.10.10 nhid 1 via 192.168.5.1 proto static', output)

            output = common.check_output('ip route show dev veth99 10.10.10.11')
            print(output)
            self.assertEqual('10.10.10.11 nhid 2 via inet6 2001:1234:5:8f63::2 proto static', output)

            output = common.check_output('ip route show dev veth99 10.10.10.12')
            print(output)
            self.assertEqual('10.10.10.12 nhid 5 via 192.168.10.1 proto static onlink', output)

            output = common.check_output('ip -6 route show dev veth99 2001:1234:5:8f62::1')
            print(output)
            self.assertEqual('2001:1234:5:8f62::1 nhid 2 via 2001:1234:5:8f63::2 proto static metric 1024 pref medium', output)

            output = common.check_output('ip route show 10.10.10.13')
            print(output)
            self.assertEqual('blackhole 10.10.10.13 nhid 6 dev lo proto static', output)

            output = common.check_output('ip -6 route show 2001:1234:5:8f62::2')
            print(output)
            self.assertEqual('blackhole 2001:1234:5:8f62::2 nhid 7 dev lo proto static metric 1024 pref medium', output)

            output = common.check_output('ip route show 10.10.10.14')
            print(output)
            self.assertIn('10.10.10.14 nhid 21 proto static', output)
            self.assertIn('nexthop via 192.168.20.1 dev dummy98 weight 1', output)
            self.assertIn('nexthop via 192.168.5.1 dev veth99 weight 3', output)

            # TODO: check json string
            common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

        common.copy_network_unit('25-nexthop.network', '25-veth.netdev', '25-veth-peer.network',
                          '12-dummy.netdev', '25-nexthop-dummy.network')
        common.start_networkd()

        check_nexthop(self)

        common.remove_network_unit('25-nexthop.network')
        common.copy_network_unit('25-nexthop-nothing.network')
        common.networkctl_reload()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = common.check_output('ip nexthop list dev veth99')
        print(output)
        self.assertEqual(output, '')
        output = common.check_output('ip nexthop list dev lo')
        print(output)
        self.assertEqual(output, '')

        common.remove_network_unit('25-nexthop-nothing.network')
        common.copy_network_unit('25-nexthop.network')
        common.networkctl_reconfigure('dummy98')
        common.networkctl_reload()

        check_nexthop(self)

        common.remove_link('veth99')
        time.sleep(2)

        output = common.check_output('ip nexthop list dev lo')
        print(output)
        self.assertEqual(output, '')
