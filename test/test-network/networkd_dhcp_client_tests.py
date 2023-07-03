# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import itertools
import os
import re
import time
import unittest

import common


class NetworkdDHCPClientTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_dhcp_client_ipv6_only(self):
        common.copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client-ipv6-only.network')

        common.start_networkd()
        self.wait_online(['veth-peer:carrier'])
        common.start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        # checking address
        output = common.check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet6 2600::[0-9a-f:]*/128 scope global dynamic noprefixroute')
        self.assertNotIn('192.168.5', output)

        # checking semi-static route
        output = common.check_output('ip -6 route list dev veth99 2001:1234:5:9fff:ff:ff:ff:ff')
        print(output)
        self.assertRegex(output, 'via fe80::1034:56ff:fe78:9abd')

        # Confirm that ipv6 token is not set in the kernel
        output = common.check_output('ip token show dev veth99')
        print(output)
        self.assertRegex(output, 'token :: dev veth99')

        print('## dnsmasq log')
        output = common.read_dnsmasq_log_file()
        print(output)
        self.assertIn('DHCPSOLICIT(veth-peer)', output)
        self.assertNotIn('DHCPADVERTISE(veth-peer)', output)
        self.assertNotIn('DHCPREQUEST(veth-peer)', output)
        self.assertIn('DHCPREPLY(veth-peer)', output)
        self.assertIn('sent size:  0 option: 14 rapid-commit', output)

        with open(os.path.join(common.network_unit_dir, '25-dhcp-client-ipv6-only.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[DHCPv6]\nRapidCommit=no\n')

        common.stop_dnsmasq()
        common.start_dnsmasq()

        common.networkctl_reload()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        # checking address
        output = common.check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet6 2600::[0-9a-f:]*/128 scope global dynamic noprefixroute')
        self.assertNotIn('192.168.5', output)

        # checking semi-static route
        output = common.check_output('ip -6 route list dev veth99 2001:1234:5:9fff:ff:ff:ff:ff')
        print(output)
        self.assertRegex(output, 'via fe80::1034:56ff:fe78:9abd')

        print('## dnsmasq log')
        output = common.read_dnsmasq_log_file()
        print(output)
        self.assertIn('DHCPSOLICIT(veth-peer)', output)
        self.assertIn('DHCPADVERTISE(veth-peer)', output)
        self.assertIn('DHCPREQUEST(veth-peer)', output)
        self.assertIn('DHCPREPLY(veth-peer)', output)
        self.assertNotIn('rapid-commit', output)

    def test_dhcp_client_ipv4_only(self):
        common.copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client-ipv4-only.network')

        common.start_networkd()
        self.wait_online(['veth-peer:carrier'])
        common.start_dnsmasq(
                '--dhcp-option=option:dns-server,192.168.5.6,192.168.5.7',
                '--dhcp-option=option:domain-search,example.com',
                '--dhcp-alternate-port=67,5555',
                ipv4_range='192.168.5.110,192.168.5.119')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])
        self.wait_address('veth99', r'inet 192.168.5.11[0-9]*/24', ipv='-4')

        print('## ip address show dev veth99 scope global')
        output = common.check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertIn('mtu 1492', output)
        self.assertIn('inet 192.168.5.250/24 brd 192.168.5.255 scope global veth99', output)
        self.assertRegex(output, r'inet 192.168.5.11[0-9]/24 metric 24 brd 192.168.5.255 scope global secondary dynamic noprefixroute test-label')
        self.assertNotIn('2600::', output)

        print('## ip route show table main dev veth99')
        output = common.check_output('ip route show table main dev veth99')
        print(output)
        # no DHCP routes assigned to the main table
        self.assertNotIn('proto dhcp', output)
        # static routes
        self.assertIn('192.168.5.0/24 proto kernel scope link src 192.168.5.250', output)
        self.assertIn('192.168.5.0/24 proto static scope link', output)
        self.assertIn('192.168.6.0/24 proto static scope link', output)
        self.assertIn('192.168.7.0/24 proto static scope link', output)

        print('## ip route show table 211 dev veth99')
        output = common.check_output('ip route show table 211 dev veth99')
        print(output)
        self.assertRegex(output, 'default via 192.168.5.1 proto dhcp src 192.168.5.11[0-9] metric 24')
        self.assertRegex(output, '192.168.5.0/24 proto dhcp scope link src 192.168.5.11[0-9] metric 24')
        self.assertRegex(output, '192.168.5.1 proto dhcp scope link src 192.168.5.11[0-9] metric 24')
        self.assertRegex(output, '192.168.5.6 proto dhcp scope link src 192.168.5.11[0-9] metric 24')
        self.assertRegex(output, '192.168.5.7 proto dhcp scope link src 192.168.5.11[0-9] metric 24')
        self.assertIn('10.0.0.0/8 via 192.168.5.1 proto dhcp', output)

        print('## link state file')
        output = common.read_link_state_file('veth99')
        print(output)
        # checking DNS server and Domains
        self.assertIn('DNS=192.168.5.6 192.168.5.7', output)
        self.assertIn('DOMAINS=example.com', output)

        print('## dnsmasq log')
        output = common.read_dnsmasq_log_file()
        print(output)
        self.assertIn('vendor class: FooBarVendorTest', output)
        self.assertIn('DHCPDISCOVER(veth-peer) 12:34:56:78:9a:bc', output)
        self.assertIn('client provides name: test-hostname', output)
        self.assertIn('26:mtu', output)

        # change address range, DNS servers, and Domains
        common.stop_dnsmasq()
        common.start_dnsmasq(
                '--dhcp-option=option:dns-server,192.168.5.1,192.168.5.7,192.168.5.8',
                '--dhcp-option=option:domain-search,foo.example.com',
                '--dhcp-alternate-port=67,5555',
                ipv4_range='192.168.5.120,192.168.5.129',)

        # Sleep for 120 sec as the dnsmasq minimum lease time can only be set to 120
        print('Wait for the DHCP lease to be expired')
        self.wait_address_dropped('veth99', r'inet 192.168.5.11[0-9]*/24', ipv='-4', timeout_sec=120)
        self.wait_address('veth99', r'inet 192.168.5.12[0-9]*/24', ipv='-4')

        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        print('## ip address show dev veth99 scope global')
        output = common.check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertIn('mtu 1492', output)
        self.assertIn('inet 192.168.5.250/24 brd 192.168.5.255 scope global veth99', output)
        self.assertNotIn('192.168.5.11', output)
        self.assertRegex(output, r'inet 192.168.5.12[0-9]/24 metric 24 brd 192.168.5.255 scope global secondary dynamic noprefixroute test-label')
        self.assertNotIn('2600::', output)

        print('## ip route show table main dev veth99')
        output = common.check_output('ip route show table main dev veth99')
        print(output)
        # no DHCP routes assigned to the main table
        self.assertNotIn('proto dhcp', output)
        # static routes
        self.assertIn('192.168.5.0/24 proto kernel scope link src 192.168.5.250', output)
        self.assertIn('192.168.5.0/24 proto static scope link', output)
        self.assertIn('192.168.6.0/24 proto static scope link', output)
        self.assertIn('192.168.7.0/24 proto static scope link', output)

        print('## ip route show table 211 dev veth99')
        output = common.check_output('ip route show table 211 dev veth99')
        print(output)
        self.assertRegex(output, 'default via 192.168.5.1 proto dhcp src 192.168.5.12[0-9] metric 24')
        self.assertRegex(output, '192.168.5.0/24 proto dhcp scope link src 192.168.5.12[0-9] metric 24')
        self.assertRegex(output, '192.168.5.1 proto dhcp scope link src 192.168.5.12[0-9] metric 24')
        self.assertNotIn('192.168.5.6', output)
        self.assertRegex(output, '192.168.5.7 proto dhcp scope link src 192.168.5.12[0-9] metric 24')
        self.assertRegex(output, '192.168.5.8 proto dhcp scope link src 192.168.5.12[0-9] metric 24')
        self.assertIn('10.0.0.0/8 via 192.168.5.1 proto dhcp', output)

        print('## link state file')
        output = common.read_link_state_file('veth99')
        print(output)
        # checking DNS server and Domains
        self.assertIn('DNS=192.168.5.1 192.168.5.7 192.168.5.8', output)
        self.assertIn('DOMAINS=foo.example.com', output)

        print('## dnsmasq log')
        output = common.read_dnsmasq_log_file()
        print(output)
        self.assertIn('vendor class: FooBarVendorTest', output)
        self.assertIn('DHCPDISCOVER(veth-peer) 192.168.5.11', output)
        self.assertIn('client provides name: test-hostname', output)
        self.assertIn('26:mtu', output)

        self.check_netlabel('veth99', r'192\.168\.5\.0/24')

    def test_dhcp_client_ipv4_use_routes_gateway(self):
        first = True
        for (routes, gateway, dns_and_ntp_routes, classless) in itertools.product([True, False], repeat=4):
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_dhcp_client_ipv4_use_routes_gateway(routes={routes}, gateway={gateway}, dns_and_ntp_routes={dns_and_ntp_routes}, classless={classless})')
            with self.subTest(routes=routes, gateway=gateway, dns_and_ntp_routes=dns_and_ntp_routes, classless=classless):
                self._test_dhcp_client_ipv4_use_routes_gateway(routes, gateway, dns_and_ntp_routes, classless)

    def _test_dhcp_client_ipv4_use_routes_gateway(self, use_routes, use_gateway, dns_and_ntp_routes, classless):
        testunit = '25-dhcp-client-ipv4-use-routes-use-gateway.network'
        testunits = ['25-veth.netdev', '25-dhcp-server-veth-peer.network', testunit]
        testunits.append(f'{testunit}.d/use-routes-{use_routes}.conf')
        testunits.append(f'{testunit}.d/use-gateway-{use_gateway}.conf')
        testunits.append(f'{testunit}.d/use-dns-and-ntp-routes-{dns_and_ntp_routes}.conf')
        common.copy_network_unit(*testunits, copy_dropins=False)

        common.start_networkd()
        self.wait_online(['veth-peer:carrier'])
        additional_options = [
            '--dhcp-option=option:dns-server,192.168.5.10,8.8.8.8',
            '--dhcp-option=option:ntp-server,192.168.5.11,9.9.9.9',
            '--dhcp-option=option:static-route,192.168.5.100,192.168.5.2,8.8.8.8,192.168.5.3'
        ]
        if classless:
            additional_options += [
                '--dhcp-option=option:classless-static-route,0.0.0.0/0,192.168.5.4,8.0.0.0/8,192.168.5.5'
            ]
        common.start_dnsmasq(*additional_options)
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = common.check_output('ip -4 route show dev veth99')
        print(output)

        # Check UseRoutes=
        if use_routes:
            if classless:
                self.assertRegex(output, r'default via 192.168.5.4 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'8.0.0.0/8 via 192.168.5.5 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'192.168.5.4 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'192.168.5.5 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            else:
                self.assertRegex(output, r'192.168.5.0/24 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'8.0.0.0/8 via 192.168.5.3 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'192.168.5.3 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
        else:
            self.assertNotRegex(output, r'default via 192.168.5.4 proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'8.0.0.0/8 via 192.168.5.5 proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.4 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.5 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.0/24 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'8.0.0.0/8 via 192.168.5.3 proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.3 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')

        # Check UseGateway=
        if use_gateway and (not classless or not use_routes):
            self.assertRegex(output, r'default via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
        else:
            self.assertNotRegex(output, r'default via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')

        # Check route to gateway
        if (use_gateway or dns_and_ntp_routes) and (not classless or not use_routes):
            self.assertRegex(output, r'192.168.5.1 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
        else:
            self.assertNotRegex(output, r'192.168.5.1 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')

        # Check RoutesToDNS= and RoutesToNTP=
        if dns_and_ntp_routes:
            self.assertRegex(output, r'192.168.5.10 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertRegex(output, r'192.168.5.11 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            if classless and use_routes:
                self.assertRegex(output, r'8.8.8.8 via 192.168.5.4 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'9.9.9.9 via 192.168.5.4 proto dhcp src 192.168.5.[0-9]* metric 1024')
            else:
                self.assertRegex(output, r'8.8.8.8 via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'9.9.9.9 via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
        else:
            self.assertNotRegex(output, r'192.168.5.10 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.11 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'8.8.8.8 via 192.168.5.[0-9]* proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'9.9.9.9 via 192.168.5.[0-9]* proto dhcp src 192.168.5.[0-9]* metric 1024')

        # TODO: check json string
        common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

    def test_dhcp_client_settings_anonymize(self):
        common.copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client-anonymize.network')
        common.start_networkd()
        self.wait_online(['veth-peer:carrier'])
        common.start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        print('## dnsmasq log')
        output = common.read_dnsmasq_log_file()
        print(output)
        self.assertNotIn('VendorClassIdentifier=SusantVendorTest', output)
        self.assertNotIn('test-hostname', output)
        self.assertNotIn('26:mtu', output)

    def test_dhcp_keep_configuration_dhcp(self):
        common.copy_network_unit(
                '25-veth.netdev',
                '25-dhcp-server-veth-peer.network',
                '25-dhcp-client-keep-configuration-dhcp.network')
        common.start_networkd()
        self.wait_online(['veth-peer:carrier'])
        common.start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = common.check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global veth99\n *'
                         'valid_lft forever preferred_lft forever')

        # Stopping dnsmasq as networkd won't be allowed to renew the DHCP lease.
        common.stop_dnsmasq()

        # Sleep for 120 sec as the dnsmasq minimum lease time can only be set to 120
        print('Wait for the DHCP lease to be expired')
        time.sleep(120)

        # The lease address should be kept after the lease expired
        output = common.check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global veth99\n *'
                         'valid_lft forever preferred_lft forever')

        common.stop_networkd()

        # The lease address should be kept after networkd stopped
        output = common.check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global veth99\n *'
                         'valid_lft forever preferred_lft forever')

        with open(os.path.join(common.network_unit_dir, '25-dhcp-client-keep-configuration-dhcp.network'), mode='a', encoding='utf-8') as f:
            f.write('[Network]\nDHCP=no\n')

        common.start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        # Still the lease address should be kept after networkd restarted
        output = common.check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global veth99\n *'
                         'valid_lft forever preferred_lft forever')

    def test_dhcp_keep_configuration_dhcp_on_stop(self):
        common.copy_network_unit(
                '25-veth.netdev',
                '25-dhcp-server-veth-peer.network',
                '25-dhcp-client-keep-configuration-dhcp-on-stop.network')
        common.start_networkd()
        self.wait_online(['veth-peer:carrier'])
        common.start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = common.check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic veth99')

        common.stop_dnsmasq()
        common.stop_networkd()

        output = common.check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic veth99')

        common.start_networkd()
        self.wait_online(['veth-peer:routable'])

        output = common.check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertNotIn('192.168.5.', output)

    def test_dhcp_client_reuse_address_as_static(self):
        common.copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client.network')
        common.start_networkd()
        self.wait_online(['veth-peer:carrier'])
        common.start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        # link become 'routable' when at least one protocol provide an valid address.
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

        output = common.check_output('ip address show dev veth99 scope global')
        ipv4_address = re.search(r'192.168.5.[0-9]*/24', output).group()
        ipv6_address = re.search(r'2600::[0-9a-f:]*/128', output).group()
        static_network = '\n'.join(['[Match]', 'Name=veth99', '[Network]', 'IPv6AcceptRA=no', 'Address=' + ipv4_address, 'Address=' + ipv6_address])
        print(static_network)

        common.remove_network_unit('25-dhcp-client.network')

        with open(os.path.join(common.network_unit_dir, '25-static.network'), mode='w', encoding='utf-8') as f:
            f.write(static_network)

        common.start_networkd()
        self.wait_online(['veth99:routable'])

        output = common.check_output('ip -4 address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, f'inet {ipv4_address} brd 192.168.5.255 scope global veth99\n *'
                         'valid_lft forever preferred_lft forever')

        output = common.check_output('ip -6 address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, f'inet6 {ipv6_address} scope global *\n *'
                         'valid_lft forever preferred_lft forever')

    @common.expectedFailureIfModuleIsNotAvailable('vrf')
    def test_dhcp_client_vrf(self):
        common.copy_network_unit(
                '25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client-vrf.network',
                '25-vrf.netdev', '25-vrf.network')
        common.start_networkd()
        self.wait_online(['veth-peer:carrier'])
        common.start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable', 'vrf99:carrier'])

        # link become 'routable' when at least one protocol provide an valid address.
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

        print('## ip -d link show dev vrf99')
        output = common.check_output('ip -d link show dev vrf99')
        print(output)
        self.assertRegex(output, 'vrf table 42')

        print('## ip address show vrf vrf99')
        output = common.check_output('ip address show vrf vrf99')
        print(output)
        self.assertRegex(output, 'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic veth99')
        self.assertRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)')
        self.assertRegex(output, 'inet6 .* scope link')

        print('## ip address show dev veth99')
        output = common.check_output('ip address show dev veth99')
        print(output)
        self.assertRegex(output, 'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic veth99')
        self.assertRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)')
        self.assertRegex(output, 'inet6 .* scope link')

        print('## ip route show vrf vrf99')
        output = common.check_output('ip route show vrf vrf99')
        print(output)
        self.assertRegex(output, 'default via 192.168.5.1 dev veth99 proto dhcp src 192.168.5.')
        self.assertRegex(output, '192.168.5.0/24 dev veth99 proto kernel scope link src 192.168.5')
        self.assertRegex(output, '192.168.5.1 dev veth99 proto dhcp scope link src 192.168.5')

        print('## ip route show table main dev veth99')
        output = common.check_output('ip route show table main dev veth99')
        print(output)
        self.assertEqual(output, '')

    def test_dhcp_client_gateway_onlink_implicit(self):
        common.copy_network_unit(
                '25-veth.netdev', '25-dhcp-server-veth-peer.network',
                '25-dhcp-client-gateway-onlink-implicit.network')
        common.start_networkd()
        self.wait_online(['veth-peer:carrier'])
        common.start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'veth99', env=common.env)
        print(output)
        self.assertRegex(output, '192.168.5')

        output = common.check_output('ip route list dev veth99 10.0.0.0/8')
        print(output)
        self.assertRegex(output, 'onlink')
        output = common.check_output('ip route list dev veth99 192.168.100.0/24')
        print(output)
        self.assertRegex(output, 'onlink')

    def test_dhcp_client_with_ipv4ll(self):
        common.copy_network_unit(
                '25-veth.netdev', '25-dhcp-server-veth-peer.network',
                '25-dhcp-client-with-ipv4ll.network')
        common.start_networkd()
        # we need to increase timeout above default, as this will need to wait for
        # systemd-networkd to get the dhcpv4 transient failure event
        self.wait_online(['veth99:degraded', 'veth-peer:routable'], timeout='60s')

        output = common.check_output('ip -4 address show dev veth99')
        print(output)
        self.assertNotIn('192.168.5.', output)
        self.assertIn('inet 169.254.133.11/16 metric 2048 brd 169.254.255.255 scope link', output)

        common.start_dnsmasq()
        print('Wait for a DHCP lease to be acquired and the IPv4LL address to be dropped')
        self.wait_address('veth99', r'inet 192\.168\.5\.\d+/24 metric 1024 brd 192\.168\.5\.255 scope global dynamic', ipv='-4')
        self.wait_address_dropped('veth99', r'inet 169\.254\.\d+\.\d+/16 metric 2048 brd 169\.254\.255\.255 scope link', scope='link', ipv='-4')
        self.wait_online(['veth99:routable'])

        output = common.check_output('ip -4 address show dev veth99')
        print(output)
        self.assertRegex(output, r'inet 192\.168\.5\.\d+/24 metric 1024 brd 192\.168\.5\.255 scope global dynamic veth99')
        self.assertNotIn('169.254.', output)
        self.assertNotIn('scope link', output)

        common.stop_dnsmasq()
        print('Wait for the DHCP lease to be expired and an IPv4LL address to be acquired')
        self.wait_address_dropped('veth99', r'inet 192\.168\.5\.\d+/24 metric 1024 brd 192\.168\.5\.255 scope global dynamic', ipv='-4', timeout_sec=130)
        self.wait_address('veth99', r'inet 169\.254\.133\.11/16 metric 2048 brd 169\.254\.255\.255 scope link', scope='link', ipv='-4')

        output = common.check_output('ip -4 address show dev veth99')
        print(output)
        self.assertNotIn('192.168.5.', output)
        self.assertIn('inet 169.254.133.11/16 metric 2048 brd 169.254.255.255 scope link', output)

    def test_dhcp_client_use_dns(self):
        def check(self, ipv4, ipv6):
            os.makedirs(os.path.join(common.network_unit_dir, '25-dhcp-client.network.d'), exist_ok=True)
            with open(os.path.join(common.network_unit_dir, '25-dhcp-client.network.d/override.conf'), mode='w', encoding='utf-8') as f:
                f.write('[DHCPv4]\nUseDNS=')
                f.write('yes' if ipv4 else 'no')
                f.write('\n[DHCPv6]\nUseDNS=')
                f.write('yes' if ipv6 else 'no')
                f.write('\n[IPv6AcceptRA]\nUseDNS=no')

            common.networkctl_reload()
            self.wait_online(['veth99:routable'])

            # link becomes 'routable' when at least one protocol provide an valid address. Hence, we need to explicitly wait for both addresses.
            self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
            self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

            # make resolved re-read the link state file
            common.check_output(*common.resolvectl_cmd, 'revert', 'veth99', env=common.env)

            output = common.check_output(*common.resolvectl_cmd, 'dns', 'veth99', env=common.env)
            print(output)
            if ipv4:
                self.assertIn('192.168.5.1', output)
            else:
                self.assertNotIn('192.168.5.1', output)
            if ipv6:
                self.assertIn('2600::1', output)
            else:
                self.assertNotIn('2600::1', output)

            # TODO: check json string
            common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

        common.copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client.network', copy_dropins=False)

        common.start_networkd()
        self.wait_online(['veth-peer:carrier'])
        common.start_dnsmasq('--dhcp-option=option:dns-server,192.168.5.1',
                      '--dhcp-option=option6:dns-server,[2600::1]')

        check(self, True, True)
        check(self, True, False)
        check(self, False, True)
        check(self, False, False)

    def test_dhcp_client_use_captive_portal(self):
        def check(self, ipv4, ipv6):
            os.makedirs(os.path.join(common.network_unit_dir, '25-dhcp-client.network.d'), exist_ok=True)
            with open(os.path.join(common.network_unit_dir, '25-dhcp-client.network.d/override.conf'), mode='w', encoding='utf-8') as f:
                f.write('[DHCPv4]\nUseCaptivePortal=')
                f.write('yes' if ipv4 else 'no')
                f.write('\n[DHCPv6]\nUseCaptivePortal=')
                f.write('yes' if ipv6 else 'no')
                f.write('\n[IPv6AcceptRA]\nUseCaptivePortal=no')

            common.networkctl_reload()
            self.wait_online(['veth99:routable'])

            # link becomes 'routable' when at least one protocol provide an valid address. Hence, we need to explicitly wait for both addresses.
            self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
            self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

            output = common.check_output(*common.networkctl_cmd, 'status', 'veth99', env=common.env)
            print(output)
            if ipv4 or ipv6:
                self.assertIn('Captive Portal: http://systemd.io', output)
            else:
                self.assertNotIn('Captive Portal: http://systemd.io', output)

            # TODO: check json string
            common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

        common.copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client.network', copy_dropins=False)

        common.start_networkd()
        self.wait_online(['veth-peer:carrier'])
        common.start_dnsmasq('--dhcp-option=114,http://systemd.io',
                      '--dhcp-option=option6:103,http://systemd.io')

        check(self, True, True)
        check(self, True, False)
        check(self, False, True)
        check(self, False, False)
