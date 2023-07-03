# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import unittest

import common


class NetworkdDHCPServerTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_dhcp_server(self):
        common.copy_network_unit('25-veth.netdev', '25-dhcp-client.network', '25-dhcp-server.network')
        common.start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'veth99', env=common.env)
        print(output)
        self.assertRegex(output, r'Address: 192.168.5.[0-9]* \(DHCP4 via 192.168.5.1\)')
        self.assertIn('Gateway: 192.168.5.3', output)
        self.assertRegex(output, 'DNS: 192.168.5.1\n *192.168.5.10')
        self.assertRegex(output, 'NTP: 192.168.5.1\n *192.168.5.11')

    def test_dhcp_server_with_uplink(self):
        common.copy_network_unit(
                '25-veth.netdev', '25-dhcp-client.network', '25-dhcp-server-downstream.network',
                '12-dummy.netdev', '25-dhcp-server-uplink.network')
        common.start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'veth99', env=common.env)
        print(output)
        self.assertRegex(output, r'Address: 192.168.5.[0-9]* \(DHCP4 via 192.168.5.1\)')
        self.assertIn('Gateway: 192.168.5.3', output)
        self.assertIn('DNS: 192.168.5.1', output)
        self.assertIn('NTP: 192.168.5.1', output)

    def test_emit_router_timezone(self):
        common.copy_network_unit('25-veth.netdev', '25-dhcp-client-timezone-router.network', '25-dhcp-server-timezone-router.network')
        common.start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'veth99', env=common.env)
        print(output)
        self.assertRegex(output, r'Address: 192.168.5.[0-9]* \(DHCP4 via 192.168.5.1\)')
        self.assertIn('Gateway: 192.168.5.1', output)
        self.assertIn('Time Zone: Europe/Berlin', output)

    def test_dhcp_server_static_lease(self):
        common.copy_network_unit('25-veth.netdev', '25-dhcp-client-static-lease.network', '25-dhcp-server-static-lease.network')
        common.start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'veth99', env=common.env)
        print(output)
        self.assertIn('Address: 10.1.1.200 (DHCP4 via 10.1.1.1)', output)
        self.assertIn('DHCP4 Client ID: 12:34:56:78:9a:bc', output)

    def test_dhcp_server_static_lease_default_client_id(self):
        common.copy_network_unit('25-veth.netdev', '25-dhcp-client.network', '25-dhcp-server-static-lease.network')
        common.start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'veth99', env=common.env)
        print(output)
        self.assertIn('Address: 10.1.1.200 (DHCP4 via 10.1.1.1)', output)
        self.assertRegex(output, 'DHCP4 Client ID: IAID:[0-9a-z]*/DUID')
