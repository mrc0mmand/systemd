# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import unittest

import common


class NetworkdDHCPServerRelayAgentTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_relay_agent(self):
        common.copy_network_unit('25-agent-veth-client.netdev',
                          '25-agent-veth-server.netdev',
                          '25-agent-client.network',
                          '25-agent-server.network',
                          '25-agent-client-peer.network',
                          '25-agent-server-peer.network')
        common.start_networkd()

        self.wait_online(['client:routable'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'client', env=common.env)
        print(output)
        self.assertRegex(output, r'Address: 192.168.5.150 \(DHCP4 via 192.168.5.1\)')
