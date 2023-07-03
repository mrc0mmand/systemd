# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import unittest

import common


class NetworkdStateFileTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_state_file(self):
        common.copy_network_unit('12-dummy.netdev', '25-state-file-tests.network')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        # make link state file updated
        common.check_output(*common.resolvectl_cmd, 'revert', 'dummy98', env=common.env)

        # TODO: check json string
        common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

        output = common.read_link_state_file('dummy98')
        print(output)
        self.assertIn('IPV4_ADDRESS_STATE=routable', output)
        self.assertIn('IPV6_ADDRESS_STATE=routable', output)
        self.assertIn('ADMIN_STATE=configured', output)
        self.assertIn('OPER_STATE=routable', output)
        self.assertIn('REQUIRED_FOR_ONLINE=yes', output)
        self.assertIn('REQUIRED_OPER_STATE_FOR_ONLINE=routable', output)
        self.assertIn('REQUIRED_FAMILY_FOR_ONLINE=both', output)
        self.assertIn('ACTIVATION_POLICY=up', output)
        self.assertIn('NETWORK_FILE=/run/systemd/network/25-state-file-tests.network', output)
        self.assertIn('DNS=10.10.10.10#aaa.com 10.10.10.11:1111#bbb.com [1111:2222::3333]:1234#ccc.com', output)
        self.assertIn('NTP=0.fedora.pool.ntp.org 1.fedora.pool.ntp.org', output)
        self.assertIn('DOMAINS=hogehoge', output)
        self.assertIn('ROUTE_DOMAINS=foofoo', output)
        self.assertIn('LLMNR=no', output)
        self.assertIn('MDNS=yes', output)
        self.assertIn('DNSSEC=no', output)

        common.check_output(*common.resolvectl_cmd, 'dns', 'dummy98', '10.10.10.12#ccc.com', '10.10.10.13', '1111:2222::3333', env=common.env)
        common.check_output(*common.resolvectl_cmd, 'domain', 'dummy98', 'hogehogehoge', '~foofoofoo', env=common.env)
        common.check_output(*common.resolvectl_cmd, 'llmnr', 'dummy98', 'yes', env=common.env)
        common.check_output(*common.resolvectl_cmd, 'mdns', 'dummy98', 'no', env=common.env)
        common.check_output(*common.resolvectl_cmd, 'dnssec', 'dummy98', 'yes', env=common.env)
        common.check_output(*common.timedatectl_cmd, 'ntp-servers', 'dummy98', '2.fedora.pool.ntp.org', '3.fedora.pool.ntp.org', env=common.env)

        # TODO: check json string
        common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

        output = common.read_link_state_file('dummy98')
        print(output)
        self.assertIn('DNS=10.10.10.12#ccc.com 10.10.10.13 1111:2222::3333', output)
        self.assertIn('NTP=2.fedora.pool.ntp.org 3.fedora.pool.ntp.org', output)
        self.assertIn('DOMAINS=hogehogehoge', output)
        self.assertIn('ROUTE_DOMAINS=foofoofoo', output)
        self.assertIn('LLMNR=yes', output)
        self.assertIn('MDNS=no', output)
        self.assertIn('DNSSEC=yes', output)

        common.check_output(*common.timedatectl_cmd, 'revert', 'dummy98', env=common.env)

        # TODO: check json string
        common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

        output = common.read_link_state_file('dummy98')
        print(output)
        self.assertIn('DNS=10.10.10.12#ccc.com 10.10.10.13 1111:2222::3333', output)
        self.assertIn('NTP=0.fedora.pool.ntp.org 1.fedora.pool.ntp.org', output)
        self.assertIn('DOMAINS=hogehogehoge', output)
        self.assertIn('ROUTE_DOMAINS=foofoofoo', output)
        self.assertIn('LLMNR=yes', output)
        self.assertIn('MDNS=no', output)
        self.assertIn('DNSSEC=yes', output)

        common.check_output(*common.resolvectl_cmd, 'revert', 'dummy98', env=common.env)

        # TODO: check json string
        common.check_output(*common.networkctl_cmd, '--json=short', 'status', env=common.env)

        output = common.read_link_state_file('dummy98')
        print(output)
        self.assertIn('DNS=10.10.10.10#aaa.com 10.10.10.11:1111#bbb.com [1111:2222::3333]:1234#ccc.com', output)
        self.assertIn('NTP=0.fedora.pool.ntp.org 1.fedora.pool.ntp.org', output)
        self.assertIn('DOMAINS=hogehoge', output)
        self.assertIn('ROUTE_DOMAINS=foofoo', output)
        self.assertIn('LLMNR=no', output)
        self.assertIn('MDNS=yes', output)
        self.assertIn('DNSSEC=no', output)

    def test_address_state(self):
        common.copy_network_unit('12-dummy.netdev', '12-dummy-no-address.network')
        common.start_networkd()

        self.wait_online(['dummy98:degraded'])

        output = common.read_link_state_file('dummy98')
        self.assertIn('IPV4_ADDRESS_STATE=off', output)
        self.assertIn('IPV6_ADDRESS_STATE=degraded', output)

        # with a routable IPv4 address
        common.check_output('ip address add 10.1.2.3/16 dev dummy98')
        self.wait_online(['dummy98:routable'], ipv4=True)
        self.wait_online(['dummy98:routable'])

        output = common.read_link_state_file('dummy98')
        self.assertIn('IPV4_ADDRESS_STATE=routable', output)
        self.assertIn('IPV6_ADDRESS_STATE=degraded', output)

        common.check_output('ip address del 10.1.2.3/16 dev dummy98')

        # with a routable IPv6 address
        common.check_output('ip address add 2002:da8:1:0:1034:56ff:fe78:9abc/64 dev dummy98')
        self.wait_online(['dummy98:routable'], ipv6=True)
        self.wait_online(['dummy98:routable'])

        output = common.read_link_state_file('dummy98')
        self.assertIn('IPV4_ADDRESS_STATE=off', output)
        self.assertIn('IPV6_ADDRESS_STATE=routable', output)
