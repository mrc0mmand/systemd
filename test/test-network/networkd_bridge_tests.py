# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import time
import unittest

import common


class NetworkdBridgeTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_bridge_vlan(self):
        common.copy_network_unit(
                '11-dummy.netdev', '26-bridge-vlan-slave.network',
                '26-bridge.netdev', '26-bridge-vlan-master.network')
        common.start_networkd()
        self.wait_online(['test1:enslaved', 'bridge99:degraded'])

        output = common.check_output('bridge vlan show dev test1')
        print(output)
        self.assertNotRegex(output, '4063')
        for i in range(4064, 4095):
            self.assertRegex(output, f'{i}')
        self.assertNotRegex(output, '4095')

        output = common.check_output('bridge vlan show dev bridge99')
        print(output)
        self.assertNotRegex(output, '4059')
        for i in range(4060, 4095):
            self.assertRegex(output, f'{i}')
        self.assertNotRegex(output, '4095')

    def test_bridge_vlan_issue_20373(self):
        common.copy_network_unit(
                '11-dummy.netdev', '26-bridge-vlan-slave-issue-20373.network',
                '26-bridge-issue-20373.netdev', '26-bridge-vlan-master-issue-20373.network',
                '21-vlan.netdev', '21-vlan.network')
        common.start_networkd()
        self.wait_online(['test1:enslaved', 'bridge99:degraded', 'vlan99:routable'])

        output = common.check_output('bridge vlan show dev test1')
        print(output)
        self.assertIn('100 PVID Egress Untagged', output)
        self.assertIn('560', output)
        self.assertIn('600', output)

        output = common.check_output('bridge vlan show dev bridge99')
        print(output)
        self.assertIn('1 PVID Egress Untagged', output)
        self.assertIn('100', output)
        self.assertIn('600', output)

    def test_bridge_mdb(self):
        common.copy_network_unit(
                '11-dummy.netdev', '26-bridge-mdb-slave.network',
                '26-bridge.netdev', '26-bridge-mdb-master.network')
        common.start_networkd()
        self.wait_online(['test1:enslaved', 'bridge99:degraded'])

        output = common.check_output('bridge mdb show dev bridge99')
        print(output)
        self.assertRegex(output, 'dev bridge99 port test1 grp ff02:aaaa:fee5::1:3 permanent *vid 4064')
        self.assertRegex(output, 'dev bridge99 port test1 grp 224.0.1.1 permanent *vid 4065')

        # Old kernel may not support bridge MDB entries on bridge master
        if common.call_quiet('bridge mdb add dev bridge99 port bridge99 grp 224.0.1.3 temp vid 4068') == 0:
            self.assertRegex(output, 'dev bridge99 port bridge99 grp ff02:aaaa:fee5::1:4 temp *vid 4066')
            self.assertRegex(output, 'dev bridge99 port bridge99 grp 224.0.1.2 temp *vid 4067')

    def test_bridge_keep_master(self):
        common.check_output('ip link add bridge99 type bridge')
        common.check_output('ip link set bridge99 up')
        common.check_output('ip link add dummy98 type dummy')
        common.check_output('ip link set dummy98 master bridge99')

        common.copy_network_unit('23-keep-master.network')
        common.start_networkd()
        self.wait_online(['dummy98:enslaved'])

        output = common.check_output('ip -d link show dummy98')
        print(output)
        self.assertRegex(output, 'master bridge99')
        self.assertRegex(output, 'bridge')

        output = common.check_output('bridge -d link show dummy98')
        print(output)
        self.check_bridge_port_attr('bridge99', 'dummy98', 'path_cost',            '400')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'hairpin_mode',         '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'multicast_fast_leave', '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'unicast_flood',        '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'multicast_flood',      '0')
        # CONFIG_BRIDGE_IGMP_SNOOPING=y
        self.check_bridge_port_attr('bridge99', 'dummy98', 'multicast_to_unicast', '1', allow_enoent=True)
        self.check_bridge_port_attr('bridge99', 'dummy98', 'neigh_suppress',       '1', allow_enoent=True)
        self.check_bridge_port_attr('bridge99', 'dummy98', 'learning',             '0')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'priority',             '23')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'bpdu_guard',           '0')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'root_block',           '0')

    def test_bridge_property(self):
        common.copy_network_unit(
                '11-dummy.netdev', '12-dummy.netdev', '26-bridge.netdev',
                '26-bridge-slave-interface-1.network', '26-bridge-slave-interface-2.network',
                '25-bridge99.network')
        common.start_networkd()
        self.wait_online(['dummy98:enslaved', 'test1:enslaved', 'bridge99:routable'])

        output = common.check_output('ip -d link show bridge99')
        print(output)
        self.assertIn('mtu 9000 ', output)

        output = common.check_output('ip -d link show test1')
        print(output)
        self.assertIn('master bridge99 ', output)
        self.assertIn('bridge_slave', output)
        self.assertIn('mtu 9000 ', output)

        output = common.check_output('ip -d link show dummy98')
        print(output)
        self.assertIn('master bridge99 ', output)
        self.assertIn('bridge_slave', output)
        self.assertIn('mtu 9000 ', output)

        output = common.check_output('ip addr show bridge99')
        print(output)
        self.assertIn('192.168.0.15/24', output)

        output = common.check_output('bridge -d link show dummy98')
        print(output)
        self.check_bridge_port_attr('bridge99', 'dummy98', 'path_cost',            '400')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'hairpin_mode',         '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'isolated',             '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'multicast_fast_leave', '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'unicast_flood',        '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'multicast_flood',      '0')
        # CONFIG_BRIDGE_IGMP_SNOOPING=y
        self.check_bridge_port_attr('bridge99', 'dummy98', 'multicast_to_unicast', '1', allow_enoent=True)
        self.check_bridge_port_attr('bridge99', 'dummy98', 'neigh_suppress',       '1', allow_enoent=True)
        self.check_bridge_port_attr('bridge99', 'dummy98', 'learning',             '0')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'priority',             '23')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'bpdu_guard',           '0')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'root_block',           '0')

        output = common.check_output('bridge -d link show test1')
        print(output)
        self.check_bridge_port_attr('bridge99', 'test1', 'priority',               '0')

        common.check_output('ip address add 192.168.0.16/24 dev bridge99')
        output = common.check_output('ip addr show bridge99')
        print(output)
        self.assertIn('192.168.0.16/24', output)

        # for issue #6088
        print('### ip -6 route list table all dev bridge99')
        output = common.check_output('ip -6 route list table all dev bridge99')
        print(output)
        self.assertRegex(output, 'ff00::/8 table local (proto kernel )?metric 256 (linkdown )?pref medium')

        common.remove_link('test1')
        self.wait_operstate('bridge99', 'routable')

        output = common.check_output('ip -d link show bridge99')
        print(output)
        self.assertIn('mtu 9000 ', output)

        output = common.check_output('ip -d link show dummy98')
        print(output)
        self.assertIn('master bridge99 ', output)
        self.assertIn('bridge_slave', output)
        self.assertIn('mtu 9000 ', output)

        common.remove_link('dummy98')
        self.wait_operstate('bridge99', 'no-carrier')

        output = common.check_output('ip -d link show bridge99')
        print(output)
        # When no carrier, the kernel may reset the MTU
        self.assertIn('NO-CARRIER', output)

        output = common.check_output('ip address show bridge99')
        print(output)
        self.assertNotIn('192.168.0.15/24', output)
        self.assertIn('192.168.0.16/24', output) # foreign address is kept

        print('### ip -6 route list table all dev bridge99')
        output = common.check_output('ip -6 route list table all dev bridge99')
        print(output)
        self.assertRegex(output, 'ff00::/8 table local (proto kernel )?metric 256 (linkdown )?pref medium')

        common.check_output('ip link add dummy98 type dummy')
        self.wait_online(['dummy98:enslaved', 'bridge99:routable'])

        output = common.check_output('ip -d link show bridge99')
        print(output)
        self.assertIn('mtu 9000 ', output)

        output = common.check_output('ip -d link show dummy98')
        print(output)
        self.assertIn('master bridge99 ', output)
        self.assertIn('bridge_slave', output)
        self.assertIn('mtu 9000 ', output)

    def test_bridge_configure_without_carrier(self):
        common.copy_network_unit(
                '26-bridge.netdev', '26-bridge-configure-without-carrier.network',
               '11-dummy.netdev')
        common.start_networkd()

        # With ConfigureWithoutCarrier=yes, the bridge should remain configured for all these situations
        for test in ['no-slave', 'add-slave', 'slave-up', 'slave-no-carrier', 'slave-carrier', 'slave-down']:
            with self.subTest(test=test):
                if test == 'no-slave':
                    # bridge has no slaves; it's up but *might* not have carrier
                    self.wait_operstate('bridge99', operstate=r'(no-carrier|routable)', setup_state=None, setup_timeout=30)
                    # due to a bug in the kernel, newly-created bridges are brought up
                    # *with* carrier, unless they have had any setting changed; e.g.
                    # their mac set, priority set, etc.  Then, they will lose carrier
                    # as soon as a (down) slave interface is added, and regain carrier
                    # again once the slave interface is brought up.
                    #self.check_link_attr('bridge99', 'carrier', '0')
                elif test == 'add-slave':
                    # add slave to bridge, but leave it down; bridge is definitely no-carrier
                    self.check_link_attr('test1', 'operstate', 'down')
                    common.check_output('ip link set dev test1 master bridge99')
                    self.wait_operstate('bridge99', operstate='no-carrier', setup_state=None)
                    self.check_link_attr('bridge99', 'carrier', '0')
                elif test == 'slave-up':
                    # bring up slave, which will have carrier; bridge gains carrier
                    common.check_output('ip link set dev test1 up')
                    self.wait_online(['bridge99:routable'])
                    self.check_link_attr('bridge99', 'carrier', '1')
                elif test == 'slave-no-carrier':
                    # drop slave carrier; bridge loses carrier
                    common.check_output('ip link set dev test1 carrier off')
                    self.wait_online(['bridge99:no-carrier:no-carrier'])
                    self.check_link_attr('bridge99', 'carrier', '0')
                elif test == 'slave-carrier':
                    # restore slave carrier; bridge gains carrier
                    common.check_output('ip link set dev test1 carrier on')
                    self.wait_online(['bridge99:routable'])
                    self.check_link_attr('bridge99', 'carrier', '1')
                elif test == 'slave-down':
                    # bring down slave; bridge loses carrier
                    common.check_output('ip link set dev test1 down')
                    self.wait_online(['bridge99:no-carrier:no-carrier'])
                    self.check_link_attr('bridge99', 'carrier', '0')

                output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'bridge99', env=common.env)
                self.assertRegex(output, '10.1.2.3')
                self.assertRegex(output, '10.1.2.1')

    def test_bridge_ignore_carrier_loss(self):
        common.copy_network_unit(
                '11-dummy.netdev', '12-dummy.netdev', '26-bridge.netdev',
                '26-bridge-slave-interface-1.network', '26-bridge-slave-interface-2.network',
                '25-bridge99-ignore-carrier-loss.network')
        common.start_networkd()
        self.wait_online(['dummy98:enslaved', 'test1:enslaved', 'bridge99:routable'])

        common.check_output('ip address add 192.168.0.16/24 dev bridge99')
        common.remove_link('test1', 'dummy98')
        time.sleep(3)

        output = common.check_output('ip address show bridge99')
        print(output)
        self.assertRegex(output, 'NO-CARRIER')
        self.assertRegex(output, 'inet 192.168.0.15/24 brd 192.168.0.255 scope global bridge99')
        self.assertRegex(output, 'inet 192.168.0.16/24 scope global secondary bridge99')

    def test_bridge_ignore_carrier_loss_frequent_loss_and_gain(self):
        common.copy_network_unit(
                '26-bridge.netdev', '26-bridge-slave-interface-1.network',
               '25-bridge99-ignore-carrier-loss.network')
        common.start_networkd()
        self.wait_online(['bridge99:no-carrier'])

        for trial in range(4):
            common.check_output('ip link add dummy98 type dummy')
            common.check_output('ip link set dummy98 up')
            if trial < 3:
                common.remove_link('dummy98')

        self.wait_online(['bridge99:routable', 'dummy98:enslaved'])

        output = common.check_output('ip address show bridge99')
        print(output)
        self.assertRegex(output, 'inet 192.168.0.15/24 brd 192.168.0.255 scope global bridge99')

        output = common.check_output('ip rule list table 100')
        print(output)
        self.assertIn('from all to 8.8.8.8 lookup 100', output)
