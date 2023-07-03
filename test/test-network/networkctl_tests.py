# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import unittest

import common


class NetworkctlTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    @common.expectedFailureIfAlternativeNameIsNotAvailable()
    def test_altname(self):
        common.copy_network_unit('26-netdev-link-local-addressing-yes.network', '12-dummy.netdev', '12-dummy.link')
        common.start_networkd()
        self.wait_online(['dummy98:degraded'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'dummy98', env=common.env)
        self.assertRegex(output, 'hogehogehogehogehogehoge')

    @common.expectedFailureIfAlternativeNameIsNotAvailable()
    def test_rename_to_altname(self):
        common.copy_network_unit(
                '26-netdev-link-local-addressing-yes.network',
                '12-dummy.netdev', '12-dummy-rename-to-altname.link')
        common.start_networkd()
        self.wait_online(['dummyalt:degraded'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'dummyalt', env=common.env)
        self.assertIn('hogehogehogehogehogehoge', output)
        self.assertNotIn('dummy98', output)

    def test_reconfigure(self):
        common.copy_network_unit('25-address-static.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertIn('inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98', output)
        self.assertIn('inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98', output)
        self.assertIn('inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98', output)

        common.check_output('ip address del 10.1.2.3/16 dev dummy98')
        common.check_output('ip address del 10.1.2.4/16 dev dummy98')
        common.check_output('ip address del 10.2.2.4/16 dev dummy98')

        common.networkctl_reconfigure('dummy98')
        self.wait_online(['dummy98:routable'])

        output = common.check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertIn('inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98', output)
        self.assertIn('inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98', output)
        self.assertIn('inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98', output)

        common.remove_network_unit('25-address-static.network')

        common.networkctl_reload()
        self.wait_operstate('dummy98', 'degraded', setup_state='unmanaged')

        output = common.check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertNotIn('inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98', output)
        self.assertNotIn('inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98', output)
        self.assertNotIn('inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98', output)

        common.copy_network_unit('25-address-static.network')
        common.networkctl_reload()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertIn('inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98', output)
        self.assertIn('inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98', output)
        self.assertIn('inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98', output)

    def test_reload(self):
        common.start_networkd()

        common.copy_network_unit('11-dummy.netdev')
        common.networkctl_reload()
        self.wait_operstate('test1', 'off', setup_state='unmanaged')

        common.copy_network_unit('11-dummy.network')
        common.networkctl_reload()
        self.wait_online(['test1:degraded'])

        common.remove_network_unit('11-dummy.network')
        common.networkctl_reload()
        self.wait_operstate('test1', 'degraded', setup_state='unmanaged')

        common.remove_network_unit('11-dummy.netdev')
        common.networkctl_reload()
        self.wait_operstate('test1', 'degraded', setup_state='unmanaged')

        common.copy_network_unit('11-dummy.netdev', '11-dummy.network')
        common.networkctl_reload()
        self.wait_operstate('test1', 'degraded')

    def test_glob(self):
        common.copy_network_unit('11-dummy.netdev', '11-dummy.network')
        common.start_networkd()

        self.wait_online(['test1:degraded'])

        output = common.check_output(*common.networkctl_cmd, 'list', env=common.env)
        self.assertRegex(output, '1 lo ')
        self.assertRegex(output, 'test1')

        output = common.check_output(*common.networkctl_cmd, 'list', 'test1', env=common.env)
        self.assertNotRegex(output, '1 lo ')
        self.assertRegex(output, 'test1')

        output = common.check_output(*common.networkctl_cmd, 'list', 'te*', env=common.env)
        self.assertNotRegex(output, '1 lo ')
        self.assertRegex(output, 'test1')

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'te*', env=common.env)
        self.assertNotRegex(output, '1: lo ')
        self.assertRegex(output, 'test1')

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'tes[a-z][0-9]', env=common.env)
        self.assertNotRegex(output, '1: lo ')
        self.assertRegex(output, 'test1')

    def test_mtu(self):
        common.copy_network_unit('11-dummy-mtu.netdev', '11-dummy.network')
        common.start_networkd()

        self.wait_online(['test1:degraded'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'test1', env=common.env)
        self.assertRegex(output, 'MTU: 1600')

    def test_type(self):
        common.copy_network_unit('11-dummy.netdev', '11-dummy.network')
        common.start_networkd()
        self.wait_online(['test1:degraded'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'test1', env=common.env)
        print(output)
        self.assertRegex(output, 'Type: ether')

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'lo', env=common.env)
        print(output)
        self.assertRegex(output, 'Type: loopback')

    def test_udev_link_file(self):
        common.copy_network_unit('11-dummy.netdev', '11-dummy.network', '25-default.link')
        common.start_networkd()
        self.wait_online(['test1:degraded'])

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'test1', env=common.env)
        print(output)
        self.assertRegex(output, r'Link File: /run/systemd/network/25-default.link')
        self.assertRegex(output, r'Network File: /run/systemd/network/11-dummy.network')

        # This test may be run on the system that has older udevd than 70f32a260b5ebb68c19ecadf5d69b3844896ba55 (v249).
        # In that case, the udev DB for the loopback network interface may already have ID_NET_LINK_FILE property.
        # Let's reprocess the interface and drop the property.
        common.check_output(*common.udevadm_cmd, 'trigger', '--settle', '--action=add', '/sys/class/net/lo')
        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'lo', env=common.env)
        print(output)
        self.assertRegex(output, r'Link File: n/a')
        self.assertRegex(output, r'Network File: n/a')

    def test_delete_links(self):
        common.copy_network_unit(
                '11-dummy.netdev', '11-dummy.network',
                '25-veth.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['test1:degraded', 'veth99:degraded', 'veth-peer:degraded'])

        common.check_output(*common.networkctl_cmd, 'delete', 'test1', 'veth99', env=common.env)
        self.check_link_exists('test1', expected=False)
        self.check_link_exists('veth99', expected=False)
        self.check_link_exists('veth-peer', expected=False)
