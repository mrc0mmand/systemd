# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import unittest

import common


class NetworkdMTUTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def check_mtu(self, mtu, ipv6_mtu=None, reset=True):
        if not ipv6_mtu:
            ipv6_mtu = mtu

        # test normal start
        common.start_networkd()
        self.wait_online(['dummy98:routable'])
        self.check_link_attr('dummy98', 'mtu', mtu)
        self.check_ipv6_sysctl_attr('dummy98', 'mtu', ipv6_mtu)

        # test normal restart
        common.start_networkd()
        self.wait_online(['dummy98:routable'])
        self.check_link_attr('dummy98', 'mtu', mtu)
        self.check_ipv6_sysctl_attr('dummy98', 'mtu', ipv6_mtu)

        if reset:
            self.reset_check_mtu(mtu, ipv6_mtu)

    def reset_check_mtu(self, mtu, ipv6_mtu=None):
        ''' test setting mtu/ipv6_mtu with interface already up '''
        common.stop_networkd()

        # note - changing the device mtu resets the ipv6 mtu
        common.check_output('ip link set up mtu 1501 dev dummy98')
        common.check_output('ip link set up mtu 1500 dev dummy98')
        self.check_link_attr('dummy98', 'mtu', '1500')
        self.check_ipv6_sysctl_attr('dummy98', 'mtu', '1500')

        self.check_mtu(mtu, ipv6_mtu, reset=False)

    def test_mtu_network(self):
        common.copy_network_unit('12-dummy.netdev', '12-dummy.network.d/mtu.conf')
        self.check_mtu('1600')

    def test_mtu_netdev(self):
        common.copy_network_unit('12-dummy-mtu.netdev', '12-dummy.network', copy_dropins=False)
        # note - MTU set by .netdev happens ONLY at device creation!
        self.check_mtu('1600', reset=False)

    def test_mtu_link(self):
        common.copy_network_unit('12-dummy.netdev', '12-dummy-mtu.link', '12-dummy.network', copy_dropins=False)
        # note - MTU set by .link happens ONLY at udev processing of device 'add' uevent!
        self.check_mtu('1600', reset=False)

    def test_ipv6_mtu(self):
        ''' set ipv6 mtu without setting device mtu '''
        common.copy_network_unit('12-dummy.netdev', '12-dummy.network.d/ipv6-mtu-1400.conf')
        self.check_mtu('1500', '1400')

    def test_ipv6_mtu_toolarge(self):
        ''' try set ipv6 mtu over device mtu (it shouldn't work) '''
        common.copy_network_unit('12-dummy.netdev', '12-dummy.network.d/ipv6-mtu-1550.conf')
        self.check_mtu('1500', '1500')

    def test_mtu_network_ipv6_mtu(self):
        ''' set ipv6 mtu and set device mtu via network file '''
        common.copy_network_unit('12-dummy.netdev', '12-dummy.network.d/mtu.conf', '12-dummy.network.d/ipv6-mtu-1550.conf')
        self.check_mtu('1600', '1550')

    def test_mtu_netdev_ipv6_mtu(self):
        ''' set ipv6 mtu and set device mtu via netdev file '''
        common.copy_network_unit('12-dummy-mtu.netdev', '12-dummy.network.d/ipv6-mtu-1550.conf')
        self.check_mtu('1600', '1550', reset=False)

    def test_mtu_link_ipv6_mtu(self):
        ''' set ipv6 mtu and set device mtu via link file '''
        common.copy_network_unit('12-dummy.netdev', '12-dummy-mtu.link', '12-dummy.network.d/ipv6-mtu-1550.conf')
        self.check_mtu('1600', '1550', reset=False)
