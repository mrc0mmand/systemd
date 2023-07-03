# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import os
import unittest

import common


class NetworkdSRIOVTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    @common.expectedFailureIfNetdevsimWithSRIOVIsNotAvailable()
    def test_sriov(self):
        common.copy_network_unit('25-default.link', '25-sriov.network')

        common.call('modprobe netdevsim')

        with open('/sys/bus/netdevsim/new_device', mode='w', encoding='utf-8') as f:
            f.write('99 1')

        with open('/sys/bus/netdevsim/devices/netdevsim99/sriov_numvfs', mode='w', encoding='utf-8') as f:
            f.write('3')

        common.start_networkd()
        self.wait_online(['eni99np1:routable'])

        output = common.check_output('ip link show dev eni99np1')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off\n *'
                         'vf 2 .*00:11:22:33:44:57.*vlan 7, qos 3, spoof checking off, link-state auto, trust off, query_rss off'
                         )

    @common.expectedFailureIfNetdevsimWithSRIOVIsNotAvailable()
    def test_sriov_udev(self):
        common.copy_network_unit('25-sriov.link', '25-sriov-udev.network')

        common.call('modprobe netdevsim')

        with open('/sys/bus/netdevsim/new_device', mode='w', encoding='utf-8') as f:
            f.write('99 1')

        common.start_networkd()
        self.wait_online(['eni99np1:routable'])

        # the name eni99np1 may be an alternative name.
        ifname = common.link_resolve('eni99np1')

        output = common.check_output('ip link show dev eni99np1')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off\n *'
                         'vf 2 .*00:11:22:33:44:57.*vlan 7, qos 3, spoof checking off, link-state auto, trust off, query_rss off'
                         )
        self.assertNotIn('vf 3', output)
        self.assertNotIn('vf 4', output)

        with open(os.path.join(common.network_unit_dir, '25-sriov.link'), mode='a', encoding='utf-8') as f:
            f.write('[Link]\nSR-IOVVirtualFunctions=4\n')

        common.udev_reload()
        common.check_output(*common.udevadm_cmd, 'trigger', '--action=add', '--settle', f'/sys/devices/netdevsim99/net/{ifname}')

        output = common.check_output('ip link show dev eni99np1')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off\n *'
                         'vf 2 .*00:11:22:33:44:57.*vlan 7, qos 3, spoof checking off, link-state auto, trust off, query_rss off\n *'
                         'vf 3'
                         )
        self.assertNotIn('vf 4', output)

        with open(os.path.join(common.network_unit_dir, '25-sriov.link'), mode='a', encoding='utf-8') as f:
            f.write('[Link]\nSR-IOVVirtualFunctions=\n')

        common.udev_reload()
        common.check_output(*common.udevadm_cmd, 'trigger', '--action=add', '--settle', f'/sys/devices/netdevsim99/net/{ifname}')

        output = common.check_output('ip link show dev eni99np1')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off\n *'
                         'vf 2 .*00:11:22:33:44:57.*vlan 7, qos 3, spoof checking off, link-state auto, trust off, query_rss off\n *'
                         'vf 3'
                         )
        self.assertNotIn('vf 4', output)

        with open(os.path.join(common.network_unit_dir, '25-sriov.link'), mode='a', encoding='utf-8') as f:
            f.write('[Link]\nSR-IOVVirtualFunctions=2\n')

        common.udev_reload()
        common.check_output(*common.udevadm_cmd, 'trigger', '--action=add', '--settle', f'/sys/devices/netdevsim99/net/{ifname}')

        output = common.check_output('ip link show dev eni99np1')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off'
                         )
        self.assertNotIn('vf 2', output)
        self.assertNotIn('vf 3', output)
        self.assertNotIn('vf 4', output)

        with open(os.path.join(common.network_unit_dir, '25-sriov.link'), mode='a', encoding='utf-8') as f:
            f.write('[Link]\nSR-IOVVirtualFunctions=\n')

        common.udev_reload()
        common.check_output(*common.udevadm_cmd, 'trigger', '--action=add', '--settle', f'/sys/devices/netdevsim99/net/{ifname}')

        output = common.check_output('ip link show dev eni99np1')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off\n *'
                         'vf 2 .*00:11:22:33:44:57.*vlan 7, qos 3, spoof checking off, link-state auto, trust off, query_rss off'
                         )
        self.assertNotIn('vf 3', output)
        self.assertNotIn('vf 4', output)
