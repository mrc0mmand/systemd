# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import os
import unittest

import common


class NetworkdBondTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_bond_keep_master(self):
        common.check_output('ip link add bond199 type bond mode active-backup')
        common.check_output('ip link add dummy98 type dummy')
        common.check_output('ip link set dummy98 master bond199')

        common.copy_network_unit('23-keep-master.network')
        common.start_networkd()
        self.wait_online(['dummy98:enslaved'])

        output = common.check_output('ip -d link show bond199')
        print(output)
        self.assertRegex(output, 'active_slave dummy98')

        output = common.check_output('ip -d link show dummy98')
        print(output)
        self.assertRegex(output, 'master bond199')

    def test_bond_active_slave(self):
        common.copy_network_unit('23-active-slave.network', '23-bond199.network', '25-bond-active-backup-slave.netdev', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:enslaved', 'bond199:degraded'])

        output = common.check_output('ip -d link show bond199')
        print(output)
        self.assertIn('active_slave dummy98', output)

    def test_bond_primary_slave(self):
        common.copy_network_unit('23-primary-slave.network', '23-bond199.network', '25-bond-active-backup-slave.netdev', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:enslaved', 'bond199:degraded'])

        output = common.check_output('ip -d link show bond199')
        print(output)
        self.assertIn('primary dummy98', output)

        # for issue #25627
        common.mkdir_p(os.path.join(common.network_unit_dir, '23-bond199.network.d'))
        for mac in ['00:11:22:33:44:55', '00:11:22:33:44:56']:
            with open(os.path.join(common.network_unit_dir, '23-bond199.network.d/mac.conf'), mode='w', encoding='utf-8') as f:
                f.write(f'[Link]\nMACAddress={mac}\n')

            common.networkctl_reload()
            self.wait_online(['dummy98:enslaved', 'bond199:degraded'])

            output = common.check_output('ip -d link show bond199')
            print(output)
            self.assertIn(f'link/ether {mac}', output)

    def test_bond_operstate(self):
        common.copy_network_unit(
                '25-bond.netdev', '11-dummy.netdev', '12-dummy.netdev',
                '25-bond99.network', '25-bond-slave.network')
        common.start_networkd()
        self.wait_online(['dummy98:enslaved', 'test1:enslaved', 'bond99:routable'])

        output = common.check_output('ip -d link show dummy98')
        print(output)
        self.assertRegex(output, 'SLAVE,UP,LOWER_UP')

        output = common.check_output('ip -d link show test1')
        print(output)
        self.assertRegex(output, 'SLAVE,UP,LOWER_UP')

        output = common.check_output('ip -d link show bond99')
        print(output)
        self.assertRegex(output, 'MASTER,UP,LOWER_UP')

        self.wait_operstate('dummy98', 'enslaved')
        self.wait_operstate('test1', 'enslaved')
        self.wait_operstate('bond99', 'routable')

        common.check_output('ip link set dummy98 down')

        self.wait_operstate('dummy98', 'off')
        self.wait_operstate('test1', 'enslaved')
        self.wait_operstate('bond99', 'routable')

        common.check_output('ip link set dummy98 up')

        self.wait_operstate('dummy98', 'enslaved')
        self.wait_operstate('test1', 'enslaved')
        self.wait_operstate('bond99', 'routable')

        common.check_output('ip link set dummy98 down')
        common.check_output('ip link set test1 down')

        self.wait_operstate('dummy98', 'off')
        self.wait_operstate('test1', 'off')

        if not self.wait_operstate('bond99', 'no-carrier', setup_timeout=30, fail_assert=False):
            # Huh? Kernel does not recognize that all slave interfaces are down?
            # Let's confirm that networkd's operstate is consistent with ip's result.
            self.assertNotRegex(output, 'NO-CARRIER')
