# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import unittest

import common


class NetworkdTCTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    @common.expectedFailureIfModuleIsNotAvailable('sch_cake')
    def test_qdisc_cake(self):
        common.copy_network_unit('25-qdisc-cake.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertIn('qdisc cake 3a: root', output)
        self.assertIn('bandwidth 500Mbit', output)
        self.assertIn('autorate-ingress', output)
        self.assertIn('diffserv8', output)
        self.assertIn('dual-dsthost', output)
        self.assertIn(' nat', output)
        self.assertIn(' wash', output)
        self.assertIn(' split-gso', output)
        self.assertIn(' raw', output)
        self.assertIn(' atm', output)
        self.assertIn('overhead 128', output)
        self.assertIn('mpu 20', output)
        self.assertIn('fwmark 0xff00', output)
        self.assertIn('rtt 1s', output)
        self.assertIn('ack-filter-aggressive', output)

    @common.expectedFailureIfModuleIsNotAvailable('sch_codel')
    def test_qdisc_codel(self):
        common.copy_network_unit('25-qdisc-codel.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc codel 33: root')
        self.assertRegex(output, 'limit 2000p target 10(.0)?ms ce_threshold 100(.0)?ms interval 50(.0)?ms ecn')

    @common.expectedFailureIfModuleIsNotAvailable('sch_drr')
    def test_qdisc_drr(self):
        common.copy_network_unit('25-qdisc-drr.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc drr 2: root')
        output = common.check_output('tc class show dev dummy98')
        print(output)
        self.assertRegex(output, 'class drr 2:30 root quantum 2000b')

    @common.expectedFailureIfModuleIsNotAvailable('sch_ets')
    def test_qdisc_ets(self):
        common.copy_network_unit('25-qdisc-ets.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)

        self.assertRegex(output, 'qdisc ets 3a: root')
        self.assertRegex(output, 'bands 10 strict 3')
        self.assertRegex(output, 'quanta 1 2 3 4 5')
        self.assertRegex(output, 'priomap 3 4 5 6 7')

    @common.expectedFailureIfModuleIsNotAvailable('sch_fq')
    def test_qdisc_fq(self):
        common.copy_network_unit('25-qdisc-fq.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc fq 32: root')
        self.assertRegex(output, 'limit 1000p flow_limit 200p buckets 512 orphan_mask 511')
        self.assertRegex(output, 'quantum 1500')
        self.assertRegex(output, 'initial_quantum 13000')
        self.assertRegex(output, 'maxrate 1Mbit')

    @common.expectedFailureIfModuleIsNotAvailable('sch_fq_codel')
    def test_qdisc_fq_codel(self):
        common.copy_network_unit('25-qdisc-fq_codel.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc fq_codel 34: root')
        self.assertRegex(output, 'limit 20480p flows 2048 quantum 1400 target 10(.0)?ms ce_threshold 100(.0)?ms interval 200(.0)?ms memory_limit 64Mb ecn')

    @common.expectedFailureIfModuleIsNotAvailable('sch_fq_pie')
    def test_qdisc_fq_pie(self):
        common.copy_network_unit('25-qdisc-fq_pie.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)

        self.assertRegex(output, 'qdisc fq_pie 3a: root')
        self.assertRegex(output, 'limit 200000p')

    @common.expectedFailureIfModuleIsNotAvailable('sch_gred')
    def test_qdisc_gred(self):
        common.copy_network_unit('25-qdisc-gred.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc gred 38: root')
        self.assertRegex(output, 'vqs 12 default 10 grio')

    @common.expectedFailureIfModuleIsNotAvailable('sch_hhf')
    def test_qdisc_hhf(self):
        common.copy_network_unit('25-qdisc-hhf.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc hhf 3a: root')
        self.assertRegex(output, 'limit 1022p')

    @common.expectedFailureIfModuleIsNotAvailable('sch_htb')
    def test_qdisc_htb_fifo(self):
        common.copy_network_unit('25-qdisc-htb-fifo.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc htb 2: root')
        self.assertRegex(output, r'default (0x30|30)')

        self.assertRegex(output, 'qdisc pfifo 37: parent 2:37')
        self.assertRegex(output, 'limit 100000p')

        self.assertRegex(output, 'qdisc bfifo 3a: parent 2:3a')
        self.assertRegex(output, 'limit 1000000')

        self.assertRegex(output, 'qdisc pfifo_head_drop 3b: parent 2:3b')
        self.assertRegex(output, 'limit 1023p')

        self.assertRegex(output, 'qdisc pfifo_fast 3c: parent 2:3c')

        output = common.check_output('tc -d class show dev dummy98')
        print(output)
        # Here (:|prio) is a workaround for a bug in iproute2 v6.2.0 caused by
        # https://github.com/shemminger/iproute2/commit/010a8388aea11e767ba3a2506728b9ad9760df0e
        # which is fixed in v6.3.0 by
        # https://github.com/shemminger/iproute2/commit/4e0e56e0ef05387f7f5d8ab41fe6ec6a1897b26d
        self.assertRegex(output, 'class htb 2:37 root leaf 37(:|prio) ')
        self.assertRegex(output, 'class htb 2:3a root leaf 3a(:|prio) ')
        self.assertRegex(output, 'class htb 2:3b root leaf 3b(:|prio) ')
        self.assertRegex(output, 'class htb 2:3c root leaf 3c(:|prio) ')
        self.assertRegex(output, 'prio 1 quantum 4000 rate 1Mbit overhead 100 ceil 500Kbit')
        self.assertRegex(output, 'burst 123456')
        self.assertRegex(output, 'cburst 123457')

    @common.expectedFailureIfModuleIsNotAvailable('sch_ingress')
    def test_qdisc_ingress(self):
        common.copy_network_unit('25-qdisc-clsact.network', '12-dummy.netdev',
                          '25-qdisc-ingress.network', '11-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable', 'test1:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc clsact')

        output = common.check_output('tc qdisc show dev test1')
        print(output)
        self.assertRegex(output, 'qdisc ingress')

    @common.expectedFailureIfModuleIsNotAvailable('sch_netem')
    def test_qdisc_netem(self):
        common.copy_network_unit('25-qdisc-netem.network', '12-dummy.netdev',
                          '25-qdisc-netem-compat.network', '11-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable', 'test1:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc netem 30: root')
        self.assertRegex(output, 'limit 100 delay 50(.0)?ms  10(.0)?ms loss 20%')

        output = common.check_output('tc qdisc show dev test1')
        print(output)
        self.assertRegex(output, 'qdisc netem [0-9a-f]*: root')
        self.assertRegex(output, 'limit 100 delay 50(.0)?ms  10(.0)?ms loss 20%')

    @common.expectedFailureIfModuleIsNotAvailable('sch_pie')
    def test_qdisc_pie(self):
        common.copy_network_unit('25-qdisc-pie.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc pie 3a: root')
        self.assertRegex(output, 'limit 200000')

    @common.expectedFailureIfModuleIsNotAvailable('sch_qfq')
    def test_qdisc_qfq(self):
        common.copy_network_unit('25-qdisc-qfq.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc qfq 2: root')
        output = common.check_output('tc class show dev dummy98')
        print(output)
        self.assertRegex(output, 'class qfq 2:30 root weight 2 maxpkt 16000')
        self.assertRegex(output, 'class qfq 2:31 root weight 10 maxpkt 8000')

    @common.expectedFailureIfModuleIsNotAvailable('sch_sfb')
    def test_qdisc_sfb(self):
        common.copy_network_unit('25-qdisc-sfb.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc sfb 39: root')
        self.assertRegex(output, 'limit 200000')

    @common.expectedFailureIfModuleIsNotAvailable('sch_sfq')
    def test_qdisc_sfq(self):
        common.copy_network_unit('25-qdisc-sfq.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc sfq 36: root')
        self.assertRegex(output, 'perturb 5sec')

    @common.expectedFailureIfModuleIsNotAvailable('sch_tbf')
    def test_qdisc_tbf(self):
        common.copy_network_unit('25-qdisc-tbf.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc tbf 35: root')
        self.assertRegex(output, 'rate 1Gbit burst 5000b peakrate 100Gbit minburst 987500b lat 70(.0)?ms')

    @common.expectedFailureIfModuleIsNotAvailable('sch_teql')
    def test_qdisc_teql(self):
        common.call_quiet('rmmod sch_teql')

        common.copy_network_unit('25-qdisc-teql.network', '12-dummy.netdev')
        common.start_networkd()
        self.wait_links('dummy98')
        common.check_output('modprobe sch_teql max_equalizers=2')
        self.wait_online(['dummy98:routable'])

        output = common.check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc teql1 31: root')
