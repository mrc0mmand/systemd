# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import os
import re
import shutil
import time
import unittest

import common
import psutil


class NetworkdNetDevTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_dropin_and_name_conflict(self):
        common.copy_network_unit('10-dropin-test.netdev', '15-name-conflict-test.netdev')
        common.start_networkd()

        self.wait_online(['dropin-test:off'], setup_state='unmanaged')

        output = common.check_output('ip link show dropin-test')
        print(output)
        self.assertRegex(output, '00:50:56:c0:00:28')

    @common.expectedFailureIfModuleIsNotAvailable('bareudp')
    def test_bareudp(self):
        common.copy_network_unit('25-bareudp.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['bareudp99:degraded'])

        output = common.check_output('ip -d link show bareudp99')
        print(output)
        self.assertRegex(output, 'dstport 1000 ')
        self.assertRegex(output, 'ethertype ip ')

    @common.expectedFailureIfModuleIsNotAvailable('batman-adv')
    def test_batadv(self):
        common.copy_network_unit('25-batadv.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['batadv99:degraded'])

        output = common.check_output('ip -d link show batadv99')
        print(output)
        self.assertRegex(output, 'batadv')

    def test_bridge(self):
        common.copy_network_unit('25-bridge.netdev', '25-bridge-configure-without-carrier.network')
        common.start_networkd()

        self.wait_online(['bridge99:no-carrier'])

        tick = os.sysconf('SC_CLK_TCK')
        self.assertEqual(9, round(float(common.read_link_attr('bridge99', 'bridge', 'hello_time')) / tick))
        self.assertEqual(9, round(float(common.read_link_attr('bridge99', 'bridge', 'max_age')) / tick))
        self.assertEqual(9, round(float(common.read_link_attr('bridge99', 'bridge', 'forward_delay')) / tick))
        self.assertEqual(9, round(float(common.read_link_attr('bridge99', 'bridge', 'ageing_time')) / tick))
        self.assertEqual(9,         int(common.read_link_attr('bridge99', 'bridge', 'priority')))
        self.assertEqual(1,         int(common.read_link_attr('bridge99', 'bridge', 'multicast_querier')))
        self.assertEqual(1,         int(common.read_link_attr('bridge99', 'bridge', 'multicast_snooping')))
        self.assertEqual(1,         int(common.read_link_attr('bridge99', 'bridge', 'stp_state')))
        self.assertEqual(3,         int(common.read_link_attr('bridge99', 'bridge', 'multicast_igmp_version')))

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'bridge99', env=common.env)
        print(output)
        self.assertRegex(output, 'Priority: 9')
        self.assertRegex(output, 'STP: yes')
        self.assertRegex(output, 'Multicast IGMP Version: 3')

        output = common.check_output('ip -d link show bridge99')
        print(output)
        self.assertIn('vlan_filtering 1 ', output)
        self.assertIn('vlan_protocol 802.1ad ', output)
        self.assertIn('vlan_default_pvid 9 ', output)

    def test_bond(self):
        common.copy_network_unit('25-bond.netdev', '25-bond-balanced-tlb.netdev')
        common.start_networkd()

        self.wait_online(['bond99:off', 'bond98:off'], setup_state='unmanaged')

        self.check_link_attr('bond99', 'bonding', 'mode',              '802.3ad 4')
        self.check_link_attr('bond99', 'bonding', 'xmit_hash_policy',  'layer3+4 1')
        self.check_link_attr('bond99', 'bonding', 'miimon',            '1000')
        self.check_link_attr('bond99', 'bonding', 'lacommon.cp_rate',         'fast 1')
        self.check_link_attr('bond99', 'bonding', 'updelay',           '2000')
        self.check_link_attr('bond99', 'bonding', 'downdelay',         '2000')
        self.check_link_attr('bond99', 'bonding', 'resend_igmp',       '4')
        self.check_link_attr('bond99', 'bonding', 'min_links',         '1')
        self.check_link_attr('bond99', 'bonding', 'ad_actor_sys_prio', '1218')
        self.check_link_attr('bond99', 'bonding', 'ad_user_port_key',  '811')
        self.check_link_attr('bond99', 'bonding', 'ad_actor_system',   '00:11:22:33:44:55')

        self.check_link_attr('bond98', 'bonding', 'mode',              'balance-tlb 5')
        self.check_link_attr('bond98', 'bonding', 'tlb_dynamic_lb',    '1')

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'bond99', env=common.env)
        print(output)
        self.assertIn('Mode: 802.3ad', output)
        self.assertIn('Miimon: 1s', output)
        self.assertIn('Updelay: 2s', output)
        self.assertIn('Downdelay: 2s', output)

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'bond98', env=common.env)
        print(output)
        self.assertIn('Mode: balance-tlb', output)

    def test_vlan(self):
        common.copy_network_unit('21-vlan.netdev', '11-dummy.netdev',
                          '21-vlan.network', '21-vlan-test1.network')
        common.start_networkd()

        self.wait_online(['test1:degraded', 'vlan99:routable'])

        output = common.check_output('ip -d link show test1')
        print(output)
        self.assertRegex(output, ' mtu 2000 ')

        output = common.check_output('ip -d link show vlan99')
        print(output)
        self.assertIn(' mtu 2000 ', output)
        self.assertIn('REORDER_HDR', output)
        self.assertIn('LOOSE_BINDING', output)
        self.assertIn('GVRP', output)
        self.assertIn('MVRP', output)
        self.assertIn(' id 99 ', output)
        self.assertIn('ingress-qos-map { 4:100 7:13 }', output)
        self.assertIn('egress-qos-map { 0:1 1:3 6:6 7:7 10:3 }', output)

        output = common.check_output('ip -4 address show dev test1')
        print(output)
        self.assertRegex(output, 'inet 192.168.24.5/24 brd 192.168.24.255 scope global test1')
        self.assertRegex(output, 'inet 192.168.25.5/24 brd 192.168.25.255 scope global test1')

        output = common.check_output('ip -4 address show dev vlan99')
        print(output)
        self.assertRegex(output, 'inet 192.168.23.5/24 brd 192.168.23.255 scope global vlan99')

    def test_vlan_on_bond(self):
        # For issue #24377 (https://github.com/systemd/systemd/issues/24377),
        # which is fixed by b05e52000b4eee764b383cc3031da0a3739e996e (PR#24020).

        common.copy_network_unit(
                '21-bond-802.3ad.netdev', '21-bond-802.3ad.network',
                '21-vlan-on-bond.netdev', '21-vlan-on-bond.network')
        common.start_networkd()
        self.wait_online(['bond99:off'])
        self.wait_operstate('vlan99', operstate='off', setup_state='configuring', setup_timeout=10)

        # The commit b05e52000b4eee764b383cc3031da0a3739e996e adds ", ignoring". To make it easily confirmed
        # that the issue is fixed by the commit, let's allow to match both string.
        log_re = re.compile('vlan99: Could not bring up interface(, ignoring|): Network is down$', re.MULTILINE)
        for i in range(20):
            if i > 0:
                time.sleep(0.5)
            if log_re.search(common.read_networkd_log()):
                break
        else:
            self.fail()

        common.copy_network_unit('11-dummy.netdev', '12-dummy.netdev', '21-dummy-bond-slave.network')
        common.networkctl_reload()
        self.wait_online(['test1:enslaved', 'dummy98:enslaved', 'bond99:carrier', 'vlan99:routable'])

    def test_macvtap(self):
        first = True
        for mode in ['private', 'vepa', 'bridge', 'passthru']:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_macvtap(mode={mode})')
            with self.subTest(mode=mode):
                common.copy_network_unit(
                        '21-macvtap.netdev', '26-netdev-link-local-addressing-yes.network',
                        '11-dummy.netdev', '25-macvtap.network')
                with open(os.path.join(common.network_unit_dir, '21-macvtap.netdev'), mode='a', encoding='utf-8') as f:
                    f.write('[MACVTAP]\nMode=' + mode)
                common.start_networkd()

                self.wait_online(['macvtap99:degraded',
                                  'test1:carrier' if mode == 'passthru' else 'test1:degraded'])

                output = common.check_output('ip -d link show macvtap99')
                print(output)
                self.assertRegex(output, 'macvtap mode ' + mode + ' ')

    def test_macvlan(self):
        first = True
        for mode in ['private', 'vepa', 'bridge', 'passthru']:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_macvlan(mode={mode})')
            with self.subTest(mode=mode):
                common.copy_network_unit(
                        '21-macvlan.netdev', '26-netdev-link-local-addressing-yes.network',
                        '11-dummy.netdev', '25-macvlan.network')
                with open(os.path.join(common.network_unit_dir, '21-macvlan.netdev'), mode='a', encoding='utf-8') as f:
                    f.write('[MACVLAN]\nMode=' + mode)
                common.start_networkd()

                self.wait_online(['macvlan99:degraded',
                                  'test1:carrier' if mode == 'passthru' else 'test1:degraded'])

                output = common.check_output('ip -d link show test1')
                print(output)
                self.assertRegex(output, ' mtu 2000 ')

                output = common.check_output('ip -d link show macvlan99')
                print(output)
                self.assertRegex(output, ' mtu 2000 ')
                self.assertRegex(output, 'macvlan mode ' + mode + ' ')

                common.remove_link('test1')
                time.sleep(1)

                common.check_output("ip link add test1 type dummy")
                self.wait_online(['macvlan99:degraded',
                                  'test1:carrier' if mode == 'passthru' else 'test1:degraded'])

                output = common.check_output('ip -d link show test1')
                print(output)
                self.assertRegex(output, ' mtu 2000 ')

                output = common.check_output('ip -d link show macvlan99')
                print(output)
                self.assertRegex(output, ' mtu 2000 ')
                self.assertRegex(output, 'macvlan mode ' + mode + ' ')

    @common.expectedFailureIfModuleIsNotAvailable('ipvlan')
    def test_ipvlan(self):
        first = True
        for mode, flag in [['L2', 'private'], ['L3', 'vepa'], ['L3S', 'bridge']]:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_ipvlan(mode={mode}, flag={flag})')
            with self.subTest(mode=mode, flag=flag):
                common.copy_network_unit(
                        '25-ipvlan.netdev', '26-netdev-link-local-addressing-yes.network',
                        '11-dummy.netdev', '25-ipvlan.network')
                with open(os.path.join(common.network_unit_dir, '25-ipvlan.netdev'), mode='a', encoding='utf-8') as f:
                    f.write('[IPVLAN]\nMode=' + mode + '\nFlags=' + flag)

                common.start_networkd()
                self.wait_online(['ipvlan99:degraded', 'test1:degraded'])

                output = common.check_output('ip -d link show ipvlan99')
                print(output)
                self.assertRegex(output, 'ipvlan  *mode ' + mode.lower() + ' ' + flag)

    @common.expectedFailureIfModuleIsNotAvailable('ipvtap')
    def test_ipvtap(self):
        first = True
        for mode, flag in [['L2', 'private'], ['L3', 'vepa'], ['L3S', 'bridge']]:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_ipvtap(mode={mode}, flag={flag})')
            with self.subTest(mode=mode, flag=flag):
                common.copy_network_unit(
                        '25-ipvtap.netdev', '26-netdev-link-local-addressing-yes.network',
                        '11-dummy.netdev', '25-ipvtap.network')
                with open(os.path.join(common.network_unit_dir, '25-ipvtap.netdev'), mode='a', encoding='utf-8') as f:
                    f.write('[IPVTAP]\nMode=' + mode + '\nFlags=' + flag)

                common.start_networkd()
                self.wait_online(['ipvtap99:degraded', 'test1:degraded'])

                output = common.check_output('ip -d link show ipvtap99')
                print(output)
                self.assertRegex(output, 'ipvtap  *mode ' + mode.lower() + ' ' + flag)

    def test_veth(self):
        common.copy_network_unit(
                '25-veth.netdev', '26-netdev-link-local-addressing-yes.network',
                '25-veth-mtu.netdev')
        common.start_networkd()

        self.wait_online(['veth99:degraded', 'veth-peer:degraded', 'veth-mtu:degraded', 'veth-mtu-peer:degraded'])

        output = common.check_output('ip -d link show veth99')
        print(output)
        self.assertRegex(output, 'link/ether 12:34:56:78:9a:bc')
        output = common.check_output('ip -d link show veth-peer')
        print(output)
        self.assertRegex(output, 'link/ether 12:34:56:78:9a:bd')

        output = common.check_output('ip -d link show veth-mtu')
        print(output)
        self.assertRegex(output, 'link/ether 12:34:56:78:9a:be')
        self.assertRegex(output, 'mtu 1800')
        output = common.check_output('ip -d link show veth-mtu-peer')
        print(output)
        self.assertRegex(output, 'link/ether 12:34:56:78:9a:bf')
        self.assertRegex(output, 'mtu 1800')

    def test_tuntap(self):
        common.copy_network_unit('25-tun.netdev', '25-tap.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['testtun99:degraded', 'testtap99:degraded'])

        pid = common.networkd_pid()
        name = psutil.Process(pid).name()[:15]

        output = common.check_output('ip -d tuntap show')
        print(output)
        self.assertRegex(output, fr'(?m)testtap99: tap pi (multi_queue |)vnet_hdr persist filter *(0x100|)\n\tAttached to processes:{name}\({pid}\)systemd\(1\)$')
        self.assertRegex(output, fr'(?m)testtun99: tun pi (multi_queue |)vnet_hdr persist filter *(0x100|)\n\tAttached to processes:{name}\({pid}\)systemd\(1\)$')

        output = common.check_output('ip -d link show testtun99')
        print(output)
        # Old ip command does not support IFF_ flags
        self.assertRegex(output, 'tun (type tun pi on vnet_hdr on multi_queue|addrgenmode) ')
        self.assertIn('UP,LOWER_UP', output)

        output = common.check_output('ip -d link show testtap99')
        print(output)
        self.assertRegex(output, 'tun (type tap pi on vnet_hdr on multi_queue|addrgenmode) ')
        self.assertIn('UP,LOWER_UP', output)

        common.remove_network_unit('26-netdev-link-local-addressing-yes.network')

        common.start_networkd()
        self.wait_online(['testtun99:degraded', 'testtap99:degraded'], setup_state='unmanaged')

        pid = common.networkd_pid()
        name = psutil.Process(pid).name()[:15]

        output = common.check_output('ip -d tuntap show')
        print(output)
        self.assertRegex(output, fr'(?m)testtap99: tap pi (multi_queue |)vnet_hdr persist filter *(0x100|)\n\tAttached to processes:{name}\({pid}\)systemd\(1\)$')
        self.assertRegex(output, fr'(?m)testtun99: tun pi (multi_queue |)vnet_hdr persist filter *(0x100|)\n\tAttached to processes:{name}\({pid}\)systemd\(1\)$')

        output = common.check_output('ip -d link show testtun99')
        print(output)
        self.assertRegex(output, 'tun (type tun pi on vnet_hdr on multi_queue|addrgenmode) ')
        self.assertIn('UP,LOWER_UP', output)

        output = common.check_output('ip -d link show testtap99')
        print(output)
        self.assertRegex(output, 'tun (type tap pi on vnet_hdr on multi_queue|addrgenmode) ')
        self.assertIn('UP,LOWER_UP', output)

        common.clear_network_units()
        common.start_networkd()
        self.wait_online(['testtun99:off', 'testtap99:off'], setup_state='unmanaged')

        output = common.check_output('ip -d tuntap show')
        print(output)
        self.assertRegex(output, r'(?m)testtap99: tap pi (multi_queue |)vnet_hdr persist filter *(0x100|)\n\tAttached to processes:$')
        self.assertRegex(output, r'(?m)testtun99: tun pi (multi_queue |)vnet_hdr persist filter *(0x100|)\n\tAttached to processes:$')

        for i in range(10):
            if i != 0:
                time.sleep(1)
            output = common.check_output('ip -d link show testtun99')
            print(output)
            self.assertRegex(output, 'tun (type tun pi on vnet_hdr on multi_queue|addrgenmode) ')
            if 'NO-CARRIER' in output:
                break
        else:
            self.fail()

        for i in range(10):
            if i != 0:
                time.sleep(1)
            output = common.check_output('ip -d link show testtap99')
            print(output)
            self.assertRegex(output, 'tun (type tap pi on vnet_hdr on multi_queue|addrgenmode) ')
            if 'NO-CARRIER' in output:
                break
        else:
            self.fail()

    @common.expectedFailureIfModuleIsNotAvailable('vrf')
    def test_vrf(self):
        common.copy_network_unit('25-vrf.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['vrf99:carrier'])

    @common.expectedFailureIfModuleIsNotAvailable('vcan')
    def test_vcan(self):
        common.copy_network_unit('25-vcan.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['vcan99:carrier'])

    @common.expectedFailureIfModuleIsNotAvailable('vxcan')
    def test_vxcan(self):
        common.copy_network_unit('25-vxcan.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['vxcan99:carrier', 'vxcan-peer:carrier'])

    @common.expectedFailureIfModuleIsNotAvailable('wireguard')
    def test_wireguard(self):
        common.copy_network_unit(
                '25-wireguard.netdev', '25-wireguard.network',
                '25-wireguard-23-peers.netdev', '25-wireguard-23-peers.network',
                '25-wireguard-preshared-key.txt', '25-wireguard-private-key.txt',
                '25-wireguard-no-peer.netdev', '25-wireguard-no-peer.network')
        common.start_networkd()
        self.wait_online(['wg99:routable', 'wg98:routable', 'wg97:carrier'])

        output = common.check_output('ip -4 address show dev wg99')
        print(output)
        self.assertIn('inet 192.168.124.1/24 scope global wg99', output)

        output = common.check_output('ip -4 address show dev wg99')
        print(output)
        self.assertIn('inet 169.254.11.1/24 scope link wg99', output)

        output = common.check_output('ip -6 address show dev wg99')
        print(output)
        self.assertIn('inet6 fe80::1/64 scope link', output)

        output = common.check_output('ip -4 address show dev wg98')
        print(output)
        self.assertIn('inet 192.168.123.123/24 scope global wg98', output)

        output = common.check_output('ip -6 address show dev wg98')
        print(output)
        self.assertIn('inet6 fd8d:4d6d:3ccb:500::1/64 scope global', output)

        output = common.check_output('ip -4 route show dev wg99 table 1234')
        print(output)
        self.assertIn('192.168.26.0/24 proto static metric 123', output)

        output = common.check_output('ip -6 route show dev wg99 table 1234')
        print(output)
        self.assertIn('fd31:bf08:57cb::/48 proto static metric 123 pref medium', output)

        output = common.check_output('ip -6 route show dev wg98 table 1234')
        print(output)
        self.assertIn('fd8d:4d6d:3ccb:500:c79:2339:edce:ece1 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:1dbf:ca8a:32d3:dd81 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:1e54:1415:35d0:a47c proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:270d:b5dd:4a3f:8909 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:5660:679d:3532:94d8 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:6825:573f:30f3:9472 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:6f2e:6888:c6fd:dfb9 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:8d4d:bab:7280:a09a proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:900c:d437:ec27:8822 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:9742:9931:5217:18d5 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:9c11:d820:2e96:9be0 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:a072:80da:de4f:add1 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:a3f3:df38:19b0:721 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:a94b:cd6a:a32d:90e6 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:b39c:9cdc:755a:ead3 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:b684:4f81:2e3e:132e proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:bad5:495d:8e9c:3427 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:bfe5:c3c3:5d77:fcb proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:c624:6bf7:4c09:3b59 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:d4f9:5dc:9296:a1a proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:dcdd:d33b:90c9:6088 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:e2e1:ae15:103f:f376 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:f349:c4f0:10c1:6b4 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:c79:2339:edce::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:1dbf:ca8a:32d3::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:1e54:1415:35d0::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:270d:b5dd:4a3f::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:5660:679d:3532::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:6825:573f:30f3::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:6f2e:6888:c6fd::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:8d4d:bab:7280::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:900c:d437:ec27::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:9742:9931:5217::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:9c11:d820:2e96::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:a072:80da:de4f::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:a3f3:df38:19b0::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:a94b:cd6a:a32d::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:b39c:9cdc:755a::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:b684:4f81:2e3e::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:bad5:495d:8e9c::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:bfe5:c3c3:5d77::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:c624:6bf7:4c09::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:d4f9:5dc:9296::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:dcdd:d33b:90c9::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:e2e1:ae15:103f::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:f349:c4f0:10c1::/96 proto static metric 123 pref medium', output)

        if shutil.which('wg'):
            common.call('wg')

            output = common.check_output('wg show wg99 listen-port')
            self.assertEqual(output, '51820')
            output = common.check_output('wg show wg99 fwmark')
            self.assertEqual(output, '0x4d2')
            output = common.check_output('wg show wg99 private-key')
            self.assertEqual(output, 'EEGlnEPYJV//kbvvIqxKkQwOiS+UENyPncC4bF46ong=')
            output = common.check_output('wg show wg99 allowed-ips')
            self.assertIn('9uioxkGzjvGjkse3V35I9AhorWfIjBcrf3UPMS0bw2c=\t192.168.124.3/32', output)
            self.assertIn('TTiCUpCxS7zDn/ax4p5W6Evg41r8hOrnWQw2Sq6Nh10=\t192.168.124.2/32', output)
            self.assertIn('lsDtM3AbjxNlauRKzHEPfgS1Zp7cp/VX5Use/P4PQSc=\tfdbc:bae2:7871:e1fe:793:8636::/96 fdbc:bae2:7871:500:e1fe:793:8636:dad1/128', output)
            self.assertIn('RDf+LSpeEre7YEIKaxg+wbpsNV7du+ktR99uBEtIiCA=\t192.168.26.0/24 fd31:bf08:57cb::/48', output)
            output = common.check_output('wg show wg99 persistent-keepalive')
            self.assertIn('9uioxkGzjvGjkse3V35I9AhorWfIjBcrf3UPMS0bw2c=\toff', output)
            self.assertIn('TTiCUpCxS7zDn/ax4p5W6Evg41r8hOrnWQw2Sq6Nh10=\toff', output)
            self.assertIn('lsDtM3AbjxNlauRKzHEPfgS1Zp7cp/VX5Use/P4PQSc=\toff', output)
            self.assertIn('RDf+LSpeEre7YEIKaxg+wbpsNV7du+ktR99uBEtIiCA=\t20', output)
            output = common.check_output('wg show wg99 endpoints')
            self.assertIn('9uioxkGzjvGjkse3V35I9AhorWfIjBcrf3UPMS0bw2c=\t(none)', output)
            self.assertIn('TTiCUpCxS7zDn/ax4p5W6Evg41r8hOrnWQw2Sq6Nh10=\t(none)', output)
            self.assertIn('lsDtM3AbjxNlauRKzHEPfgS1Zp7cp/VX5Use/P4PQSc=\t(none)', output)
            self.assertIn('RDf+LSpeEre7YEIKaxg+wbpsNV7du+ktR99uBEtIiCA=\t192.168.27.3:51820', output)
            output = common.check_output('wg show wg99 preshared-keys')
            self.assertIn('9uioxkGzjvGjkse3V35I9AhorWfIjBcrf3UPMS0bw2c=\t6Fsg8XN0DE6aPQgAX4r2oazEYJOGqyHUz3QRH/jCB+I=', output)
            self.assertIn('TTiCUpCxS7zDn/ax4p5W6Evg41r8hOrnWQw2Sq6Nh10=\tit7nd33chCT/tKT2ZZWfYyp43Zs+6oif72hexnSNMqA=', output)
            self.assertIn('lsDtM3AbjxNlauRKzHEPfgS1Zp7cp/VX5Use/P4PQSc=\tcPLOy1YUrEI0EMMIycPJmOo0aTu3RZnw8bL5meVD6m0=', output)
            self.assertIn('RDf+LSpeEre7YEIKaxg+wbpsNV7du+ktR99uBEtIiCA=\tIIWIV17wutHv7t4cR6pOT91z6NSz/T8Arh0yaywhw3M=', output)

            output = common.check_output('wg show wg98 private-key')
            self.assertEqual(output, 'CJQUtcS9emY2fLYqDlpSZiE/QJyHkPWr+WHtZLZ90FU=')

            output = common.check_output('wg show wg97 listen-port')
            self.assertEqual(output, '51821')
            output = common.check_output('wg show wg97 fwmark')
            self.assertEqual(output, '0x4d3')

    def test_geneve(self):
        common.copy_network_unit('25-geneve.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['geneve99:degraded'])

        output = common.check_output('ip -d link show geneve99')
        print(output)
        self.assertRegex(output, '192.168.22.1')
        self.assertRegex(output, '6082')
        self.assertRegex(output, 'udpcsum')
        self.assertRegex(output, 'udp6zerocsumrx')

    def test_ipip_tunnel(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-ipip.network',
                '25-ipip-tunnel.netdev', '25-tunnel.network',
                '25-ipip-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                '25-ipip-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                '25-ipip-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        common.start_networkd()
        self.wait_online(['ipiptun99:routable', 'ipiptun98:routable', 'ipiptun97:routable', 'ipiptun96:routable', 'dummy98:degraded'])

        output = common.check_output('ip -d link show ipiptun99')
        print(output)
        self.assertRegex(output, 'ipip (ipip )?remote 192.169.224.239 local 192.168.223.238 dev dummy98')
        output = common.check_output('ip -d link show ipiptun98')
        print(output)
        self.assertRegex(output, 'ipip (ipip )?remote 192.169.224.239 local any dev dummy98')
        output = common.check_output('ip -d link show ipiptun97')
        print(output)
        self.assertRegex(output, 'ipip (ipip )?remote any local 192.168.223.238 dev dummy98')
        output = common.check_output('ip -d link show ipiptun96')
        print(output)
        self.assertRegex(output, 'ipip (ipip )?remote any local any dev dummy98')

    def test_gre_tunnel(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-gretun.network',
                '25-gre-tunnel.netdev', '25-tunnel.network',
                '25-gre-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                '25-gre-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                '25-gre-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        common.start_networkd()
        self.wait_online(['gretun99:routable', 'gretun98:routable', 'gretun97:routable', 'gretun96:routable', 'dummy98:degraded'])

        output = common.check_output('ip -d link show gretun99')
        print(output)
        self.assertRegex(output, 'gre remote 10.65.223.239 local 10.65.223.238 dev dummy98')
        self.assertRegex(output, 'ikey 1.2.3.103')
        self.assertRegex(output, 'okey 1.2.4.103')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')
        output = common.check_output('ip -d link show gretun98')
        print(output)
        self.assertRegex(output, 'gre remote 10.65.223.239 local any dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.104')
        self.assertRegex(output, 'okey 0.0.0.104')
        self.assertNotRegex(output, 'iseq')
        self.assertNotRegex(output, 'oseq')
        output = common.check_output('ip -d link show gretun97')
        print(output)
        self.assertRegex(output, 'gre remote any local 10.65.223.238 dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.105')
        self.assertRegex(output, 'okey 0.0.0.105')
        self.assertNotRegex(output, 'iseq')
        self.assertNotRegex(output, 'oseq')
        output = common.check_output('ip -d link show gretun96')
        print(output)
        self.assertRegex(output, 'gre remote any local any dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.106')
        self.assertRegex(output, 'okey 0.0.0.106')
        self.assertNotRegex(output, 'iseq')
        self.assertNotRegex(output, 'oseq')

    def test_ip6gre_tunnel(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-ip6gretun.network',
                '25-ip6gre-tunnel.netdev', '25-tunnel.network',
                '25-ip6gre-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                '25-ip6gre-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                '25-ip6gre-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        common.start_networkd()

        # Old kernels seem not to support IPv6LL address on ip6gre tunnel, So please do not use wait_online() here.

        self.wait_links('dummy98', 'ip6gretun99', 'ip6gretun98', 'ip6gretun97', 'ip6gretun96')

        output = common.check_output('ip -d link show ip6gretun99')
        print(output)
        self.assertRegex(output, 'ip6gre remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = common.check_output('ip -d link show ip6gretun98')
        print(output)
        self.assertRegex(output, 'ip6gre remote 2001:473:fece:cafe::5179 local any dev dummy98')
        output = common.check_output('ip -d link show ip6gretun97')
        print(output)
        self.assertRegex(output, 'ip6gre remote any local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = common.check_output('ip -d link show ip6gretun96')
        print(output)
        self.assertRegex(output, 'ip6gre remote any local any dev dummy98')

    def test_gretap_tunnel(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-gretap.network',
                '25-gretap-tunnel.netdev', '25-tunnel.network',
                '25-gretap-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        common.start_networkd()
        self.wait_online(['gretap99:routable', 'gretap98:routable', 'dummy98:degraded'])

        output = common.check_output('ip -d link show gretap99')
        print(output)
        self.assertRegex(output, 'gretap remote 10.65.223.239 local 10.65.223.238 dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.106')
        self.assertRegex(output, 'okey 0.0.0.106')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')
        self.assertIn('nopmtudisc', output)
        self.assertIn('ignore-df', output)
        output = common.check_output('ip -d link show gretap98')
        print(output)
        self.assertRegex(output, 'gretap remote 10.65.223.239 local any dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.107')
        self.assertRegex(output, 'okey 0.0.0.107')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')

    def test_ip6gretap_tunnel(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-ip6gretap.network',
                '25-ip6gretap-tunnel.netdev', '25-tunnel.network',
                '25-ip6gretap-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        common.start_networkd()
        self.wait_online(['ip6gretap99:routable', 'ip6gretap98:routable', 'dummy98:degraded'])

        output = common.check_output('ip -d link show ip6gretap99')
        print(output)
        self.assertRegex(output, 'ip6gretap remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = common.check_output('ip -d link show ip6gretap98')
        print(output)
        self.assertRegex(output, 'ip6gretap remote 2001:473:fece:cafe::5179 local any dev dummy98')

    def test_vti_tunnel(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-vti.network',
                '25-vti-tunnel.netdev', '25-tunnel.network',
                '25-vti-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                '25-vti-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                '25-vti-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        common.start_networkd()
        self.wait_online(['vtitun99:routable', 'vtitun98:routable', 'vtitun97:routable', 'vtitun96:routable', 'dummy98:degraded'])

        output = common.check_output('ip -d link show vtitun99')
        print(output)
        self.assertRegex(output, 'vti remote 10.65.223.239 local 10.65.223.238 dev dummy98')
        output = common.check_output('ip -d link show vtitun98')
        print(output)
        self.assertRegex(output, 'vti remote 10.65.223.239 local any dev dummy98')
        output = common.check_output('ip -d link show vtitun97')
        print(output)
        self.assertRegex(output, 'vti remote any local 10.65.223.238 dev dummy98')
        output = common.check_output('ip -d link show vtitun96')
        print(output)
        self.assertRegex(output, 'vti remote any local any dev dummy98')

    def test_vti6_tunnel(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-vti6.network',
                '25-vti6-tunnel.netdev', '25-tunnel.network',
                '25-vti6-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                '25-vti6-tunnel-remote-any.netdev', '25-tunnel-remote-any.network')
        common.start_networkd()
        self.wait_online(['vti6tun99:routable', 'vti6tun98:routable', 'vti6tun97:routable', 'dummy98:degraded'])

        output = common.check_output('ip -d link show vti6tun99')
        print(output)
        self.assertRegex(output, 'vti6 remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = common.check_output('ip -d link show vti6tun98')
        print(output)
        self.assertRegex(output, 'vti6 remote 2001:473:fece:cafe::5179 local (any|::) dev dummy98')
        output = common.check_output('ip -d link show vti6tun97')
        print(output)
        self.assertRegex(output, 'vti6 remote (any|::) local 2a00:ffde:4567:edde::4987 dev dummy98')

    def test_ip6tnl_tunnel(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-ip6tnl.network',
                '25-ip6tnl-tunnel.netdev', '25-tunnel.network',
                '25-ip6tnl-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                '25-ip6tnl-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                '25-veth.netdev', '25-ip6tnl-slaac.network', '25-ipv6-prefix.network',
                '25-ip6tnl-tunnel-local-slaac.netdev', '25-ip6tnl-tunnel-local-slaac.network',
                '25-ip6tnl-tunnel-external.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()
        self.wait_online(['ip6tnl99:routable', 'ip6tnl98:routable', 'ip6tnl97:routable',
                          'ip6tnl-slaac:degraded', 'ip6tnl-external:degraded',
                          'dummy98:degraded', 'veth99:routable', 'veth-peer:degraded'])

        output = common.check_output('ip -d link show ip6tnl99')
        print(output)
        self.assertIn('ip6tnl ip6ip6 remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98', output)
        output = common.check_output('ip -d link show ip6tnl98')
        print(output)
        self.assertRegex(output, 'ip6tnl ip6ip6 remote 2001:473:fece:cafe::5179 local (any|::) dev dummy98')
        output = common.check_output('ip -d link show ip6tnl97')
        print(output)
        self.assertRegex(output, 'ip6tnl ip6ip6 remote (any|::) local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = common.check_output('ip -d link show ip6tnl-external')
        print(output)
        self.assertIn('ip6tnl-external@NONE:', output)
        self.assertIn('ip6tnl external ', output)
        output = common.check_output('ip -d link show ip6tnl-slaac')
        print(output)
        self.assertIn('ip6tnl ip6ip6 remote 2001:473:fece:cafe::5179 local 2002:da8:1:0:1034:56ff:fe78:9abc dev veth99', output)

        output = common.check_output('ip -6 address show veth99')
        print(output)
        self.assertIn('inet6 2002:da8:1:0:1034:56ff:fe78:9abc/64 scope global dynamic', output)

        output = common.check_output('ip -4 route show default')
        print(output)
        self.assertIn('default dev ip6tnl-slaac proto static', output)

    def test_sit_tunnel(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-sit.network',
                '25-sit-tunnel.netdev', '25-tunnel.network',
                '25-sit-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                '25-sit-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                '25-sit-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        common.start_networkd()
        self.wait_online(['sittun99:routable', 'sittun98:routable', 'sittun97:routable', 'sittun96:routable', 'dummy98:degraded'])

        output = common.check_output('ip -d link show sittun99')
        print(output)
        self.assertRegex(output, "sit (ip6ip )?remote 10.65.223.239 local 10.65.223.238 dev dummy98")
        output = common.check_output('ip -d link show sittun98')
        print(output)
        self.assertRegex(output, "sit (ip6ip )?remote 10.65.223.239 local any dev dummy98")
        output = common.check_output('ip -d link show sittun97')
        print(output)
        self.assertRegex(output, "sit (ip6ip )?remote any local 10.65.223.238 dev dummy98")
        output = common.check_output('ip -d link show sittun96')
        print(output)
        self.assertRegex(output, "sit (ip6ip )?remote any local any dev dummy98")

    def test_isatap_tunnel(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-isatap.network',
                '25-isatap-tunnel.netdev', '25-tunnel.network')
        common.start_networkd()
        self.wait_online(['isataptun99:routable', 'dummy98:degraded'])

        output = common.check_output('ip -d link show isataptun99')
        print(output)
        self.assertRegex(output, "isatap ")

    def test_6rd_tunnel(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-6rd.network',
                '25-6rd-tunnel.netdev', '25-tunnel.network')
        common.start_networkd()
        self.wait_online(['sittun99:routable', 'dummy98:degraded'])

        output = common.check_output('ip -d link show sittun99')
        print(output)
        self.assertRegex(output, '6rd-prefix 2602::/24')

    @common.expectedFailureIfERSPANv0IsNotSupported()
    def test_erspan_tunnel_v0(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-erspan.network',
                '25-erspan0-tunnel.netdev', '25-tunnel.network',
                '25-erspan0-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        common.start_networkd()
        self.wait_online(['erspan99:routable', 'erspan98:routable', 'dummy98:degraded'])

        output = common.check_output('ip -d link show erspan99')
        print(output)
        self.assertIn('erspan remote 172.16.1.100 local 172.16.1.200', output)
        self.assertIn('erspan_ver 0', output)
        self.assertNotIn('erspan_index 123', output)
        self.assertNotIn('erspan_dir ingress', output)
        self.assertNotIn('erspan_hwid 1f', output)
        self.assertIn('ikey 0.0.0.101', output)
        self.assertIn('iseq', output)
        self.assertIn('nopmtudisc', output)
        self.assertIn('ignore-df', output)
        output = common.check_output('ip -d link show erspan98')
        print(output)
        self.assertIn('erspan remote 172.16.1.100 local any', output)
        self.assertIn('erspan_ver 0', output)
        self.assertNotIn('erspan_index 124', output)
        self.assertNotIn('erspan_dir egress', output)
        self.assertNotIn('erspan_hwid 2f', output)
        self.assertIn('ikey 0.0.0.102', output)
        self.assertIn('iseq', output)

    def test_erspan_tunnel_v1(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-erspan.network',
                '25-erspan1-tunnel.netdev', '25-tunnel.network',
                '25-erspan1-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        common.start_networkd()
        self.wait_online(['erspan99:routable', 'erspan98:routable', 'dummy98:degraded'])

        output = common.check_output('ip -d link show erspan99')
        print(output)
        self.assertIn('erspan remote 172.16.1.100 local 172.16.1.200', output)
        self.assertIn('erspan_ver 1', output)
        self.assertIn('erspan_index 123', output)
        self.assertNotIn('erspan_dir ingress', output)
        self.assertNotIn('erspan_hwid 1f', output)
        self.assertIn('ikey 0.0.0.101', output)
        self.assertIn('okey 0.0.0.101', output)
        self.assertIn('iseq', output)
        self.assertIn('oseq', output)
        output = common.check_output('ip -d link show erspan98')
        print(output)
        self.assertIn('erspan remote 172.16.1.100 local any', output)
        self.assertIn('erspan_ver 1', output)
        self.assertIn('erspan_index 124', output)
        self.assertNotIn('erspan_dir egress', output)
        self.assertNotIn('erspan_hwid 2f', output)
        self.assertIn('ikey 0.0.0.102', output)
        self.assertIn('okey 0.0.0.102', output)
        self.assertIn('iseq', output)
        self.assertIn('oseq', output)

    @common.expectedFailureIfERSPANv2IsNotSupported()
    def test_erspan_tunnel_v2(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-erspan.network',
                '25-erspan2-tunnel.netdev', '25-tunnel.network',
                '25-erspan2-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        common.start_networkd()
        self.wait_online(['erspan99:routable', 'erspan98:routable', 'dummy98:degraded'])

        output = common.check_output('ip -d link show erspan99')
        print(output)
        self.assertIn('erspan remote 172.16.1.100 local 172.16.1.200', output)
        self.assertIn('erspan_ver 2', output)
        self.assertNotIn('erspan_index 123', output)
        self.assertIn('erspan_dir ingress', output)
        self.assertIn('erspan_hwid 0x1f', output)
        self.assertIn('ikey 0.0.0.101', output)
        self.assertIn('okey 0.0.0.101', output)
        self.assertIn('iseq', output)
        self.assertIn('oseq', output)
        output = common.check_output('ip -d link show erspan98')
        print(output)
        self.assertIn('erspan remote 172.16.1.100 local any', output)
        self.assertIn('erspan_ver 2', output)
        self.assertNotIn('erspan_index 124', output)
        self.assertIn('erspan_dir egress', output)
        self.assertIn('erspan_hwid 0x2f', output)
        self.assertIn('ikey 0.0.0.102', output)
        self.assertIn('okey 0.0.0.102', output)
        self.assertIn('iseq', output)
        self.assertIn('oseq', output)

    def test_tunnel_independent(self):
        common.copy_network_unit('25-ipip-tunnel-independent.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['ipiptun99:carrier'])

    def test_tunnel_independent_loopback(self):
        common.copy_network_unit('25-ipip-tunnel-independent-loopback.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['ipiptun99:carrier'])

    @common.expectedFailureIfModuleIsNotAvailable('xfrm_interface')
    def test_xfrm(self):
        common.copy_network_unit(
                '12-dummy.netdev', '25-xfrm.network',
                '25-xfrm.netdev', '25-xfrm-independent.netdev',
                '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['dummy98:degraded', 'xfrm98:degraded', 'xfrm99:degraded'])

        output = common.check_output('ip -d link show dev xfrm98')
        print(output)
        self.assertIn('xfrm98@dummy98:', output)
        self.assertIn('xfrm if_id 0x98 ', output)

        output = common.check_output('ip -d link show dev xfrm99')
        print(output)
        self.assertIn('xfrm99@lo:', output)
        self.assertIn('xfrm if_id 0x99 ', output)

    @common.expectedFailureIfModuleIsNotAvailable('fou')
    def test_fou(self):
        # The following redundant check is necessary for CentOS CI.
        # Maybe, error handling in lookup_id() in sd-netlink/generic-netlink.c needs to be updated.
        self.assertTrue(common.is_module_available('fou'))

        common.copy_network_unit(
                '25-fou-ipproto-ipip.netdev', '25-fou-ipproto-gre.netdev',
                '25-fou-ipip.netdev', '25-fou-sit.netdev',
                '25-fou-gre.netdev', '25-fou-gretap.netdev')
        common.start_networkd()

        self.wait_online(['ipiptun96:off', 'sittun96:off', 'gretun96:off', 'gretap96:off'], setup_state='unmanaged')

        output = common.check_output('ip fou show')
        print(output)
        self.assertRegex(output, 'port 55555 ipproto 4')
        self.assertRegex(output, 'port 55556 ipproto 47')

        output = common.check_output('ip -d link show ipiptun96')
        print(output)
        self.assertRegex(output, 'encap fou encap-sport auto encap-dport 55555')
        output = common.check_output('ip -d link show sittun96')
        print(output)
        self.assertRegex(output, 'encap fou encap-sport auto encap-dport 55555')
        output = common.check_output('ip -d link show gretun96')
        print(output)
        self.assertRegex(output, 'encap fou encap-sport 1001 encap-dport 55556')
        output = common.check_output('ip -d link show gretap96')
        print(output)
        self.assertRegex(output, 'encap fou encap-sport auto encap-dport 55556')

    def test_vxlan(self):
        common.copy_network_unit(
                '11-dummy.netdev', '25-vxlan-test1.network',
                '25-vxlan.netdev', '25-vxlan.network',
                '25-vxlan-ipv6.netdev', '25-vxlan-ipv6.network',
                '25-vxlan-independent.netdev', '26-netdev-link-local-addressing-yes.network',
                '25-veth.netdev', '25-vxlan-veth99.network', '25-ipv6-prefix.network',
                '25-vxlan-local-slaac.netdev', '25-vxlan-local-slaac.network')
        common.start_networkd()

        self.wait_online(['test1:degraded', 'veth99:routable', 'veth-peer:degraded',
                          'vxlan99:degraded', 'vxlan98:degraded', 'vxlan97:degraded', 'vxlan-slaac:degraded'])

        output = common.check_output('ip -d -d link show vxlan99')
        print(output)
        self.assertIn('999', output)
        self.assertIn('5555', output)
        self.assertIn('l2miss', output)
        self.assertIn('l3miss', output)
        self.assertIn('gbp', output)
        # Since [0] some of the options use slightly different names and some
        # options with default values are shown only if the -d(etails) setting
        # is repeated
        # [0] https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/commit/?id=1215e9d3862387353d8672296cb4c6c16e8cbb72
        self.assertRegex(output, '(udpcsum|udp_csum)')
        self.assertRegex(output, '(udp6zerocsumtx|udp_zero_csum6_tx)')
        self.assertRegex(output, '(udp6zerocsumrx|udp_zero_csum6_rx)')
        self.assertRegex(output, '(remcsumtx|remcsum_tx)')
        self.assertRegex(output, '(remcsumrx|remcsum_rx)')

        output = common.check_output('bridge fdb show dev vxlan99')
        print(output)
        self.assertIn('00:11:22:33:44:55 dst 10.0.0.5 self permanent', output)
        self.assertIn('00:11:22:33:44:66 dst 10.0.0.6 self permanent', output)
        self.assertIn('00:11:22:33:44:77 dst 10.0.0.7 via test1 self permanent', output)

        output = common.check_output(*common.networkctl_cmd, '-n', '0', 'status', 'vxlan99', env=common.env)
        print(output)
        self.assertIn('VNI: 999', output)
        self.assertIn('Destination Port: 5555', output)
        self.assertIn('Underlying Device: test1', output)

        output = common.check_output('bridge fdb show dev vxlan97')
        print(output)
        self.assertIn('00:00:00:00:00:00 dst fe80::23b:d2ff:fe95:967f via test1 self permanent', output)
        self.assertIn('00:00:00:00:00:00 dst fe80::27c:16ff:fec0:6c74 via test1 self permanent', output)
        self.assertIn('00:00:00:00:00:00 dst fe80::2a2:e4ff:fef9:2269 via test1 self permanent', output)

        output = common.check_output('ip -d link show vxlan-slaac')
        print(output)
        self.assertIn('vxlan id 4831584 local 2002:da8:1:0:1034:56ff:fe78:9abc dev veth99', output)

        output = common.check_output('ip -6 address show veth99')
        print(output)
        self.assertIn('inet6 2002:da8:1:0:1034:56ff:fe78:9abc/64 scope global dynamic', output)

    @unittest.skipUnless(common.compare_kernel_version("6"), reason="Causes kernel panic on unpatched kernels: https://bugzilla.kernel.org/show_bug.cgi?id=208315")
    def test_macsec(self):
        common.copy_network_unit(
                '25-macsec.netdev', '25-macsec.network', '25-macsec.key',
                '26-macsec.network', '12-dummy.netdev')
        common.start_networkd()

        self.wait_online(['dummy98:degraded', 'macsec99:routable'])

        output = common.check_output('ip -d link show macsec99')
        print(output)
        self.assertRegex(output, 'macsec99@dummy98')
        self.assertRegex(output, 'macsec sci [0-9a-f]*000b')
        self.assertRegex(output, 'encrypt on')

        output = common.check_output('ip macsec show macsec99')
        print(output)
        self.assertRegex(output, 'encrypt on')
        self.assertRegex(output, 'TXSC: [0-9a-f]*000b on SA 1')
        self.assertRegex(output, '0: PN [0-9]*, state on, key 01000000000000000000000000000000')
        self.assertRegex(output, '1: PN [0-9]*, state on, key 02030000000000000000000000000000')
        self.assertRegex(output, 'RXSC: c619528fe6a00100, state on')
        self.assertRegex(output, '0: PN [0-9]*, state on, key 02030405000000000000000000000000')
        self.assertRegex(output, '1: PN [0-9]*, state on, key 02030405060000000000000000000000')
        self.assertRegex(output, '2: PN [0-9]*, state off, key 02030405060700000000000000000000')
        self.assertRegex(output, '3: PN [0-9]*, state off, key 02030405060708000000000000000000')
        self.assertNotRegex(output, 'key 02030405067080900000000000000000')
        self.assertRegex(output, 'RXSC: 8c16456c83a90002, state on')
        self.assertRegex(output, '0: PN [0-9]*, state off, key 02030400000000000000000000000000')

    def test_nlmon(self):
        common.copy_network_unit('25-nlmon.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['nlmon99:carrier'])

    @common.expectedFailureIfModuleIsNotAvailable('ifb')
    def test_ifb(self):
        common.copy_network_unit('25-ifb.netdev', '26-netdev-link-local-addressing-yes.network')
        common.start_networkd()

        self.wait_online(['ifb99:degraded'])
