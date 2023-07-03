# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import re
import time
import unittest

import common


class NetworkdLLDPTests(unittest.TestCase, common.Utilities):

    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_lldp(self):
        common.copy_network_unit('23-emit-lldp.network', '24-lldp.network', '25-veth.netdev')
        common.start_networkd()
        self.wait_online(['veth99:degraded', 'veth-peer:degraded'])

        for trial in range(10):
            if trial > 0:
                time.sleep(1)

            output = common.check_output(*common.networkctl_cmd, 'lldp', env=common.env)
            print(output)
            if re.search(r'veth99 .* veth-peer', output):
                break
        else:
            self.fail()
