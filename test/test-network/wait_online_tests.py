# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import unittest

import common


class WaitOnlineTests(unittest.TestCase, common.Utilities):
    def setUp(self):
        common.setup_common()

    def tearDown(self):
        common.tear_down_common()

    def test_wait_online_any(self):
        common.copy_network_unit('25-bridge.netdev', '25-bridge.network', '11-dummy.netdev', '11-dummy.network')
        common.start_networkd()

        self.wait_online(['bridge99', 'test1:degraded'], bool_any=True)

        self.wait_operstate('bridge99', '(off|no-carrier)', setup_state='configuring')
        self.wait_operstate('test1', 'degraded')
