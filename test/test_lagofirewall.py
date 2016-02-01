try:
    import mock
except ImportError:
    from unittest import mock

import sys
import unittest
from nose.tools import *

from lagofirewall import Lago_Firewall
import ryu

class mock_ofproto():
    OFPFC_ADD = "ADD"
    OFPFC_DELETE = "DELETE"
    def __init__():
        return

class Test_lagoFw(unittest.TestCase):

    def test_add_flow(self):
        with mock.patch('lagofirewall.mod_flow_entry'):
            mod_flow_entry = mock.Mock()
            datapath = None
            ofproto = mock_ofproto
            rule = {"priority":100}
            test = Lago_Firewall.add_flow_rules(datapath, ofproto, rule)

    def test_calculate_port_mask(self):
        port_list = Lago_Firewall.calculate_port_mask(1024, 65535, 0)
        self.assertEqual(6, len(port_list))
        self.assertIn({'mask': 0xFC00, 'key': 0x0400}, port_list)
        self.assertIn({'mask': 0xF800, 'key': 0x0800}, port_list)
        self.assertIn({'mask': 0xF000, 'key': 0x1000}, port_list)
        self.assertIn({'mask': 0xE000, 'key': 0x2000}, port_list)
        self.assertIn({'mask': 0xC000, 'key': 0x4000}, port_list)
        self.assertIn({'mask': 0x8000, 'key': 0x8000}, port_list)

        port_list = Lago_Firewall.calculate_port_mask(0, 1023, 0)
        self.assertEqual(1, len(port_list))
        self.assertIn({'mask': 0xFC00, 'key': 0}, port_list)

        port_list = Lago_Firewall.calculate_port_mask(12345, 12345, 0)
        self.assertEqual(1, len(port_list))
        self.assertIn({'mask': 0xFFFF, 'key': 12345}, port_list)

        port_list = Lago_Firewall.calculate_port_mask(1, 65534, 0)
        self.assertEqual(30, len(port_list))


if __name__ == "__main__":
    unitteset.main()
