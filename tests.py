#!/usr/bin/env python3
import unittest
from collections import OrderedDict

from privex import pyrewall


class TestRuleHandlers(unittest.TestCase):
    def setUp(self):
        self.rp = pyrewall.RuleParser()

    def test_port_handler_multi(self):
        """Test port rule parser with a multiple ports and port ranges"""
        expected = '-A INPUT -p tcp -m multiport --dports 123,443,600:900,1000:2000 -j ACCEPT'

        v4r, v6r = self.rp.parse('allow port 123,443,600-900,1000:2000')
        self.assertEqual(len(v4r), 1)
        self.assertEqual(len(v6r), 1)

        self.assertEqual(v4r[0], expected)
        self.assertEqual(v6r[0], expected)

    def test_port_handler_single(self):
        """Test port rule parser with a singular port"""
        expected = '-A INPUT -p tcp --dport 800 -j ACCEPT'
        v4r, v6r = self.rp.parse('allow port 800')
        self.assertEqual(len(v4r), 1)
        self.assertEqual(len(v6r), 1)

        self.assertEqual(v4r[0], expected)
        self.assertEqual(v6r[0], expected)

    def test_from_v4(self):
        """Test that a rule with an IPv4 source address only returns a v4 rule"""
        expected = '-A INPUT -p tcp --dport 800 -s 1.2.3.4/32 -j ACCEPT'
        v4r, v6r = self.rp.parse('allow port 800 from 1.2.3.4')
        self.assertEqual(len(v4r), 1)
        self.assertEqual(len(v6r), 0)

        self.assertEqual(v4r[0], expected)

    def test_from_v6(self):
        """Test that a rule with an IPv6 source address only returns a v6 rule"""
        expected = '-A INPUT -p tcp --dport 800 -s 2a07:e00::1/128 -j ACCEPT'
        v4r, v6r = self.rp.parse('allow port 800 from 2a07:e00::1')
        self.assertEqual(len(v4r), 0)
        self.assertEqual(len(v6r), 1)

        self.assertEqual(v6r[0], expected)


if __name__ == '__main__':
    unittest.main()
