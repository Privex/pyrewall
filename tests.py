#!/usr/bin/env python3
import unittest
from collections import OrderedDict
from os.path import abspath, dirname, join

from privex import pyrewall
from privex.pyrewall import find_file

BASE_DIR = dirname(abspath(__file__))
DIR_FF1 = join(BASE_DIR, 'testdata', 'findfile')
DIR_FF2 = join(BASE_DIR, 'testdata', 'findfile2')
DIR_CONF = join(BASE_DIR, 'testdata', 'configs')

TEST_SEARCH_PATH = [DIR_FF1, DIR_FF2, DIR_CONF]
TEST_SEARCH_EXT = ['.pyre', '.txt', '.log']


def _find_file(filename):
    """Small helper static method, simple calls find_file with the test paths/extensions automatically passed"""
    return pyrewall.find_file(filename=filename, paths=TEST_SEARCH_PATH, extensions=TEST_SEARCH_EXT)


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

    def test_raw_ipt(self):
        """Test ``ipt`` Pyre rule parses into an equal IPv4 and IPv6 rule"""
        expected = '-A FORWARD -p tcp --dport 420 --example testing -j ACCEPT'
        v4r, v6r = self.rp.parse(f'ipt {expected}')
        self.assertEqual(len(v4r), 1)
        self.assertEqual(len(v6r), 1)
        self.assertEqual(v4r[0], expected)
        self.assertEqual(v6r[0], expected)
    

    def test_raw_ipt_v4(self):
        """Test ``ipt4`` Pyre rule parses into a singular IPv4 rule"""
        expected = '-A OUTPUT -p tcp -s 1.2.3.0/24 --dport 420 --example testing -j ACCEPT'
        v4r, v6r = self.rp.parse(f'ipt4 {expected}')
        self.assertEqual(len(v4r), 1)
        self.assertEqual(len(v6r), 0)
        self.assertEqual(v4r[0], expected)
    
    def test_raw_ipt_v6(self):
        """Test ``ipt6`` Pyre rule parses into a singular IPv6 rule"""
        expected = '-A FORWARD -p tcp -s 2a07:e00::/32 --example testing -j ACCEPT'
        v4r, v6r = self.rp.parse(f'ipt6 {expected}')
        self.assertEqual(len(v4r), 0)
        self.assertEqual(len(v6r), 1)
        self.assertEqual(v6r[0], expected)


class TestRuleValidation(unittest.TestCase):
    def test_valid_port(self):
        """Test :py:func:`privex.pyrewall.core.valid_port` with a valid string and integer"""
        p = pyrewall.valid_port('1234')
        self.assertIs(type(p), int)
        self.assertEqual(p, 1234)

        k = pyrewall.valid_port(2345)
        self.assertIs(type(k), int)
        self.assertEqual(k, 2345)

    def test_invalid_port_overflow(self):
        """Test valid_port raises InvalidPort with a too high port number (65537)"""
        with self.assertRaises(pyrewall.InvalidPort):
            pyrewall.valid_port('65537')
        with self.assertRaises(pyrewall.InvalidPort):
            pyrewall.valid_port(65537)

    def test_invalid_port_zero(self):
        """Test valid_port raises InvalidPort with port 0 """
        with self.assertRaises(pyrewall.InvalidPort):
            pyrewall.valid_port('0')
        with self.assertRaises(pyrewall.InvalidPort):
            pyrewall.valid_port(0)

    def test_invalid_port_negative(self):
        """Test valid_port raises InvalidPort with negative port -1"""
        with self.assertRaises(pyrewall.InvalidPort):
            pyrewall.valid_port('-1')
        with self.assertRaises(pyrewall.InvalidPort):
            pyrewall.valid_port(-1)


class TestPyreParser(unittest.TestCase):
    """
    Unit testing which tests the output from parsing entire .pyre files by comparing the returned rules to expected
    result .v4 and .v6 files.

    Pyre testing configurations can be found in ``testdata/configs`` - Pyre configs generally end with ``.pyre``, while
    the rendered outputs end in ``.v4`` and ``.v6`` respectively (unless they're designed for testing an ``@import``)
    """

    pyre_files = dict(
        test1=dict(
            path=_find_file('test1.pyre'),
            v4=_find_file('test1_out.v4'),
            v6=_find_file('test1_out.v6'),
        ),
    )
    render_cache = {}

    def _parse_help(self, testname, cached=True):
        """
        Helper method - parses ``path`` under the matching test name in :py:attr:`.pyre_files` using
        :class:`.PyreParser` and outputs a dict containing ``v4`` and ``v6``

        e.g.

            dict(
                v4=[ ['*filter', ...], ['*filter', ...], ],
                v6=[ ['*filter', ...], ['*filter', ...], ],
            )


        **Note:** To improve testing speed, rendered results are cached in :py:attr:`.render_cache`. If a test
        changes something about the way the file would be rendered, make sure to pass ``cached=False`` to bypass
        the render cache.

        """
        if cached and testname in TestPyreParser.render_cache:
            return TestPyreParser.render_cache[testname]

        p = pyrewall.PyreParser()
        fp = self.pyre_files[testname]
        v4r, v6r = p.parse_file(fp['path'])

        res = dict(v4=[v4r], v6=[v6r])
        if 'v4' in fp:
            with open(fp['v4']) as fh:
                res['v4'].append([l.strip() for l in fh.readlines() if l.strip() != ''])
        if 'v6' in fp:
            with open(fp['v6']) as fh:
                res['v6'].append([l.strip() for l in fh.readlines() if l.strip() != ''])

        TestPyreParser.render_cache[testname] = res

        return res

    def test_basic_parsing_test1_v4(self):
        parsed, pre = self._parse_help('test1')['v4']
        self.assertEqual(parsed, pre, msg='Test parsed test1.pyre matches pre-rendered v4 rules file')

    def test_basic_parsing_test1_v6(self):
        parsed, pre = self._parse_help('test1')['v6']
        self.assertEqual(parsed, pre, msg='Test parsed test1.pyre matches pre-rendered v6 rules file')


class TestFindFile(unittest.TestCase):
    """
    Test cases to thoroughly test absolute, relative, and flat filenames with PyreWall function
    :py:func:`privex.pyrewall.core.find_file`

    Tests both the "search paths" functionality, along with the automatic extension guessing.

    Dependant on the folder ``testdata`` which contains various empty files in a hierarchical structure designed
    for testing the search path functionality.
    """

    def test_filename(self):
        """Test search path with extensionless example1 in search paths (testdata/findfile)"""
        f = _find_file('example1')
        self.assertEqual(f, join(DIR_FF1, 'example1'))

    def test_filename_relative(self):
        """Test search path with ``subdirtest/example8.txt`` in search paths (testdata/findfile)"""
        f = _find_file('subdirtest/example8.txt')
        self.assertEqual(f, join(DIR_FF1, 'subdirtest/example8.txt'))

    def test_ff2_filename(self):
        """Test search path with extensionless example4 in search paths (testdata/findfile2)"""
        f = _find_file('example4')
        self.assertEqual(f, join(DIR_FF2, 'example4'))

    def test_filename_ext_log(self):
        """Test search path with specified extension finding example3.log in search paths (testdata/findfile)"""
        f = _find_file('example3.log')
        self.assertEqual(f, join(DIR_FF1, 'example3.log'))

    def test_filename_ext_txt_relative(self):
        """Test search path / extensions by finding relative ``subdirtest/example8.txt`` in search paths"""
        f = _find_file('subdirtest/example8')
        self.assertEqual(f, join(DIR_FF1, 'subdirtest/example8.txt'))

    def test_filename_find_ext_txt(self):
        """Test search path / extensions with finding example2 in search paths (testdata/findfile)"""
        f = _find_file('example2')
        self.assertEqual(f, join(DIR_FF1, 'example2.txt'))

    def test_ff2_filename_find_ext_txt(self):
        """Test search path / extensions with finding example5 in search paths (testdata/findfile2)"""
        f = _find_file('example5')
        self.assertEqual(f, join(DIR_FF2, 'example5.txt'))

    def test_ff2_filename_find_ext_log(self):
        """Test search path / extensions with finding example6 in search paths (testdata/findfile2)"""
        f = _find_file('example6')
        self.assertEqual(f, join(DIR_FF2, 'example6.log'))

    def test_filename_absolute(self):
        """Test finding absolute paths returns the correct path"""
        path = join(BASE_DIR, 'testdata', 'example7.txt')
        f = _find_file(path)
        self.assertEqual(f, path)

    def test_filename_noexist(self):
        """Test non-existent search filename causes FileNotFoundError exception"""
        with self.assertRaises(FileNotFoundError):
            _find_file('TOTALLY_NON_EXISTENT_FILE.PYRE')

    def test_filename_noexist_absolute(self):
        """Test non-existent absolute path causes FileNotFoundError exception"""
        with self.assertRaises(FileNotFoundError):
            _find_file(join(BASE_DIR, 'testdata', 'TOTALLY_NON_EXISTENT_FILE.PYRE'))


if __name__ == '__main__':
    unittest.main()
