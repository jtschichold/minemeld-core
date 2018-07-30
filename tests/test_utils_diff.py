"""Utils Diff tests

Unit tests for minemeld.utils.diff
"""

import unittest
import tempfile
import shutil
import random
import time

from minemeld.utils import compare, diff_dicts

class MineMeldUtilsDiffTests(unittest.TestCase):
    def test_compare_1(self):
        self.assertFalse(compare('a', True))
        self.assertTrue(compare(None, None))
        self.assertTrue(compare(False, False))
        self.assertFalse(compare(True, False))
        self.assertTrue(compare(1, 1))
        self.assertFalse(compare(1, 2))
        self.assertTrue(compare('foo', 'foo'))
        self.assertFalse(compare('bar', 'foo'))
        self.assertTrue(compare(b'\x00\x01', b'\x00\x01'))
        self.assertFalse(compare(b'\x00\x01', b'\x00\x02'))
        
        with self.assertRaises(RuntimeError):
            compare(set([]), set([]))

    def test_compare_list(self):
        self.assertTrue(compare([1,2,3], [3,2,1]))
        self.assertFalse(compare([1,2,3], [1,2,3,4]))
        self.assertTrue(compare([], []))
        self.assertFalse(compare([4,2,3], [4,1,2]))

    def test_compare_dict(self):
        self.assertTrue(compare(dict(A=1,B=2,C=3), dict(C=3,B=2,A=1)))
        self.assertFalse(compare(dict(A=1,B=2,C=3), dict(C=3,B=2,D=1)))
        self.assertFalse(compare(dict(A=1,B=2,C='a'), dict(C=3,B=2,A=1)))

    def test_compare_list_dict(self):
        self.assertTrue(compare(
            [dict(id=1,A=1),dict(id=2,A=2)],
            [dict(id=2,A=2),dict(id=1,A=1)]
        ))

    def test_diff_dict_1(self):
        result = diff_dicts(dict(A=1), dict(B=2))
        result.sort()
        self.assertListEqual(
            result,
            ['A', 'B']
        )

        result = diff_dicts(dict(A=1), dict(B=2,A=2))
        result.sort()
        self.assertListEqual(
            result,
            ['A', 'B']
        )

        result = diff_dicts(dict(A=2), dict(B=2,A=2))
        result.sort()
        self.assertListEqual(
            result,
            ['B']
        )
