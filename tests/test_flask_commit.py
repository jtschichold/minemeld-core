#  Copyright 2015 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""FT run config tests

Unit tests for minemeld.run.config
"""

import unittest
import mock

import minemeld.flask.commit

class MineMeldCommitTests(unittest.TestCase):
    def test_numeric_types(self):
        self.assertTrue(
            minemeld.flask.commit._is_equal(
                1, 1
            )
        )
        self.assertFalse(
            minemeld.flask.commit._is_equal(
                1, 2
            )
        )
        self.assertTrue(
            minemeld.flask.commit._is_equal(
                1.0, 1.0
            )
        )
        self.assertFalse(
            minemeld.flask.commit._is_equal(
                1.0, 2.0
            )
        )

    def test_string_types(self):
        self.assertTrue(
            minemeld.flask.commit._is_equal(
                "a", "a"
            )
        )
        self.assertFalse(
            minemeld.flask.commit._is_equal(
                "b", "a"
            )
        )
        self.assertTrue(
            minemeld.flask.commit._is_equal(
                u"a", u"a"
            )
        )
        self.assertFalse(
            minemeld.flask.commit._is_equal(
                u"a", u"b"
            )
        )

    def test_list(self):
        self.assertTrue(
            minemeld.flask.commit._is_equal(
                ["a", "b"], ["a", "b"]
            )
        )
        self.assertFalse(
            minemeld.flask.commit._is_equal(
                ["b", "b"], ["a", "b"]
            )
        )
        self.assertTrue(
            minemeld.flask.commit._is_equal(
                [1, 2], [2, 1]
            )
        )
        self.assertFalse(
            minemeld.flask.commit._is_equal(
                [u"a", u"b"], [u"c", u"d"]
            )
        )

    def test_dict(self):
        self.assertTrue(
            minemeld.flask.commit._is_equal(
                dict(a=1, b=2), dict(b=2, a=1)
            )
        )
        self.assertFalse(
            minemeld.flask.commit._is_equal(
                dict(a=2, b=2), dict(a="a", b=2)
            )
        )
        self.assertTrue(
            minemeld.flask.commit._is_equal(
                dict(a=u"1", b="foobar"), dict(b="foobar", a=u"1")
            )
        )
        self.assertFalse(
            minemeld.flask.commit._is_equal(
                dict(a=1, b=2, c=3), dict(b=2, c=3, d=4)
            )
        )

    def test_dict_list(self):
        self.assertTrue(minemeld.flask.commit._is_equal(
            dict(a=[2,3,1],b=dict(c=1,b="a")),
            dict(a=[3,2,1],b=dict(b="a",c=1))
        ))
        self.assertFalse(minemeld.flask.commit._is_equal(
            dict(a=[2,3,1],b=dict(c=1,b="a")),
            dict(a=[3,2,1],b=dict(b="b",c=1))
        ))
        self.assertTrue(minemeld.flask.commit._is_equal(
            [dict(a=1),dict(a=2)],
            [dict(a=1),dict(a=2)]
        ))
        self.assertFalse(minemeld.flask.commit._is_equal(
            [dict(a=1),dict(a=2)],
            [dict(a=2),dict(a=1)]
        ))
