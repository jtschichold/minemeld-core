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

"""FT Table tests

Unit tests for minemeld.ft.table
"""

import unittest
import tempfile
import shutil
import random
import time

import minemeld.ft.table

from nose.plugins.attrib import attr

TABLENAME = tempfile.mktemp(prefix='minemeld.fttabletest')
NUM_ELEMENTS = 10000


class MineMeldFTTableTests(unittest.TestCase):
    def setUp(self):
        try:
            shutil.rmtree(TABLENAME)
        except:
            pass

    def tearDown(self):
        try:
            shutil.rmtree(TABLENAME)
        except:
            pass

    def test_truncate(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.put('key', {'a': 1})
        table.close()
        table = None

        table = minemeld.ft.table.Table(TABLENAME)
        self.assertEqual(table.num_indicators, 1)
        table.close()
        table = None

        table = minemeld.ft.table.Table(TABLENAME, truncate=True)
        self.assertEqual(table.num_indicators, 0)
        table.close()

    def test_basic(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')
        table.create_index('b')
        table.create_index('a')

        self.assertIsNone(table.get('paperoga'))
        self.assertIsNone(table.get('paperoga'.encode('utf-8')))

        with self.assertRaises(ValueError):
            table.put('paperoga', 10)

        table.put('paperoga', dict(a=10))
        self.assertEqual(
            table.get('paperoga'),
            dict(a=10)
        )

        table.close()

        table = minemeld.ft.table.Table(TABLENAME)
        self.assertEqual(
            table.get('paperoga'.encode('utf-8')),
            dict(a=10)
        )
        table.delete('paperoga')
        table.delete('paperoga'.encode('utf-8'))

        self.assertIsNone(table.get('paperoga'))
        table.close()

    def test_indexes(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('s')
        table.put('k', dict(s='test00'))

        with self.assertRaises(ValueError):
            table.put('k2', dict(s=[]))

        table.put('k2', dict(s='test00'))
        table.put('k3', dict(s='test01'))


        self.assertListEqual(
            list(table.query('s')),
            ['k', 'k2', 'k3']
        )
        table.close()

    def test_insert(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            table.put(key, value)

        self.assertEqual(table.num_indicators, NUM_ELEMENTS)
        table.close()

    def test_index_query(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')
        table.close()

        table = minemeld.ft.table.Table(TABLENAME)
        num_below_500 = 0
        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 1000)}
            key = 'i%d' % i
            table.put(key, value)
            if value['a'] <= 500:
                num_below_500 += 1

        j = 0
        for _, _ in table.query('a', from_key=0, to_key=500,
                                include_value=True):
            j += 1

        self.assertEqual(j, num_below_500)
        table.close()

    def test_index_query_2(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        for i in range(NUM_ELEMENTS):
            value = {'a': 1483184218151+random.randint(600, 1000)}
            key = 'i%d' % i
            table.put(key, value)

        num_below_500 = 0
        for i in range(NUM_ELEMENTS):
            value = {'a': 1483184218151+random.randint(0, 1000)}
            key = 'i%d' % i
            table.put(key, value)
            if value['a'] <= 1483184218151+500:
                num_below_500 += 1

        j = 0
        for _, _ in table.query('a', to_key=1483184218151+500,
                                include_value=True):
            j += 1

        self.assertEqual(j, num_below_500)
        table.close()

    def test_index_query_3(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        for i in range(NUM_ELEMENTS):
            value = {'a': 1483184218151+random.randint(0, 500)}
            key = 'i%d' % i
            table.put(key, value)

        for i in range(NUM_ELEMENTS):
            key = 'i%d' % i
            table.delete(key)

        num_below_500 = 0
        for i in range(NUM_ELEMENTS):
            value = {'a': 1483184218151+random.randint(0, 1000)}
            key = 'i%d' % i
            table.put(key, value)
            if value['a'] <= 1483184218151+500:
                num_below_500 += 1

        j = 0
        for _, _ in table.query('a', to_key=1483184218151+500,
                                include_value=True):
            j += 1

        self.assertEqual(j, num_below_500)
        table.close()

    def test_metadata(self):
        test = dict(test=random.randint(0, 100000))

        table = minemeld.ft.table.Table(TABLENAME)
        self.assertIsNone(table.get_custom_metadata())

        table.set_custom_metadata(metadata=test)
        self.assertEqual(
            test,
            table.get_custom_metadata()
        )
        table.close()

        table = minemeld.ft.table.Table(TABLENAME)
        self.assertEqual(
            test,
            table.get_custom_metadata()
        )

        table.set_custom_metadata(metadata=None)
        self.assertIsNone(table.get_custom_metadata())
        table.close()

        table = minemeld.ft.table.Table(TABLENAME)
        self.assertIsNone(table.get_custom_metadata())
        table.close()

    def test_query(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            table.put(key, value)

        j = 0
        for _, _ in table.query(include_value=True):
            j += 1

        self.assertEqual(j, NUM_ELEMENTS)
        table.close()

    def test_query_range(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 500)}
            key = 'i%08x' % i
            table.put(key, value)

        # this should generate a stale index entry
        lastk = 'i%08x' % (NUM_ELEMENTS+1)
        value = dict(a=501)
        table.put(lastk, value)
        table.delete(lastk)

        with self.assertRaises(ValueError):
            list(table.query(index='b'))

        j = 0
        for _ in table.query(from_key='i00000000', to_key='iFFFFFFFF', include_start=True, include_stop=True, include_value=False):
            j += 1
        self.assertEqual(j, NUM_ELEMENTS)

        j = 0
        for _ in table.query('a', include_start=True, include_stop=True, include_value=False):
            j += 1
        self.assertEqual(j, NUM_ELEMENTS)

        table.close()

    def test_exists(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            table.put(key, value)

        for i in range(NUM_ELEMENTS):
            j = random.randint(0, NUM_ELEMENTS-1)
            self.assertTrue(
                table.exists('i%d' % j),
                msg="i%d does not exists" % j
            )
        table.close()

    def test_not_exists(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            table.put(key, value)

        for i in range(NUM_ELEMENTS):
            j = random.randint(NUM_ELEMENTS, 2*NUM_ELEMENTS)
            self.assertFalse(table.exists('i%d' % j))
        table.close()

    def test_update(self):
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        table.put('k1', {'a': 1})
        table.put('k2', {'a': 1})
        table.put('k1', {'a': 2})

        ok = 0
        rk = None
        for k in table.query('a', from_key=0, to_key=1):
            rk = k
            ok += 1

        self.assertEqual(rk, 'k2')
        self.assertEqual(ok, 1)
        table.close()

    @attr('slow')
    def test_random(self):
        # create table
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        # local dict
        d = {}

        # add 10000 elements to the table
        # with an 'a' attribute in range 0,500
        for i in range(NUM_ELEMENTS):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            d[key] = value
            table.put(key, value)

        # check number of indicators added
        self.assertEqual(table.num_indicators, len(d.keys()))

        # check sorted query retrieval
        flatdict = sorted(d.items(), key=lambda x: x[1]['a'])
        j = 0
        for _, v in table.query('a', from_key=0, to_key=500,
                                include_value=True):
            de = flatdict[j]
            self.assertEqual(de[1]['a'], v['a'])
            j = j+1

        # 1000 random add or delete
        for j in range(1000):
            op = random.randint(0, 1)

            if op == 0:
                # delete
                i = 'i%d' % random.randint(0, 2000)
                if i in d:
                    del d[i]
                table.delete(i)
            elif op == 1:
                # add
                i = 'i%d' % random.randint(0, 2000)
                v = {'a': random.randint(0, 500)}
                table.put(i, v)
                d[i] = v

            # check num of indicators
            self.assertEqual(table.num_indicators, len(d.keys()))
            flatdict = sorted(d.items(), key=lambda x: x[1]['a'])
            j = 0
            for _, v in table.query('a', from_key=0, to_key=500,
                                    include_value=True):
                de = flatdict[j]
                # check sorting
                self.assertEqual(de[1]['a'], v['a'])
                j = j+1

        # close table
        table.close()
        table = None

        # reopen
        table = minemeld.ft.table.Table(TABLENAME)
        table.create_index('a')

        self.assertEqual(table.num_indicators, len(d.keys()))

        # check sort again
        flatdict = sorted(d.items(), key=lambda x: x[1]['a'])
        j = 0
        for _, v in table.query('a', from_key=0, to_key=500,
                                include_value=True):
            de = flatdict[j]
            self.assertEqual(de[1]['a'], v['a'])
            j = j+1

        table.close()

    @attr('slow')
    def test_write(self):
        # create table
        table = minemeld.ft.table.Table(TABLENAME)

        # local dict
        d = {}

        t1 = time.time()
        for i in range(100000):
            value = {'a': random.randint(0, 500)}
            key = 'i%d' % i
            d[key] = value
            table.put(key, value)
        t2 = time.time()
        print('TIME: Written {} elements in {} secs'.format(100000, t2-t1))

        # check number of indicators added
        self.assertEqual(table.num_indicators, len(d.keys()))

        table.close()
        table = None
