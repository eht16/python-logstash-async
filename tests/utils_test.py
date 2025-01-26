import unittest
from copy import deepcopy

from logstash_async.utils import normalize_ecs_dict


# ruff: noqa: PT009


class NormalizeEcsDictTest(unittest.TestCase):
    def test_de_dot(self):
        with self.subTest('no dots'):
            result = normalize_ecs_dict.de_dot_record('a', {'x': [1]})
            self.assertDictEqual(result, {'a': {'x': [1]}})
        with self.subTest('dots'):
            result = normalize_ecs_dict.de_dot_record('a.b.c', {'x': [1]})
            self.assertDictEqual(result, {'a': {'b': {'c': {'x': [1]}}}})

    def test_normalization(self):
        d = {
            'a': 1,
            'b': 11,
            'b.c': {
                'd.e': [2, ({'f.g': 3}, 4), 5],
                'h': None,
            },
            'b.c.x': {'y': 6},
            'c': {'d': [1], 'e': 2},
            'c.d': [2],
            'c.f': 3,
        }
        d_copy = deepcopy(d)
        expected = {
            'a': 1,
            'b': {
                'c': {
                    'd': {
                        'e': [2, ({'f': {'g': 3}}, 4), 5],
                    },
                    'h': None,
                    'x': {'y': 6},
                },
            },
            'c': {'d': [2], 'e': 2, 'f': 3},
        }
        result = normalize_ecs_dict(d)
        self.assertDictEqual(result, expected)

        with self.subTest('source dict not mutated'):
            self.assertDictEqual(d, d_copy)
            # pylint: disable-next=unsubscriptable-object
            result['c']['d'].append(22)
            self.assertDictEqual(d, d_copy)
