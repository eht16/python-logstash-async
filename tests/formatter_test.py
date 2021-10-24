# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from logging import FileHandler, makeLogRecord
import os
import sys
import unittest

from logstash_async.formatter import LogstashFormatter


# pylint: disable=protected-access


class ExceptionCatchingFileHandler(FileHandler):
    def __init__(self, *args, **kwargs):
        FileHandler.__init__(self, *args, **kwargs)
        self.exception = None

    def handleError(self, record):
        self.exception = sys.exc_info()


class LogstashFormatterTest(unittest.TestCase):
    def test_format(self):
        file_handler = ExceptionCatchingFileHandler(os.devnull)
        file_handler.setFormatter(LogstashFormatter(ensure_ascii=False))
        file_handler.emit(makeLogRecord({'msg': 'тест'}))
        file_handler.close()

        self.assertIsNone(file_handler.exception)

    def test_format_timestamp_no_millisecond(self):
        formatter = LogstashFormatter()
        # 2021-10-24 13:32:15
        test_time_simple = 1635082335
        result = formatter._format_timestamp(test_time_simple)
        self.assertEqual(result, '2021-10-24T13:32:15.000Z')

    def test_format_timestamp_millisecond(self):
        formatter = LogstashFormatter()
        # 2021-10-24 13:32:15.024000
        test_time_millisecond = 1635082335.024000
        result = formatter._format_timestamp(test_time_millisecond)
        self.assertEqual(result, '2021-10-24T13:32:15.024Z')

    def test_format_timestamp_microsecond_1(self):
        formatter = LogstashFormatter()
        # 2021-10-24 13:32:15.000024
        test_time_microsecond1 = 1635082335.000024
        result = formatter._format_timestamp(test_time_microsecond1)
        self.assertEqual(result, '2021-10-24T13:32:15.000Z')

    def test_format_timestamp_microsecond_2(self):
        formatter = LogstashFormatter()
        # 2021-10-24 13:32:15.024747
        test_time_microsecond2 = 1635082335.024747
        result = formatter._format_timestamp(test_time_microsecond2)
        self.assertEqual(result, '2021-10-24T13:32:15.024Z')


if __name__ == '__main__':
    unittest.main()
