# -*- coding: utf-8 -*-

import logging

from logstash_async.handler import AsynchronousLogstashHandler

host = 'localhost'
port = 5959

logger = logging.getLogger('logstash_async.transport')
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
logging_format = '%(asctime)s.%(msecs)03d'
logging_format += ' | %(levelname)-8s'
logging_format += ' | %(name)s.%(module)s.%(funcName)s'
logging_format += ' | %(message)s'
date_format = '%Y-%m-%d | %H:%M:%S'
formatter = logging.Formatter(logging_format, date_format)
handler.setFormatter(formatter)
logger.addHandler(handler)

test_logger = logging.getLogger('test')
test_logger.setLevel(logging.DEBUG)
handler = AsynchronousLogstashHandler(
    host,
    port,
    ssl_enable=False,
    username='logstash',
    password='testing',
    transport='logstash_async.transport.HttpTransport',
    database_path='logstash_test.db'
)
test_logger.addHandler(handler)

# These tests crash logstash if the heap space is not enough
for _ in range(11):
    test_logger.critical('A' * 10 * 1024 * 1024)
test_logger.fatal('A' * 100 * 1024 * 1024)

for i in range(50):
    test_logger.info('test %s', i)

test_logger.info('end')
