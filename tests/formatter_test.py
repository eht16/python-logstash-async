# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

import importlib.metadata
import os
import socket
import sys
import unittest
from contextlib import suppress
from logging import FileHandler, makeLogRecord
from types import SimpleNamespace
from unittest.mock import patch

import logstash_async
from logstash_async.formatter import (
    DjangoLogstashEcsFormatter,
    DjangoLogstashFormatter,
    FlaskLogstashEcsFormatter,
    FlaskLogstashFormatter,
    LogstashEcsFormatter,
    LogstashFormatter,
)


# ruff: noqa: PT009, SLF001 pylint: disable=protected-access

INTERPRETER_VERSION = f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}'


def create_log_record(**kwargs):
    return makeLogRecord({
        'msg': 'test',
        'created': 1635082335.024747,
        'levelname': 'INFO',
        'process': 1,
        'funcName': 'f',
        'lineno': 2,
        'name': 'foo',
        'pathname': 'a/b/c',
        'processName': 'bar',
        'threadName': 'baz',
        'exc_info': (ValueError, None, None),
        **kwargs,
    })


class ExceptionCatchingFileHandler(FileHandler):
    def __init__(self, *args, **kwargs):
        FileHandler.__init__(self, *args, **kwargs)
        self.exception = None

    def handleError(self, record):  # noqa: N802
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

    @patch.object(LogstashFormatter, '_format_exception', lambda s, e: e)
    def test_default_schema(self):
        formatter = LogstashFormatter(tags=['t1', 't2'])
        result = formatter._format_to_dict(create_log_record())
        self.assertDictEqual(result, {
            '@timestamp': '2021-10-24T13:32:15.024Z',
            '@version': '1',
            'host': socket.gethostname(),
            'level': 'INFO',
            'logsource': socket.gethostname(),
            'message': 'test',
            'pid': 1,
            'program': sys.argv[0],
            'type': 'python-logstash',
            'tags': ['t1', 't2'],
            'extra': {
                'func_name': 'f',
                'interpreter': sys.executable,
                'interpreter_version': INTERPRETER_VERSION,
                'line': 2,
                'logger_name': 'foo',
                'logstash_async_version': logstash_async.__version__,
                'path': 'a/b/c',
                'process_name': 'bar',
                'thread_name': 'baz',
                'stack_trace': (ValueError, None, None),
                'error_type': 'ValueError',
            }
        })


@patch.object(LogstashEcsFormatter, '_format_exception', lambda s, e: e)
class LogstashEcsFormatterTest(unittest.TestCase):
    def test_default_schema(self):
        formatter = LogstashEcsFormatter(tags=['t1', 't2'])
        result = formatter._format_to_dict(create_log_record())
        self.assertDictEqual(result, {
            '@timestamp': '2021-10-24T13:32:15.024Z',
            '@version': '1',
            'ecs': {'version': '8.11.0'},
            'event': {'module': 'python-logstash'},
            'host': {'hostname': socket.gethostname()},
            'log': {
                'level': 'INFO',
                'syslog': {'hostname': socket.gethostname()},
                'origin': {
                    'file': {'line': 2, 'name': 'a/b/c'},
                    'function': 'f',
                },
                'logger': 'foo',
            },
            'message': 'test',
            'process': {
                'thread': {'name': 'baz'},
                'name': 'bar',
                'pid': 1,
                'executable': sys.argv[0],
            },
            'error': {'stack_trace': (ValueError, None, None), 'type': 'ValueError'},
            'tags': ['t1', 't2'],
            'extra': {
                'interpreter': sys.executable,
                'interpreter_version': INTERPRETER_VERSION,
                'logstash_async_version': logstash_async.__version__,
            }
        })

    def test_dotted_schema(self):
        class _LogstashEcsFormatter(LogstashEcsFormatter):
            normalize_ecs_message = False

        formatter = _LogstashEcsFormatter(tags=['t1', 't2'])
        result = formatter._format_to_dict(create_log_record())
        self.assertDictEqual(result, {
            '@timestamp': '2021-10-24T13:32:15.024Z',
            '@version': '1',
            'ecs.version': '8.11.0',
            'event.module': 'python-logstash',
            'host.hostname': socket.gethostname(),
            'log.level': 'INFO',
            'log.syslog.hostname': socket.gethostname(),
            'log.origin.file.line': 2,
            'log.origin.file.name': 'a/b/c',
            'log.origin.function': 'f',
            'log.logger': 'foo',
            'message': 'test',
            'process.thread.name': 'baz',
            'process.name': 'bar',
            'process.pid': 1,
            'process.executable': sys.argv[0],
            'error.stack_trace': (ValueError, None, None),
            'error.type': 'ValueError',
            'tags': ['t1', 't2'],
            'extra': {
                'interpreter': sys.executable,
                'interpreter_version': INTERPRETER_VERSION,
                'logstash_async_version': logstash_async.__version__,
            }
        })


class DjangoTestMixin:
    @classmethod
    def setUpClass(cls):  # pylint: disable=invalid-name
        super().setUpClass()

        # pylint: disable=import-outside-toplevel
        import django
        from django.conf import settings
        from django.http import HttpRequest

        # pylint: enable=import-outside-toplevel

        with suppress(RuntimeError):
            settings.configure()
        cls.HttpRequest = HttpRequest
        cls.django_version = django.get_version()

    def _create_request(self):
        request = self.HttpRequest()
        request.user = 'usr'
        request.META.update({
            'HTTP_USER_AGENT': 'dj-agent',
            'REMOTE_ADDR': 'dj-addr',
            'HTTP_HOST': 'dj-host',
            'HTTP_REFERER': 'dj-ref',
            'REQUEST_METHOD': 'GET',
            'HTTP_X_FORWARDED_PROTO': 'dj-f-proto',
            'HTTP_X_FORWARDED_FOR': 'dj-f1, dj-f2',
        })
        return request


class DjangoLogstashFormatterTest(DjangoTestMixin, unittest.TestCase):
    @patch.object(DjangoLogstashFormatter, '_format_exception', lambda s, e: e)
    def test_default_schema(self):
        formatter = DjangoLogstashFormatter(tags=['t1', 't2'])
        exc_info = (ValueError, SimpleNamespace(template_debug={
            'name': 'tpl',
            'line': 3,
            'message': 'tmsg',
            'during': 'd',
        }), None)
        result = formatter._format_to_dict(create_log_record(
            status_code=500,
            request=self._create_request(),
            exc_info=exc_info,
        ))
        self.assertDictEqual(result, {
            '@timestamp': '2021-10-24T13:32:15.024Z',
            '@version': '1',
            'host': socket.gethostname(),
            'level': 'INFO',
            'logsource': socket.gethostname(),
            'message': 'test',
            'pid': 1,
            'program': sys.argv[0],
            'type': 'python-logstash',
            'tags': ['t1', 't2'],
            'extra': {
                'func_name': 'f',
                'interpreter': sys.executable,
                'interpreter_version': INTERPRETER_VERSION,
                'line': 2,
                'logger_name': 'foo',
                'logstash_async_version': logstash_async.__version__,
                'path': 'a/b/c',
                'process_name': 'bar',
                'thread_name': 'baz',
                'stack_trace': exc_info,
                'error_type': 'ValueError',
                'status_code': 500,
                'django_version': self.django_version,
                'req_useragent': 'dj-agent',
                'req_remote_address': 'dj-addr',
                'req_host': 'dj-host',
                'req_uri': None,
                'req_user': 'usr',
                'req_method': 'GET',
                'req_referer': 'dj-ref',
                'req_forwarded_proto': 'dj-f-proto',
                'req_forwarded_for': ['dj-f1', 'dj-f2'],
                'tmpl_name': 'tpl',
                'tmpl_line': 3,
                'tmpl_message': 'tmsg',
                'tmpl_during': 'd',
                'request': '<HttpRequest>',
            }
        })


class DjangoLogstashEcsFormatterTest(DjangoTestMixin, unittest.TestCase):
    @patch.object(DjangoLogstashEcsFormatter, '_format_exception', lambda s, e: e)
    def test_default_schema(self):
        formatter = DjangoLogstashEcsFormatter(tags=['t1', 't2'])
        exc_info = (ValueError, SimpleNamespace(template_debug={
            'name': 'tpl',
            'line': 3,
            'message': 'tmsg',
            'during': 'd',
        }), None)
        result = formatter._format_to_dict(create_log_record(
            status_code=500,
            request=self._create_request(),
            exc_info=exc_info,
        ))
        self.assertDictEqual(result, {
            '@timestamp': '2021-10-24T13:32:15.024Z',
            '@version': '1',
            'ecs': {'version': '8.11.0'},
            'event': {'module': 'python-logstash'},
            'host': {'hostname': socket.gethostname()},
            'client': {'domain': 'dj-host', 'ip': 'dj-addr'},
            'http': {
                'request': {'method': 'GET', 'referrer': 'dj-ref'},
                'response': {'status_code': 500},
            },
            'url': {'original': None},
            'user': {'name': 'usr'},
            'user_agent': {'original': 'dj-agent'},
            'log': {
                'level': 'INFO',
                'syslog': {'hostname': socket.gethostname()},
                'origin': {
                    'file': {'line': 2, 'name': 'a/b/c'},
                    'function': 'f',
                },
                'logger': 'foo',
            },
            'message': 'test',
            'process': {
                'thread': {'name': 'baz'},
                'name': 'bar',
                'pid': 1,
                'executable': sys.argv[0],
            },
            'error': {'stack_trace': exc_info, 'type': 'ValueError'},
            'tags': ['t1', 't2'],
            'extra': {
                'interpreter': sys.executable,
                'interpreter_version': INTERPRETER_VERSION,
                'logstash_async_version': logstash_async.__version__,
                'req_forwarded_proto': 'dj-f-proto',
                'req_forwarded_for': ['dj-f1', 'dj-f2'],
                'tmpl_name': 'tpl',
                'tmpl_line': 3,
                'tmpl_message': 'tmsg',
                'tmpl_during': 'd',
                'request': '<HttpRequest>',
                'django_version': self.django_version,
            }
        })


class FlaskTestMixin:
    @classmethod
    def setUpClass(cls):  # pylint: disable=invalid-name
        super().setUpClass()
        cls.flask_version = importlib.metadata.version('flask')

    def _create_request(self):
        return SimpleNamespace(
            user_agent='f-agent',
            remote_addr='f-addr',
            host='f-host:80',
            url='f-url',
            method='GET',
            referrer='f-ref',
            remote_user='usr',
            headers={
                'X-Request-ID': 'x-id',
                'X-Forwarded-Proto': 'f-proto',
                'X-Forwarded-For': 'f1, f2',
            },
        )


class FlaskLogstashFormatterTest(FlaskTestMixin, unittest.TestCase):
    @patch.object(FlaskLogstashFormatter, '_format_exception', lambda s, e: e)
    def test_default_schema(self):
        with patch('flask.request', self._create_request()):
            formatter = FlaskLogstashFormatter(tags=['t1', 't2'])
            result = formatter._format_to_dict(create_log_record(status_code=500))
        self.assertDictEqual(result, {
            '@timestamp': '2021-10-24T13:32:15.024Z',
            '@version': '1',
            'host': socket.gethostname(),
            'level': 'INFO',
            'logsource': socket.gethostname(),
            'message': 'test',
            'pid': 1,
            'program': sys.argv[0],
            'type': 'python-logstash',
            'tags': ['t1', 't2'],
            'extra': {
                'func_name': 'f',
                'interpreter': sys.executable,
                'interpreter_version': INTERPRETER_VERSION,
                'line': 2,
                'logger_name': 'foo',
                'logstash_async_version': logstash_async.__version__,
                'path': 'a/b/c',
                'process_name': 'bar',
                'thread_name': 'baz',
                'error_type': 'ValueError',
                'stack_trace': (ValueError, None, None),
                'status_code': 500,
                'flask_version': self.flask_version,
                'req_useragent': 'f-agent',
                'req_remote_address': 'f-addr',
                'req_host': 'f-host',
                'req_uri': 'f-url',
                'req_user': 'usr',
                'req_method': 'GET',
                'req_referer': 'f-ref',
                'req_forwarded_proto': 'f-proto',
                'req_forwarded_for': ['f1', 'f2'],
                'request_id': 'x-id',
            }
        })


class FlaskLogstashEcsFormatterTest(FlaskTestMixin, unittest.TestCase):
    @patch.object(FlaskLogstashEcsFormatter, '_format_exception', lambda s, e: e)
    def test_default_schema(self):
        with patch('flask.request', self._create_request()):
            formatter = FlaskLogstashEcsFormatter(tags=['t1', 't2'])
            result = formatter._format_to_dict(create_log_record(status_code=500))
        self.assertDictEqual(result, {
            '@timestamp': '2021-10-24T13:32:15.024Z',
            '@version': '1',
            'ecs': {'version': '8.11.0'},
            'event': {'module': 'python-logstash'},
            'host': {'hostname': socket.gethostname()},
            'client': {'domain': 'f-host', 'ip': 'f-addr'},
            'http': {
                'request': {'id': 'x-id', 'method': 'GET', 'referrer': 'f-ref'},
                'response': {'status_code': 500},
            },
            'url': {'original': 'f-url'},
            'user': {'name': 'usr'},
            'user_agent': {'original': 'f-agent'},
            'log': {
                'level': 'INFO',
                'syslog': {'hostname': socket.gethostname()},
                'origin': {
                    'file': {'line': 2, 'name': 'a/b/c'},
                    'function': 'f',
                },
                'logger': 'foo',
            },
            'message': 'test',
            'process': {
                'thread': {'name': 'baz'},
                'name': 'bar',
                'pid': 1,
                'executable': sys.argv[0],
            },
            'error': {'stack_trace': (ValueError, None, None), 'type': 'ValueError'},
            'tags': ['t1', 't2'],
            'extra': {
                'interpreter': sys.executable,
                'interpreter_version': INTERPRETER_VERSION,
                'logstash_async_version': logstash_async.__version__,
                'req_forwarded_proto': 'f-proto',
                'req_forwarded_for': ['f1', 'f2'],
                'flask_version': self.flask_version,
            }
        })


if __name__ == '__main__':
    unittest.main()
