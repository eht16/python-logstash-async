# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from datetime import date, datetime
import logging
import socket
import sys
import time
import traceback
import uuid
try:
    import json
except ImportError:
    import simplejson as json

import logstash_async

# The list contains all the attributes listed in
# http://docs.python.org/library/logging.html#logrecord-attributes
RECORD_FIELD_SKIP_LIST = (
    'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
    'funcName', 'id', 'levelname', 'levelno', 'lineno', 'module',
    'msecs', 'message', 'msg', 'name', 'pathname', 'process',
    'processName', 'relativeCreated', 'stack_info', 'thread', 'threadName')
LOGSTASH_MESSAGE_FIELD_LIST = [
    '@timestamp', '@version', 'host', 'level', 'logsource', 'message',
    'pid', 'program', 'type', 'tags']


class LogstashFormatter(logging.Formatter):

    # ----------------------------------------------------------------------
    def __init__(self, message_type='python-logstash', tags=None, fqdn=False, extra_prefix='extra', extra=None):
        super(LogstashFormatter, self).__init__()
        self._message_type = message_type
        self._tags = tags if tags is not None else []
        self._extra_prefix = extra_prefix
        self._extra = extra

        self._interpreter = None
        self._interpreter_version = None
        self._host = None
        self._logsource = None
        self._program_name = None

        # fetch static information and process related information already as they won't change during lifetime
        self._prefetch_interpreter()
        self._prefetch_interpreter_version()
        self._prefetch_host(fqdn)
        self._prefetch_logsource()
        self._prefetch_program_name()

    # ----------------------------------------------------------------------
    def _prefetch_interpreter(self):
        """Override when needed"""
        self._interpreter = sys.executable

    # ----------------------------------------------------------------------
    def _prefetch_interpreter_version(self):
        """Override when needed"""
        self._interpreter_version = u'{}.{}.{}'.format(
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro)

    # ----------------------------------------------------------------------
    def _prefetch_host(self, fqdn):
        """Override when needed"""
        if fqdn:
            self._host = socket.getfqdn()
        else:
            self._host = socket.gethostname()

    # ----------------------------------------------------------------------
    def _prefetch_logsource(self):
        """Override when needed"""
        self._logsource = self._host

    # ----------------------------------------------------------------------
    def _prefetch_program_name(self):
        """Override when needed"""
        self._program_name = sys.argv[0]

    # ----------------------------------------------------------------------
    def format(self, record):
        message = {
            '@timestamp': self._format_timestamp(record.created),
            '@version': '1',
            'host': self._host,
            'level': record.levelname,
            'logsource': self._logsource,
            'message': record.getMessage(),
            'pid': record.process,
            'program': self._program_name,
            'type': self._message_type,
        }
        if self._tags:
            message['tags'] = self._tags

        # record fields
        record_fields = self._get_record_fields(record)
        message.update(record_fields)
        # prepare dynamic extra fields
        extra_fields = self._get_extra_fields(record)
        # wrap extra fields in configurable namespace
        if self._extra_prefix:
            message[self._extra_prefix] = extra_fields
        else:
            message.update(extra_fields)

        # move existing extra record fields into the configured prefix
        self._move_extra_record_fields_to_prefix(message)

        return self._serialize(message)

    # ----------------------------------------------------------------------
    def _format_timestamp(self, time_):
        tstamp = datetime.utcfromtimestamp(time_)
        return tstamp.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (tstamp.microsecond / 1000) + "Z"

    # ----------------------------------------------------------------------
    def _get_record_fields(self, record):
        def value_repr(value):
            if sys.version_info < (3, 0):
                easy_types = (basestring, bool, float, int, long, type(None))
            else:
                easy_types = (str, bool, float, int, type(None))

            if isinstance(value, dict):
                return {k: value_repr(v) for k, v in value.items()}
            elif isinstance(value, (tuple, list)):
                return [value_repr(v) for v in value]
            elif isinstance(value, (datetime, date)):
                return self._format_timestamp(time.mktime(value.timetuple()))
            elif isinstance(value, uuid.UUID):
                return value.hex
            elif isinstance(value, easy_types):
                return value
            else:
                return repr(value)

        fields = {}

        for key, value in record.__dict__.items():
            if key not in RECORD_FIELD_SKIP_LIST:
                fields[key] = value_repr(value)
        return fields

    # ----------------------------------------------------------------------
    def _get_extra_fields(self, record):
        extra_fields = {
            'func_name': record.funcName,
            'interpreter': self._interpreter,
            'interpreter_version': self._interpreter_version,
            'line': record.lineno,
            'logger_name': record.name,
            'logstash_async_version': logstash_async.__version__,
            'path': record.pathname,
            'process_name': record.processName,
            'thread_name': record.threadName,
        }
        # static extra fields
        if self._extra:
            extra_fields.update(self._extra)
        # exceptions
        if record.exc_info:
            extra_fields['stack_trace'] = self._format_exception(record.exc_info)
        return extra_fields

    # ----------------------------------------------------------------------
    def _format_exception(self, exc_info):
        if isinstance(exc_info, tuple):
            stack_trace = ''.join(traceback.format_exception(*exc_info))
        elif exc_info:
            stack_trace = ''.join(traceback.format_stack())
        else:
            stack_trace = ''
        return stack_trace

    # ----------------------------------------------------------------------
    def _move_extra_record_fields_to_prefix(self, message):
        """
        Anythng added by the "extra" keyword in the logging call will be moved into the
        configured "extra" prefix. This way the event in Logstash will be clean and any extras
        will be paired together in the configured extra prefix.
        If not extra prefix is configured, the message will be kept as is.
        """
        if not self._extra_prefix:
            return  # early out if no prefix is configured

        field_skip_list = LOGSTASH_MESSAGE_FIELD_LIST + [self._extra_prefix]
        for key in list(message):
            if key not in field_skip_list:
                message[self._extra_prefix][key] = message.pop(key)

    # ----------------------------------------------------------------------
    def _serialize(self, message):
        if sys.version_info < (3, 0):
            return json.dumps(message)
        else:
            return bytes(json.dumps(message), 'utf-8')


class DjangoLogstashFormatter(LogstashFormatter):

    # ----------------------------------------------------------------------
    def __init__(self, *args, **kwargs):
        super(DjangoLogstashFormatter, self).__init__(*args, **kwargs)
        self._django_version = None
        self._fetch_django_version()

    # ----------------------------------------------------------------------
    def _fetch_django_version(self):
        from django import get_version
        self._django_version = get_version()

    # ----------------------------------------------------------------------
    def _get_extra_fields(self, record):
        extra_fields = super(DjangoLogstashFormatter, self)._get_extra_fields(record)

        if hasattr(record, 'status_code'):
            extra_fields['status_code'] = record.status_code

        # Django's runserver command passes socketobject and WSGIRequest instances as "request".
        # Hence the check for the META attribute.
        # For details see https://code.djangoproject.com/ticket/27234
        if hasattr(record, 'request') and hasattr(record.request, 'META'):
            request = record.request
            extra_fields['django_version'] = self._django_version
            extra_fields['req_useragent'] = request.META.get('HTTP_USER_AGENT', '<none>')
            extra_fields['req_remote_address'] = request.META.get('REMOTE_ADDR', '<none>')
            extra_fields['req_host'] = request.get_host()
            extra_fields['req_uri'] = request.get_raw_uri()
            extra_fields['req_user'] = unicode(request.user) if request.user else ''
            extra_fields['req_method'] = request.META.get('REQUEST_METHOD', '')
            extra_fields['req_referer'] = request.META.get('HTTP_REFERER', '')

            forwarded_proto = request.META.get('HTTP_X_FORWARDED_PROTO', None)
            if forwarded_proto is not None:
                extra_fields['req_forwarded_proto'] = forwarded_proto

            forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', None)
            if forwarded_for is not None:
                # make it a list
                forwarded_for_list = forwarded_for.replace(' ', '').split(',')
                extra_fields['req_forwarded_for'] = forwarded_for_list

            # template debug
            if isinstance(record.exc_info, tuple):
                exc_value = record.exc_info[1]
                template_info = getattr(exc_value, 'template_debug', None)
                if template_info:
                    extra_fields['tmpl_name'] = template_info['name']
                    extra_fields['tmpl_line'] = template_info['line']
                    extra_fields['tmpl_message'] = template_info['message']
                    extra_fields['tmpl_during'] = template_info['during']

        return extra_fields
