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

from logstash_async.constants import constants
import logstash_async


try:
    import json
except ImportError:
    import simplejson as json


class LogstashFormatter(logging.Formatter):

    _basic_data_types = (type(None), bool, str, int, float)

    # ----------------------------------------------------------------------
    # pylint: disable=too-many-arguments
    def __init__(
            self,
            message_type='python-logstash',
            tags=None,
            fqdn=False,
            extra_prefix='extra',
            extra=None,
            ensure_ascii=True,
            metadata=None,
    ):
        super().__init__()
        self._message_type = message_type
        self._tags = tags if tags is not None else []
        self._extra_prefix = extra_prefix
        self._extra = extra
        self._ensure_ascii = ensure_ascii
        self._metadata = metadata

        self._interpreter = None
        self._interpreter_version = None
        self._host = None
        self._logsource = None
        self._program_name = None

        # fetch static information and process related information already
        # as they won't change during lifetime
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
        self._interpreter_version = \
            f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}'

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
        if self._metadata:
            message['@metadata'] = self._metadata
        if self._tags:
            message['tags'] = self._tags

        # record fields
        record_fields = self._get_record_fields(record)
        message.update(record_fields)
        # prepare dynamic extra fields
        extra_fields = self._get_extra_fields(record)
        # remove all fields to be excluded
        self._remove_excluded_fields(message, extra_fields)
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
        timestamp = datetime.utcfromtimestamp(time_)
        formatted_timestamp = timestamp.strftime('%Y-%m-%dT%H:%M:%S')
        microsecond = int(timestamp.microsecond / 1000)
        return f'{formatted_timestamp}.{microsecond:03}Z'

    # ----------------------------------------------------------------------
    def _get_record_fields(self, record):
        return {k: self._value_repr(v) for k, v in record.__dict__.items()}

    # ----------------------------------------------------------------------
    def _value_repr(self, value):
        if isinstance(value, self._basic_data_types):
            return value
        elif isinstance(value, (datetime, date)):
            return self._format_timestamp(time.mktime(value.timetuple()))
        elif isinstance(value, uuid.UUID):
            return value.hex
        elif isinstance(value, dict):
            return {k: self._value_repr(v) for k, v in value.items()}
        elif isinstance(value, (tuple, list, set)):
            return [self._value_repr(v) for v in value]
        else:
            return repr(value)

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
    def _remove_excluded_fields(self, message, extra_fields):
        for fields in (message, extra_fields):
            for field_name in list(fields):
                if field_name in constants.FORMATTER_RECORD_FIELD_SKIP_LIST:
                    del fields[field_name]

    # ----------------------------------------------------------------------
    def _move_extra_record_fields_to_prefix(self, message):
        """
        Anything added by the "extra" keyword in the logging call will be moved into the
        configured "extra" prefix. This way the event in Logstash will be clean and any extras
        will be paired together in the configured extra prefix.
        If not extra prefix is configured, the message will be kept as is.
        """
        if not self._extra_prefix:
            return  # early out if no prefix is configured

        field_skip_list = constants.FORMATTER_LOGSTASH_MESSAGE_FIELD_LIST + [self._extra_prefix]
        for key in list(message):
            if key not in field_skip_list:
                message[self._extra_prefix][key] = message.pop(key)

    # ----------------------------------------------------------------------
    def _serialize(self, message):
        return json.dumps(message, ensure_ascii=self._ensure_ascii)


class DjangoLogstashFormatter(LogstashFormatter):

    # ----------------------------------------------------------------------
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._django_version = None
        self._fetch_django_version()

    # ----------------------------------------------------------------------
    def _fetch_django_version(self):
        from django import get_version  # pylint: disable=import-error,import-outside-toplevel
        self._django_version = get_version()

    # ----------------------------------------------------------------------
    def _get_extra_fields(self, record):
        extra_fields = super()._get_extra_fields(record)

        if hasattr(record, 'status_code'):
            extra_fields['status_code'] = record.status_code

        # Django's runserver command passes socketobject and WSGIRequest instances as "request".
        # Hence the check for the META attribute.
        # For details see https://code.djangoproject.com/ticket/27234
        if hasattr(record, 'request') and hasattr(record.request, 'META'):
            request = record.request

            request_user = self._get_attribute_with_default(request, 'user', '')
            extra_fields['django_version'] = self._django_version
            extra_fields['req_useragent'] = request.META.get('HTTP_USER_AGENT', '<none>')
            extra_fields['req_remote_address'] = request.META.get('REMOTE_ADDR', '<none>')
            extra_fields['req_host'] = self._try_to_get_host_from_remote(request)
            extra_fields['req_uri'] = self._try_to_get_full_request_uri(request)
            extra_fields['req_user'] = str(request_user)
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

    # ----------------------------------------------------------------------
    def _get_attribute_with_default(self, obj, attr_name, default=None):
        """
        Query an attribute from an object but check before if it exists or return
        a default value if it is missing
        """
        if hasattr(obj, attr_name):
            value = getattr(obj, attr_name)
            if value is not None:
                return value
        # fallback
        return default

    # ----------------------------------------------------------------------
    def _try_to_get_host_from_remote(self, request):
        try:
            return request.get_host()
        except Exception:
            if 'HTTP_HOST' in request.META:
                return request.META['HTTP_HOST']
            else:
                return request.META['SERVER_NAME']

    # ----------------------------------------------------------------------
    def _try_to_get_full_request_uri(self, request):
        try:
            return request.build_absolute_uri()
        except Exception:
            # build_absolute_uri() may fail with DisallowedHost errors and maybe more
            return None


class FlaskLogstashFormatter(LogstashFormatter):

    # ----------------------------------------------------------------------
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._django_version = None
        self._fetch_flask_version()

    # ----------------------------------------------------------------------
    def _fetch_flask_version(self):
        from flask import __version__  # pylint: disable=import-error,import-outside-toplevel
        self._flask_version = __version__

    # ----------------------------------------------------------------------
    def _get_extra_fields(self, record):
        from flask import request  # pylint: disable=import-error,import-outside-toplevel

        extra_fields = super()._get_extra_fields(record)

        extra_fields['flask_version'] = self._flask_version
        if request:  # request might be unbound in other threads
            extra_fields['req_useragent'] = str(request.user_agent) if request.user_agent else ''
            extra_fields['req_remote_address'] = request.remote_addr
            extra_fields['req_host'] = request.host.split(':', 1)[0]
            extra_fields['req_uri'] = request.url
            extra_fields['req_method'] = request.method
            extra_fields['req_referer'] = request.referrer
            if 'X-Request-ID' in request.headers:
                extra_fields['request_id'] = request.headers.get('X-Request-ID')
            if request.remote_user:
                extra_fields['req_user'] = request.remote_user

            forwarded_proto = request.headers.get('X-Forwarded-Proto', None)
            if forwarded_proto is not None:
                extra_fields['req_forwarded_proto'] = forwarded_proto

            forwarded_for = request.headers.get('X-Forwarded-For', None)
            if forwarded_for is not None:
                # make it a list
                forwarded_for_list = forwarded_for.replace(' ', '').split(',')
                extra_fields['req_forwarded_for'] = forwarded_for_list

        # check if we have a status code somewhere
        if hasattr(record, 'status_code'):
            extra_fields['status_code'] = record.status_code
        if hasattr(record, 'response'):
            extra_fields['status_code'] = record.response.status_code

        return extra_fields
