# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from datetime import date, datetime
import importlib.metadata
import logging
import socket
import sys
import time
import traceback
import uuid

from logstash_async.constants import constants
from logstash_async.utils import normalize_ecs_dict
import logstash_async


try:
    import json
except ImportError:
    import simplejson as json


class LogstashFormatter(logging.Formatter):

    _basic_data_types = (type(None), bool, str, int, float)

    field_skip_set = set(constants.FORMATTER_RECORD_FIELD_SKIP_LIST)
    top_level_field_set = set(constants.FORMATTER_LOGSTASH_MESSAGE_FIELD_LIST)

    class MessageSchema:
        TIMESTAMP = '@timestamp'
        VERSION = '@version'
        METADATA = '@metadata'
        HOST = 'host'
        LOG_LEVEL = 'level'
        LOG_SOURCE = 'logsource'
        LOGGER_NAME = 'logger_name'
        LINE = 'line'
        MESSAGE = 'message'
        MESSAGE_TYPE = 'type'
        FUNC_NAME = 'func_name'
        TASK_NAME = 'task_name'
        THREAD_NAME = 'thread_name'
        PROCESS_NAME = 'process_name'
        INTERPRETER = 'interpreter'
        INTERPRETER_VERSION = 'interpreter_version'
        PATH = 'path'
        PID = 'pid'
        PROGRAM = 'program'
        STACK_TRACE = 'stack_trace'
        ERROR_TYPE = 'error_type'
        TAGS = 'tags'
        LOGSTASH_ASYNC_VERSION = 'logstash_async_version'

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
        message = self._format_to_dict(record)
        return self._serialize(message)

    # ----------------------------------------------------------------------
    def _format_to_dict(self, record):
        message = self._get_primary_fields(record)
        # record fields
        record_fields = self._get_record_fields(record)
        message.update(record_fields)
        # prepare dynamic extra fields
        extra_fields = self._get_extra_fields(record)
        message.update(extra_fields)

        # remove all fields to be excluded
        self._remove_excluded_fields(message)
        # move existing extra record fields into the configured prefix
        self._move_extra_record_fields_to_prefix(message)

        return message

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
    def _get_primary_fields(self, record):
        Schema = self.MessageSchema
        primary_fields = {
            Schema.TIMESTAMP: self._format_timestamp(record.created),
            Schema.VERSION: '1',
            Schema.HOST: self._host,
            Schema.LOG_LEVEL: record.levelname,
            Schema.LOG_SOURCE: self._logsource,
            Schema.MESSAGE: record.getMessage(),
            Schema.PID: record.process,
            Schema.PROGRAM: self._program_name,
            Schema.MESSAGE_TYPE: self._message_type,
        }
        if self._metadata:
            primary_fields[Schema.METADATA] = self._metadata
        if self._tags:
            primary_fields[Schema.TAGS] = self._tags
        return primary_fields

    # ----------------------------------------------------------------------
    def _get_extra_fields(self, record):
        Schema = self.MessageSchema
        extra_fields = {
            Schema.FUNC_NAME: record.funcName,
            Schema.INTERPRETER: self._interpreter,
            Schema.INTERPRETER_VERSION: self._interpreter_version,
            Schema.LINE: record.lineno,
            Schema.LOGGER_NAME: record.name,
            Schema.LOGSTASH_ASYNC_VERSION: logstash_async.__version__,
            Schema.PATH: record.pathname,
            Schema.PROCESS_NAME: record.processName,
            Schema.THREAD_NAME: record.threadName,
        }
        # static extra fields
        if self._extra:
            extra_fields.update(self._extra)
        if getattr(record, 'taskName', None):
            extra_fields[Schema.TASK_NAME] = record.taskName
        # exceptions
        if record.exc_info:
            extra_fields[Schema.ERROR_TYPE] = record.exc_info[0].__name__
            extra_fields[Schema.STACK_TRACE] = self._format_exception(record.exc_info)
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
    def _remove_excluded_fields(self, message):
        for field_name in list(message):
            if field_name in self.field_skip_set:
                del message[field_name]

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

        message.setdefault(self._extra_prefix, {})
        field_skip_set = self.top_level_field_set | {self._extra_prefix}
        for key in list(message):
            if key not in field_skip_set:
                message[self._extra_prefix][key] = message.pop(key)

    # ----------------------------------------------------------------------
    def _serialize(self, message):
        return json.dumps(message, ensure_ascii=self._ensure_ascii)


class LogstashEcsFormatter(LogstashFormatter):
    ecs_version = '8.11.0'
    __schema_dict = {
        'ECS_VERSION': 'ecs.version',
        'MESSAGE_TYPE': 'event.module',
        'HOST': 'host.hostname',
        'LOG_LEVEL': 'log.level',
        'LOGGER_NAME': 'log.logger',
        'LOG_SOURCE': 'log.syslog.hostname',
        'LINE': 'log.origin.file.line',
        'PATH': 'log.origin.file.name',
        'FUNC_NAME': 'log.origin.function',
        'STACK_TRACE': 'error.stack_trace',
        'ERROR_TYPE': 'error.type',
        'PROGRAM': 'process.executable',
        'PROCESS_NAME': 'process.name',
        'PID': 'process.pid',
        'THREAD_NAME': 'process.thread.name',
    }

    normalize_ecs_message = constants.FORMATTER_LOGSTASH_ECS_NORMALIZE_MESSAGE
    top_level_field_set = {*constants.FORMATTER_LOGSTASH_ECS_MESSAGE_FIELD_LIST,
                           *__schema_dict.values()}
    MessageSchema = type('MessageSchema', (LogstashFormatter.MessageSchema,), __schema_dict)

    def _get_primary_fields(self, record):
        message = super()._get_primary_fields(record)
        Schema = self.MessageSchema
        message[Schema.ECS_VERSION] = self.ecs_version
        return message

    def _format_to_dict(self, record):
        message = super()._format_to_dict(record)
        if self.normalize_ecs_message:
            # pylint: disable-next=redefined-variable-type
            message = normalize_ecs_dict(message)
        return message


class DjangoLogstashFormatter(LogstashFormatter):
    class MessageSchema(LogstashFormatter.MessageSchema):
        DJANGO_VERSION = 'django_version'
        RESP_STATUS_CODE = 'status_code'
        REQ_USER_AGENT = 'req_useragent'
        REQ_REMOTE_ADDRESS = 'req_remote_address'
        REQ_HOST = 'req_host'
        REQ_URI = 'req_uri'
        REQ_USER = 'req_user'
        REQ_METHOD = 'req_method'
        REQ_REFERER = 'req_referer'
        REQ_FORWARDED_PROTO = 'req_forwarded_proto'
        REQ_FORWARDED_FOR = 'req_forwarded_for'
        TMPL_NAME = 'tmpl_name'
        TMPL_LINE = 'tmpl_line'
        TMPL_MESSAGE = 'tmpl_message'
        TMPL_DURING = 'tmpl_during'

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
        Schema = self.MessageSchema

        if hasattr(record, 'status_code'):
            extra_fields[Schema.RESP_STATUS_CODE] = record.status_code

        # Django's runserver command passes socketobject and WSGIRequest instances as "request".
        # Hence the check for the META attribute.
        # For details see https://code.djangoproject.com/ticket/27234
        if hasattr(record, 'request') and hasattr(record.request, 'META'):
            request = record.request

            request_user = self._get_attribute_with_default(request, 'user', '')
            extra_fields[Schema.DJANGO_VERSION] = self._django_version
            extra_fields[Schema.REQ_USER_AGENT] = request.META.get('HTTP_USER_AGENT', '<none>')
            extra_fields[Schema.REQ_REMOTE_ADDRESS] = request.META.get('REMOTE_ADDR', '<none>')
            extra_fields[Schema.REQ_HOST] = self._try_to_get_host_from_remote(request)
            extra_fields[Schema.REQ_URI] = self._try_to_get_full_request_uri(request)
            extra_fields[Schema.REQ_USER] = str(request_user)
            extra_fields[Schema.REQ_METHOD] = request.META.get('REQUEST_METHOD', '')
            extra_fields[Schema.REQ_REFERER] = request.META.get('HTTP_REFERER', '')

            forwarded_proto = request.META.get('HTTP_X_FORWARDED_PROTO', None)
            if forwarded_proto is not None:
                extra_fields[Schema.REQ_FORWARDED_PROTO] = forwarded_proto

            forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', None)
            if forwarded_for is not None:
                # make it a list
                forwarded_for_list = forwarded_for.replace(' ', '').split(',')
                extra_fields[Schema.REQ_FORWARDED_FOR] = forwarded_for_list

            # template debug
            if isinstance(record.exc_info, tuple):
                exc_value = record.exc_info[1]
                template_info = getattr(exc_value, 'template_debug', None)
                if template_info:
                    extra_fields[Schema.TMPL_NAME] = template_info['name']
                    extra_fields[Schema.TMPL_LINE] = template_info['line']
                    extra_fields[Schema.TMPL_MESSAGE] = template_info['message']
                    extra_fields[Schema.TMPL_DURING] = template_info['during']

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


class DjangoLogstashEcsFormatter(DjangoLogstashFormatter, LogstashEcsFormatter):
    __schema_dict = {
        'RESP_STATUS_CODE': 'http.response.status_code',
        'REQ_USER_AGENT': 'user_agent.original',
        'REQ_REMOTE_ADDRESS': 'client.ip',
        'REQ_HOST': 'client.domain',
        'REQ_URI': 'url.original',
        'REQ_USER': 'user.name',
        'REQ_METHOD': 'http.request.method',
        'REQ_REFERER': 'http.request.referrer',
    }

    top_level_field_set = LogstashEcsFormatter.top_level_field_set | set(__schema_dict.values())
    MessageSchema = type(
        'MessageSchema',
        (DjangoLogstashFormatter.MessageSchema, LogstashEcsFormatter.MessageSchema),
        __schema_dict,
    )

    def _remove_excluded_fields(self, message):
        message.pop('status_code', None)
        super()._remove_excluded_fields(message)


class FlaskLogstashFormatter(LogstashFormatter):
    class MessageSchema(LogstashFormatter.MessageSchema):
        FLASK_VERSION = 'flask_version'
        RESP_STATUS_CODE = 'status_code'
        REQ_USER_AGENT = 'req_useragent'
        REQ_REMOTE_ADDRESS = 'req_remote_address'
        REQ_HOST = 'req_host'
        REQ_URI = 'req_uri'
        REQ_USER = 'req_user'
        REQ_METHOD = 'req_method'
        REQ_REFERER = 'req_referer'
        REQ_ID = 'request_id'
        REQ_FORWARDED_PROTO = 'req_forwarded_proto'
        REQ_FORWARDED_FOR = 'req_forwarded_for'

    # ----------------------------------------------------------------------
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._flask_version = None
        self._fetch_flask_version()

    # ----------------------------------------------------------------------
    def _fetch_flask_version(self):
        self._flask_version = importlib.metadata.version('flask')

    # ----------------------------------------------------------------------
    def _get_extra_fields(self, record):
        # pylint: disable-next=import-error,import-outside-toplevel
        from flask import request

        extra_fields = super()._get_extra_fields(record)
        Schema = self.MessageSchema

        extra_fields[Schema.FLASK_VERSION] = self._flask_version
        if request:  # request might be unbound in other threads
            extra_fields[Schema.REQ_USER_AGENT] = (str(request.user_agent)
                                                   if request.user_agent else '')
            extra_fields[Schema.REQ_REMOTE_ADDRESS] = request.remote_addr
            extra_fields[Schema.REQ_HOST] = request.host.split(':', 1)[0]
            extra_fields[Schema.REQ_URI] = request.url
            extra_fields[Schema.REQ_METHOD] = request.method
            extra_fields[Schema.REQ_REFERER] = request.referrer
            if 'X-Request-ID' in request.headers:
                extra_fields[Schema.REQ_ID] = request.headers.get('X-Request-ID')
            if request.remote_user:
                extra_fields[Schema.REQ_USER] = request.remote_user

            forwarded_proto = request.headers.get('X-Forwarded-Proto', None)
            if forwarded_proto is not None:
                extra_fields[Schema.REQ_FORWARDED_PROTO] = forwarded_proto

            forwarded_for = request.headers.get('X-Forwarded-For', None)
            if forwarded_for is not None:
                # make it a list
                forwarded_for_list = forwarded_for.replace(' ', '').split(',')
                extra_fields[Schema.REQ_FORWARDED_FOR] = forwarded_for_list

        # check if we have a status code somewhere
        if hasattr(record, 'status_code'):
            extra_fields[Schema.RESP_STATUS_CODE] = record.status_code
        if hasattr(record, 'response'):
            extra_fields[Schema.RESP_STATUS_CODE] = record.response.status_code

        return extra_fields


class FlaskLogstashEcsFormatter(FlaskLogstashFormatter, LogstashEcsFormatter):
    __schema_dict = {
        'RESP_STATUS_CODE': 'http.response.status_code',
        'REQ_USER_AGENT': 'user_agent.original',
        'REQ_REMOTE_ADDRESS': 'client.ip',
        'REQ_HOST': 'client.domain',
        'REQ_URI': 'url.original',
        'REQ_USER': 'user.name',
        'REQ_METHOD': 'http.request.method',
        'REQ_REFERER': 'http.request.referrer',
        'REQ_ID': 'http.request.id',
    }

    top_level_field_set = LogstashEcsFormatter.top_level_field_set | set(__schema_dict.values())
    MessageSchema = type(
        'MessageSchema',
        (FlaskLogstashFormatter.MessageSchema, LogstashEcsFormatter.MessageSchema),
        __schema_dict,
    )

    def _remove_excluded_fields(self, message):
        message.pop('status_code', None)
        super()._remove_excluded_fields(message)
