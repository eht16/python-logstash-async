# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.


class Constants:
    """
    Collection of various constants which are meant to static but still changeable
    from the calling application at startup if necessary.

    The class should not instantiated directly but used via the module level `constant` variable.
    """
    # timeout in seconds for TCP connections
    SOCKET_TIMEOUT = 5.0
    # interval in seconds to check the internal queue for new messages to be cached in the database
    QUEUE_CHECK_INTERVAL = 2.0
    # interval in seconds to send cached events from the database to Logstash
    QUEUED_EVENTS_FLUSH_INTERVAL = 10.0
    # count of cached events to send cached events from the database to Logstash; events are sent
    # to Logstash whenever QUEUED_EVENTS_FLUSH_COUNT or QUEUED_EVENTS_FLUSH_INTERVAL is reached,
    # whatever happens first
    QUEUED_EVENTS_FLUSH_COUNT = 50
    # maximum number of events to be sent to Logstash in one batch (i.e. using a single connection)
    QUEUED_EVENTS_BATCH_SIZE = 50
    # maximum number of events to be updated within one SQLite statement
    DATABASE_EVENT_CHUNK_SIZE = 750
    # timeout in seconds to "connect" (i.e. open) the SQLite database
    DATABASE_TIMEOUT = 5.0
    # list of record attributes which are filtered out from the event sent
    # to Logstash. By default, the list consists of some Python standard LogRecord attributes.
    # Usually this list does not need to be modified. Add/Remove elements to
    # exclude/include them in the Logstash event, for the full list see:
    # http://docs.python.org/library/logging.html#logrecord-attributes
    FORMATTER_RECORD_FIELD_SKIP_LIST = [
        'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
        'funcName', 'id', 'levelname', 'levelno', 'lineno', 'module',
        'msecs', 'msg', 'name', 'pathname', 'process',
        'processName', 'relativeCreated', 'stack_info', 'thread', 'threadName']
    # fields to be set on the top-level of a Logstash event/message, do not modify this
    # unless you know what you are doing
    FORMATTER_LOGSTASH_MESSAGE_FIELD_LIST = [
        '@timestamp', '@version', 'host', 'level', 'logsource', 'message',
        'pid', 'program', 'type', 'tags', '@metadata']
    # enable rate limiting for error messages (e.g. network errors) emitted by the logger
    # used in LogProcessingWorker, i.e. when transmitting log messages to the Logstash server.
    # Use a string like '5 per minute' or None to disable (default), for details see
    # http://limits.readthedocs.io/en/stable/string-notation.html
    ERROR_LOG_RATE_LIMIT = None


constants = Constants()  # pylint: disable=invalid-name
