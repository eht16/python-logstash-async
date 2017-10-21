Configuration
-------------

Options for configuring the log handler
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

host
    The host of the Logstash server (no default)

port
    The port of the Logstash server (no default)

database_path
    The path to the file containing queued events (no default)

transport
    Callable or path to a compatible transport class
    (default: 'logstash_async.transport.TcpTransport').

    You can specify your own transport class, e.g. to implement
    a transport via Redis or the Beats protocol.
    If you support pass a string, it should be a path to a
    class which can be imported.
    If you pass anything else, it should be an object of a class
    with a similar interface as `logstash_async.transport.TcpTransport`.
    Especially it should provide a `close()` and a `send()` method.

ssl_enable
    Should SSL be enabled for the connection? (default: False)
    Only used for `logstash_async.transport.TcpTransport`.

ssl_verify
    Should the server's SSL certificate be verified? (default: True)
    Only used for `logstash_async.transport.TcpTransport`.

keyfile
    The path to client side SSL key file (default: None)
    Only used for `logstash_async.transport.TcpTransport`.

certfile
    The path to client side SSL certificate file (default: None)
    Only used for `logstash_async.transport.TcpTransport`.

ca_certs
    The path to the file containing recognized CA certificates
    (default: None)
    Only used for `logstash_async.transport.TcpTransport`.

enable
    Flag to enable log processing (default is True, disabling
    might be handy for local testing, etc.)

event_ttl
    TTL for messages that are waiting to be published. (default: None)
    If a message is beyond it's TTL, it will be deleted from the cache
    and will not be published to logstash.


Options for configuring the log formatter
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following settings are only valid for the provided formatters
`logstash_async.handler.LogstashFormatter` and
`logstash_async.handler.DjangoLogstashFormatter`.

You can use any other formatter by configuring Python's logging
system accordingly. Any other formatter's `format()` method just
should return valid JSON suitable to be sent to Logstash
(see :ref:`logstash-config`).

Options:

message_type
    The `type` field in the message sent to Logstash
    (default: 'python-logstash')

tags
    Additional tags to include in the Logstash message (default: None)

fqdn
    Use the system's FQDN (fully qualified domain name) in the `host`
    field of the message sent to Logstash.
    `socket.getfqdn()` is used to retrieve the FQDN, otherwise
    `socket.gethostname()` is used for the default hostname.
    (default: False)

extra_prefix
    Name of the field in the resulting message sent to Logstash where
    all additional fields are grouped into. Consider it as some sort
    of namespace for all non-standard fields in the log event.
    This field will take any items passed in as extra fields via
    the `extra` configuration option (see below) as well as any extra
    items passed in the logging call.

    To disable grouping of the extra items and have them on the top
    level of the log event message, simply set this option to `None`
    or the empty string.
    (default: 'extra')

extra
    Dictionary with static items to be included in the message sent
    to Logstash. This dictionary will be merged with any other extra
    items passed in the logging call.
    (default: None)

ensure_ascii
    By default ('True') non-ASCII symbols in JSON are escaped with \uXXXX
    sequence. But on some specific settings of Elastic Stack
    those sequences won't be transformed back to UTF-8 representation.
    For those specific cases try to set parameter to 'False'.


.. _module-constants:

Options for the asynchronous processing and formatting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are a few constants which are meant to be static but still can be overridden
from the calling application by importing the ``constants`` variable from the
``logstash_async.constants`` which holds all constants as attributes
for easy modification.


constants.SOCKET_TIMEOUT
    Timeout in seconds for TCP connections (default: 5.0)

constants.QUEUE_CHECK_INTERVAL
    Interval in seconds to check the internal queue for new messages
    to be cached in the database (default: 2.0)

constants.QUEUED_EVENTS_FLUSH_INTERVAL
    Interval in seconds to send cached events from the database
    to Logstash (default 10.0)

constants.QUEUED_EVENTS_FLUSH_COUNT
    Count of cached events to send cached events from the database
    to Logstash; events are sent to Logstash whenever
    `QUEUED_EVENTS_FLUSH_COUNT` or `QUEUED_EVENTS_FLUSH_INTERVAL` is reached,
    whatever happens first (default 50)

constants.DATABASE_EVENT_CHUNK_SIZE
    Maximum number of events to be updated within one SQLite statement (default 750)

constants.FORMATTER_RECORD_FIELD_SKIP_LIST
    List of Python standard LogRecord attributes which are filtered out from the event sent
    to Logstash. Usually this list does not need to be modified. Add/Remove elements to
    exclude/include them in the Logstash event, for the full list see:
    http://docs.python.org/library/logging.html#logrecord-attributes

constants.FORMATTER_LOGSTASH_MESSAGE_FIELD_LIST
    Fields to be set on the top-level of a Logstash event/message, do not modify this
    unless you know what you are doing


Example usage:

.. code:: python

  from logstash_async.constants import constants

  constants.SOCKET_TIMEOUT = 10.0

  from logstash_async.handler import AsynchronousLogstashHandler
  ...
