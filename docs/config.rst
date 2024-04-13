Configuration
-------------

Options for configuring the log handler
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``host``

    The host of the Logstash server

    *Type*: ``string``

    *Default*: None


``port``

    The port of the Logstash server

    *Type*: ``integer``

    *Default*: None


``database_path``

    The path to the file containing queued events.
    To use an in-memory cache instead of a SQLite database,
    simply pass ``None``. See :doc:`persistence` for details.

    This setting is only relevant for `AsynchronousLogstashHandler`.

    .. note::
        Using multiple instances of `AsynchronousLogstashHandler` with
        different `database_path` settings won't work because there is only one
        `LogProcessingWorker` instance and it is configured with the
        `database_path` setting from the first handler
        which emits a log event.

    *Type*: ``string``

    *Default*: None


``transport``

    Callable or path to a compatible transport class.

    You can specify your own transport class, e.g. to implement
    a transport via Redis or the Beats protocol.
    If you pass a string, it should be a path to a
    class which can be imported.
    If you pass anything else, it should be a callable or an instance of a class
    with a similar interface as `logstash_async.transport.TcpTransport`.
    Especially it should provide a `close()` and a `send()` method.

    Currently available transports are::

      ``logstash_async.transport.TcpTransport``
      ``logstash_async.transport.UdpTransport``
      ``logstash_async.transport.BeatsTransport``
      ``logstash_async.transport.HttpTransport``

    *Type*: ``string``

    *Default*: ``logstash_async.transport.TcpTransport``


``ssl_enable``

    Should SSL be enabled for the connection?
    Only used for `logstash_async.transport.TcpTransport`,
    ``logstash_async.transport.BeatsTransport`` and
    ``logstash_async.transport.HttpTransport``.

    *Type*: ``boolean``

    *Default*: ``False``


``ssl_verify``

    Should the server's SSL certificate be verified?
    Only used for `logstash_async.transport.TcpTransport`,
    ``logstash_async.transport.BeatsTransport`` and
    ``logstash_async.transport.HttpTransport``.

    *Type*: ``boolean``

    *Default*: ``True``


``keyfile``

    The path to client side SSL key file.
    Only used for `logstash_async.transport.TcpTransport` and
    ``logstash_async.transport.BeatsTransport``.

    *Type*: ``string``

    *Default*: None


``certfile``

    The path to client side SSL certificate file.
    Only used for `logstash_async.transport.TcpTransport` and
    ``logstash_async.transport.BeatsTransport``.

    *Type*: ``string``

    *Default*: None


``ca_certs``

    The path to the file containing recognized CA certificates.
    Only used for `logstash_async.transport.TcpTransport` and
    ``logstash_async.transport.BeatsTransport``.

    *Type*: ``string``

    *Default*: None


``enable``

    Flag to enable log processing (disabling might be handy for
    local testing, etc.)

    *Type*: ``boolean``

    *Default*: True


``event_ttl``

    TTL for messages that are waiting to be published.
    If a message is beyond it's TTL, it will be deleted from the cache
    and will not be published to logstash.

    This setting is only relevant for `AsynchronousLogstashHandler`.

    *Type*: ``integer``

    *Default*: None



Options for configuring the log formatter
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following settings are only valid for the provided formatters:

- `logstash_async.handler.LogstashFormatter`
- `logstash_async.handler.LogstashEcsFormatter`
- `logstash_async.handler.DjangoLogstashFormatter`
- `logstash_async.handler.DjangoLogstashEcsFormatter`
- `logstash_async.handler.FlaskLogstashFormatter`
- `logstash_async.handler.FlaskLogstashEcsFormatter`

The included formatter classes with the "Ecs" infix generate
events to be stored using the Elastic Common Schema
(ECS, https://www.elastic.co/blog/introducing-the-elastic-common-schema)
and should be used if the target ElasticSearch index uses this schema.

You can use any other formatter by configuring Python's logging
system accordingly. Any other formatter's `format()` method just
should return valid JSON suitable to be sent to Logstash
(see :ref:`logstash-config`).

Options:

``message_type``

    The `type` field in the message sent to Logstash

    *Type*: ``string``

    *Default*: ``python-logstash``


``tags``

    Additional tags to include in the Logstash message

    *Type*: ``list``

    *Default*: None


``fqdn``

    Use the system's FQDN (fully qualified domain name) in the `host`
    field of the message sent to Logstash.
    `socket.getfqdn()` is used to retrieve the FQDN, otherwise
    `socket.gethostname()` is used for the default hostname.

    *Type*: ``boolean``

    *Default*: ``False``


``extra_prefix``

    Name of the field in the resulting message sent to Logstash where
    all additional fields are grouped into. Consider it as some sort
    of namespace for all non-standard fields in the log event.
    This field will take any items passed in as extra fields via
    the `extra` configuration option (see below) as well as any extra
    items passed in the logging call.

    To disable grouping of the extra items and have them on the top
    level of the log event message, simply set this option to `None`
    or the empty string.

    *Type*: ``string``

    *Default*: ``extra``


``extra``

    Dictionary with static items to be included in the message sent
    to Logstash. This dictionary will be merged with any other extra
    items passed in the logging call.

    *Type*: ``dict``

    *Default*: None


``metadata``

    Dictionary with static items to be included in the message sent
    to Logstash in the special `@metadata` field.
    See https://www.elastic.co/guide/en/logstash/current/event-dependent-configuration.html#metadata
    for documentation about the `@metadata` field and
    https://www.elastic.co/guide/en/beats/metricbeat/current/logstash-output.html
    for a common use.

    *Type*: ``dict``

    *Default*: None


``ensure_ascii``

    By default non-ASCII symbols in JSON are escaped with \uXXXX
    sequence. But on some specific settings of Elastic Stack
    those sequences won't be transformed back to UTF-8 representation.
    For those specific cases try to set parameter to 'False'.

    *Type*: ``boolean``

    *Default*: ``True``


.. _module-constants:

Options for the asynchronous processing and formatting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are a few constants which are meant to be static but still can be overridden
from the calling application by importing the ``constants`` variable from the
``logstash_async.constants`` which holds all constants as attributes
for easy modification.


``constants.SOCKET_TIMEOUT``

    Timeout in seconds for TCP connections

    *Type*: ``float``

    *Default*: ``5.0``


``constants.SOCKET_CLOSE_WAIT_TIMEOUT``

    Maximum time in seconds to wait for the socket's write buffer to get empty.
    Set to 0 to disable waiting for the socket write buffer to get empty.

    *Type*: ``float``

    *Default*: ``30.0``


``constants.QUEUE_CHECK_INTERVAL``

    Interval in seconds to check the internal queue for new messages
    to be cached in the database

    *Type*: ``float``

    *Default*: ``2.0``


``constants.QUEUED_EVENTS_FLUSH_INTERVAL``

    Interval in seconds to send cached events from the database
    to Logstash

    *Type*: ``float``

    *Default*: ``10.0``


``constants.QUEUED_EVENTS_FLUSH_COUNT``

    Count of cached events to send from the database
    to Logstash; events are sent to Logstash whenever
    `QUEUED_EVENTS_FLUSH_COUNT` or `QUEUED_EVENTS_FLUSH_INTERVAL` is reached,
    whatever happens first

    *Type*: ``integer``

    *Default*: ``50``


``constants.QUEUED_EVENTS_BATCH_SIZE``

    Maximum number of events to be sent to Logstash in one batch.
    Depending on the transport, this usually means a new connection to the Logstash
    is established for the event batch (this is true for the UDP, TCP and Beats transports).

    *Type*: ``integer``

    *Default*: ``50``


``constants.QUEUED_EVENTS_BEATS_BATCH_SIZE``

    Maximum number of events to be sent to Logstash in one batch when using the Beats transport,
    each batch of events is sent using the same connection and can be considered as a kind
    of transaction. Should be smaller than `QUEUED_EVENTS_BATCH_SIZE`.

    *Type*: ``integer``

    *Default*: ``25``


``constants.DATABASE_EVENT_CHUNK_SIZE``

    Maximum number of events to be updated within one SQLite statement

    *Type*: ``integer``

    *Default*: ``750``


``constants.DATABASE_TIMEOUT``

    Timeout in seconds to "connect" (i.e. open) the SQLite database

    *Type*: ``float``

    *Default*: ``5.0``


``constants.FORMATTER_RECORD_FIELD_SKIP_LIST``

    List of record attributes which are filtered out from the event sent
    to Logstash. By default, the list consists of some Python standard LogRecord attributes.
    Usually this list does not need to be modified. Add/Remove elements to
    exclude/include them in the Logstash event, for the full list see:
    http://docs.python.org/library/logging.html#logrecord-attributes

    *Type*: ``list``

    *Default*: <see source code>


``constants.FORMATTER_LOGSTASH_MESSAGE_FIELD_LIST``

    Fields to be set on the top-level of a Logstash event/message, do not modify this
    unless you know what you are doing

    *Type*: ``list``

    *Default*: <see source code>


``constants.FORMATTER_LOGSTASH_ECS_MESSAGE_FIELD_LIST``

    Fields to be set on the top-level of a Logstash event/message, do not modify this
    unless you know what you are doing. This list is used by "ECS" formatters
    (Elastic Common Schema).

    *Type*: ``list``

    *Default*: <see source code>


``constants.FORMATTER_LOGSTASH_ECS_NORMALIZE_MESSAGE``

    Whether to adapt dotted ECS fields into nested objects in the Logstash event structure.
    Logstash/ElasticSearch can process both variants however nested objects are encouraged
    to use.

    Example: `field.nested.key` becomes:

    .. code-block:: json

        "field": {
            "nested": {
                "key": "..."
            }
        }


    *Type*: ``boolean``

    *Default*: True


``constants.ERROR_LOG_RATE_LIMIT``

    Enable rate limiting for error messages (e.g. network errors) emitted by the logger
    used in LogProcessingWorker, i.e. when transmitting log messages to the Logstash server.
    In case the Logstash cannot be reached due to network issues
    (timeouts, connection refused, ...), this may lead to many repeated error log messages which
    can get annoying, especially if the application's logging system is configured to send emails
    or other notifications. For such errors emitted directly from the LogProcessingWorker class,
    rate limiting of identical errors for some time period can be configured to reduce logging
    of the same errors. In case rate limiting is in effect, the last message before dropping further
    messages will contain a hint telling that further messages of this kind will be dropped.
    To disable set this to `None`, to enable use a string like '5 per minute',
    for details see https://limits.readthedocs.io/en/stable/quickstart.html#rate-limit-string-notation.

    .. note::
        This rate limit affects only error log messages emitted directly in
        LogProcessingWorker, if you need a general rate limiting of all log messages,
        use a filter for the logging framework, e.g. https://github.com/wkeeling/ratelimitingfilter.

    *Type*: ``string``

    *Default*: None


``constants.DATABASE_VACUUM_ON_SHUTDOWN``

    Vacuum SQLite database on shutdown - when enabled, the database will be vacuumed on shutdown
    to reduce its size on disk.

    *Type*: ``boolean``

    *Default*: False


Example usage:

.. code-block:: python

  from logstash_async.constants import constants

  constants.SOCKET_TIMEOUT = 10.0

  from logstash_async.handler import AsynchronousLogstashHandler
  ...
