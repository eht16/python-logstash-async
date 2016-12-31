Configuration
-------------

Options for configuring the log handler
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

host
    The host of the Logstash server (no default)

port
    The port of the Logstash server (default 5959)

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

database_path
    The path to the file containing queued events (default: ':memory:')

enable
    Flag to enable log processing (default is True, disabling
    might be handy for local testing, etc.)


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


Options for the asynchronous processing (in module logstash_async.constants)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

SOCKET_TIMEOUT
    Timeout in seconds for TCP connections (default: 5.0)

QUEUE_CHECK_INTERVAL
    Interval in seconds to check the internal queue for new messages
    to be cached in the database (default: 2.0)

QUEUED_EVENTS_FLUSH_INTERVAL
    Interval in seconds to send cached events from the database
    to Logstash (default 10.0)

QUEUED_EVENTS_FLUSH_COUNT
    Count of cached events to send cached events from the database
    to Logstash; events are sent to Logstash whenever
    `QUEUED_EVENTS_FLUSH_COUNT` or `QUEUED_EVENTS_FLUSH_INTERVAL` is reached,
    whatever happens first (default 50)
