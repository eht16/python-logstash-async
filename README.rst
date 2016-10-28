=====================
python-logstash-async
=====================

Python logging handler for asynchronous event processing and transport to Logstash.
http://logstash.net/


About
-----

This Python logging handler is a fork of
https://github.com/vklochan/python-logstash.

It adds the following features:

  * Asynchronous transport of log events
  * Store log events temporarily in a SQLite database until transport
    to the Logstash server has been successful
  * Transport of events via TCP and UDP, in the future hopefully via
    the Beats protocol
  * TCP transport optionally SSL-encrypted
  * Special formatter ready to be used in Django projects


Asynchronous processing
^^^^^^^^^^^^^^^^^^^^^^^

Unlike the original ``python-logstash``, this handler will try to
handle log events as fast as possible so that the sending program
code can continue with its primary job.
In other words, for web applications or web services it is important
to not slow down request times due to logging delays, e.g. waiting
for network timeouts to the Logstash server or similar.

So this handler will accept log events and pass them for further
processing to a separate worker thread which will try to send
the events to the configured Logstash server asynchronously.
If sending the events fails, the events are stored in a
local SQLite database for a later sending attempt.

Whenever the application stops, to be more exact whenever
Python' logging subsystem is shutdown, the worker thread
is signaled to send any queued events and clean up itself
before shutdown.

The sending intervals and timeouts can be configured in the
``logstash_async.constants`` module by the corresponding
module-level constants, see below for details.


Installation
------------

Using pip::

  pip install python-logstash-async

Usage
-----

`AsynchronousLogstashHandler` is a custom logging handler which
sends Logstash messages using UDP and TCP. For example:

.. code:: python

  import logging
  import sys
  from logstash_async.handler import AsynchronousLogstashHandler

  host = 'localhost'
  port = 5959

  test_logger = logging.getLogger('python-logstash-logger')
  test_logger.setLevel(logging.INFO)
  test_logger.addHandler(AsynchronousLogstashHandler(
      host, port, database_path='logstash.db')))
  # test_logger.addHandler(AsynchronousLogstashHandler(host, port))

  test_logger.error('python-logstash-async: test logstash error message.')
  test_logger.info('python-logstash-async: test logstash info message.')
  test_logger.warning('python-logstash-async: test logstash warning message.')

  # add extra field to logstash message
  extra = {
      'test_string': 'python version: ' + repr(sys.version_info),
      'test_boolean': True,
      'test_dict': {'a': 1, 'b': 'c'},
      'test_float': 1.23,
      'test_integer': 123,
      'test_list': [1, 2, '3'],
  }
  test_logger.info('python-logstash: test extra fields', extra=extra)

When using the ``extra`` field make sure you don't use reserved names.
From `Python documentation <https://docs.python.org/2/library/logging.html>`_::

    "The keys in the dictionary passed in extra should not clash
    with the keys used by the logging system.
    (See the `Formatter <https://docs.python.org/2/library/logging.html#logging.Formatter>`_ documentation
    for more information on which keys are used by the logging system.)"

You can also specify an additional extra dictionary in the logging configuration with static
values like the application name, environment, etc. These values will be merged with any
extra dictionary items passed in the logging call into the configured extra prefix.


Usage with Django
-----------------

Modify your ``settings.py`` to integrate ``python-logstash-async`` with Django's logging:

.. code:: python

  LOGGING = {
    ...
    'formatters': {
        ...
        'logstash': {
            '()': 'logstash_async.formatter.DjangoLogstashFormatter',
            'message_type': 'python-logstash',
            'fqdn': False, # Fully qualified domain name. Default value: false.
            'extra_prefix': 'dev', #
            'extra': {
                'application': PROJECT_APP,
                'project_path': PROJECT_APP_PATH,
                'environment': 'production'
            }
        },
    },
    'handlers': {
        ...
        'logstash': {
            'level': 'DEBUG',
            'class': 'logstash_async.handler.AsynchronousLogstashHandler',
            'transport': 'logstash_async.transport.TcpTransport',
            'host': 'logstash.host.tld',
            'port': 5959,
            'ssl_enable': True,
            'ssl_verify': True,
            'ca_certs': 'etc/ssl/certs/logstash_ca.crt',
            'certfile': '/etc/ssl/certs/logstash.crt',
            'keyfile': '/etc/ssl/private/logstash.key',
            'database_path': '{}/logstash.db'.format(PROJECT_ROOT),
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['logstash'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
    ...
  }

This would result in a Logstash event like the following
(note: to some extend dependent of your Logstash configuration):

.. code:: json

    {
        "@timestamp": "2016-10-23T15:11:16.853Z",
        "@version": "1",
        "extra": {
            "application": "django_example",
            "django_version": "1.10.2",
            "environment": "production",
            "func_name": "get_response",
            "interpreter": "/home/enrico/example/venv/bin/python",
            "interpreter_version": "2.7.12",
            "line": 152,
            "logger_name": "django.request",
            "path": "/home/enrico/example/venv/lib/python2.7/site-packages/django/core/handlers/base.py",
            "process_name": "MainProcess",
            "project_path": "/home/enrico/example/app",
            "req_host": "localhost",
            "req_method": "GET",
            "req_referer": "",
            "req_remote_address": "127.0.0.1",
            "req_uri": "http://localhost/hosts/nonexistent/",
            "req_user": "enrico",
            "req_useragent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
            "request": "<WSGIRequest: GET '/hosts/nonexistent/'>",
            "status_code": 404,
            "thread_name": "Thread-1"
        },
        "host": "my.host.tld",
        "level": "WARNING",
        "logsource": "endor.l8failed.net",
        "message": "Not Found: /hosts/nonexistent/",
        "pid": 23605,
        "port": 56170,
        "program": "manage.py",
        "type": "python-logstash"
    }


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
(see `Example Logstash Configuration`_ below).

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


Example Logstash Configuration
------------------------------

Example ``logstash.conf`` for unencrypted TCP transport::

    input {
        tcp {
            host => "127.0.0.1"
            port => 5959
            mode => server
            codec => json
        }
    }


Example ``logstash.conf`` for SSL-encrypted TCP transport::

    input {
        tcp {
            host => "127.0.0.1"
            port => 5958
            mode => server
            codec => json

            ssl_enable => true
            ssl_verify => true
            ssl_extra_chain_certs => ["/etc/ssl/certs/logstash_ca.crt"]
            ssl_cert => "/etc/ssl/certs/logstash.crt"
            ssl_key => "/etc/ssl/private/logstash.key"
        }
    }
