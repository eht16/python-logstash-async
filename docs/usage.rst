Usage
-----

`AsynchronousLogstashHandler` is a custom logging handler which
sends Logstash messages using UDP and TCP.
Use `SynchronousLogstashHandler` for a synchronous alternative.

For example:

.. code-block:: python

  import logging
  import sys
  from logstash_async.handler import AsynchronousLogstashHandler

  host = 'localhost'
  port = 5959

  test_logger = logging.getLogger('python-logstash-logger')
  test_logger.setLevel(logging.INFO)
  test_logger.addHandler(AsynchronousLogstashHandler(
      host, port, database_path='logstash.db'))

  # If you don't want to write to a SQLite database, then you do
  # not have to specify a database_path.
  # NOTE: Without a database, messages are lost between process restarts.
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

    The keys in the dictionary passed in extra should not clash
    with the keys used by the logging system.
    (See the `Formatter <https://docs.python.org/2/library/logging.html#logging.Formatter>`_ documentation
    for more information on which keys are used by the logging system.)

You can also specify an additional extra dictionary in the logging configuration (e.g. via
FileConfig, DictConfig or logging configuration in the code)
with static values like the application name, environment, etc. These values will
be merged with any extra dictionary items passed in the logging call into the
configured extra prefix, e.g.:

.. code-block:: python

  from logstash_async.formatter import LogstashFormatter
  from logstash_async.handler import AsynchronousLogstashHandler

  ...
  logstash_formatter = LogstashFormatter(
      message_type='python-logstash',
      extra_prefix='dev',
      extra=dict(application='example-app', environment='production'))
  logstash_handler.setFormatter(logstash_formatter)
  test_logger.addHandler(logstash_handler)
  ...

Usage with HttpTransport
========================

The `AsynchronousLogstashHandler` and `SynchronousLogstashHandler` support also
the logstash `http input plugin <https://www.elastic.co/guide/en/logstash/current/plugins-inputs-http.html>`_.

.. code-block:: python

  import logging

  from logstash_async.transport import HttpTransport
  from logstash_async.handler import AsynchronousLogstashHandler

  host = 'localhost'
  port = 5959

  test_logger = logging.getLogger('python-logstash-logger')
  test_logger.setLevel(logging.INFO)

  transport = HttpTransport(
      host,
      port,
      timeout=5.0,
  )

  handler = AsynchronousLogstashHandler(
      host,
      port,
      transport=transport,
      database_path='logstash_test.db'
  )

  test_logger.addHandler(handler)
  test_logger.error('python-logstash-async: test logstash error message.')
  test_logger.info('python-logstash-async: test logstash info message.')
  test_logger.warning('python-logstash-async: test logstash warning message.')

If you are using a self-signed certificate, it's necessary to specify the CA bundled
certificate.

.. code-block:: python

  transport = HttpTransport(
      host,
      port,
      ssl_verify="/opt/ca/my_ca.crt"
      timeout=5.0,
  )

Furthermore it's possible to deactivate the certificate verification. This is
not recommended for production.

.. code-block:: python

  transport = HttpTransport(
      host,
      port,
      ssl_verify=False
      timeout=5.0,
  )

TLS is activated by default. If you are not using TLS, it is necessary to
deactivate it explicitly. This is not recommended for production.

.. code-block:: python

  transport = HttpTransport(
      host,
      port,
      ssl_enable=False
      timeout=5.0,
  )

It is also possible to use HTTP basic access authentication when necessary. The
username and the password should not be empty.

.. code-block:: python

  from get_docker_secret import get_docker_secret

  transport = HttpTransport(
      host,
      port,
      ssl_verify=False
      timeout=5.0,
      username="logstash",
      password=get_docker_secret('LOGSTASH_PASSWORD')
  )


Usage with Django
=================

Modify your ``settings.py`` to integrate ``python-logstash-async`` with Django's logging:

.. code-block:: python

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
            'formatter': 'logstash',
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

.. code-block:: json

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

Usage with Logging File Config
==============================

Example code for Python's `logging.config.fileConfig`:

.. code-block:: python

    import logging
    from logging.config import fileConfig

    fileConfig('logging.conf', disable_existing_loggers=True)
    logger = logging.getLogger()
    logger.info('python-logstash-async: test logstash info message.')


Example config for Python's `logging.config.fileConfig`:

.. code-block:: ini

    # loggers
    [loggers]
    keys = root

    [logger_root]
    name = python-app
    level = DEBUG
    handlers = console,logstash
    propagate = 1
    qualname = root

    # handlers
    [handlers]
    keys = console,logstash

    [handler_console]
    class = StreamHandler
    level = NOTSET
    formatter = console
    args = (sys.stdout,)

    [handler_logstash]
    class = logstash_async.handler.AsynchronousLogstashHandler
    level = DEBUG
    formatter = logstash
    args = ('%(host)s', %(port)s, '%(database_path)s', '%(transport)s', %(ssl_enable)s, %(ssl_verify)s, '%(keyfile)s', '%(certfile)s', '%(ca_certs)s', %(enable)s)
    transport = logstash_async.transport.TcpTransport
    host = localhost
    port = 5959
    enable = True
    ssl_enable = True
    ssl_verify = True
    ca_certs = /etc/ssl/certs/ca.crt
    certfile = /etc/ssl/certs/logstash.crt
    keyfile = /etc/ssl/private/logstash.key
    database_path = /var/lib/logstash.db

    [formatters]
    keys = console,logstash

    [formatter_console]
    format = %(asctime)s %(name)-12s %(levelname)+8s %(message)s

    [formatter_logstash]
    class = logstash_async.formatter.LogstashFormatter
    # format, datefmt and style are a hack: we cannot specify "args" for formatters
    # (see logging.config.py:111 _create_formatters()), so we pass our values as format parameters
    # "format" corresponds to LogstashFormatter's "message_type" argument,
    # "datefmt" to "tags" and "style" to "fqdn" ("style" is Python3 only).
    # However, the "tags" argument expects a list and "fqdn" expects a boolean but Python's
    # logging framework passes strings for both, so this is of limited use.
    format = format
    datefmt = custom-tag
    style = True


.. note::
    As also stated in the comment in the example configuration above, Python's
    `fileConfig` format does not allow to pass arbitary arguments to a formatter
    class in the config file in the same way as for handlers.
    It supports only three arguments: `format`, `datefmt` and `style`
    (where `style` is Python3 only) and passes those as positional arguments to
    the formatter class.

    You can either use the hack shown in the example by setting at least the
    `message_type` argument of `LogstashFormatter` which is its first position argument
    and so corresponds to `format` in the logging configuration.

    A better and more clean solution is to create a subclass of `LogstashFormatter` and
    set the various configuration values there or use a different formatter like
    https://github.com/madzak/python-json-logger.
    This is a limitation of Python's logging file config format.

Another example using Python logging file config in combination with Gunicorn
can be found on https://github.com/eht16/python-logstash-async/issues/20.


Trigger event flushing
----------------------

In case you need to trigger flushing queued events (as if it is
important for your application to try to send events as fast as
possible or similar), the `AsynchronousLogstashHandler` class
provides a method `flush` which will trigger flushing of queued
events in the asynchronous worker thread.

There is no guarantee that the flush will succeed but so you can
bypass the next `constants.QUEUED_EVENTS_FLUSH_INTERVAL` resp.
`constants.QUEUED_EVENTS_FLUSH_COUNT`
(see :ref:`module-constants` for details.).

In case sending the queued events to Logstash failed, the events
will be requeued as usual and the flush signal is reset. That is,
until the next attempt to send queued events,
`constants.QUEUED_EVENTS_FLUSH_INTERVAL` and
`constants.QUEUED_EVENTS_FLUSH_COUNT` will be taken into account
again.
