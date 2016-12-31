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

    The keys in the dictionary passed in extra should not clash
    with the keys used by the logging system.
    (See the `Formatter <https://docs.python.org/2/library/logging.html#logging.Formatter>`_ documentation
    for more information on which keys are used by the logging system.)

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

