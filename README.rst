=====================
python-logstash-async
=====================

.. image:: https://img.shields.io/pypi/v/python-logstash-async.svg
    :target: https://pypi.org/project/python-logstash-async/
    :alt: PyPI

.. image:: https://readthedocs.org/projects/python-logstash-async/badge/?version=latest
    :target: https://python-logstash-async.readthedocs.io/en/latest/
    :alt: Documentation Status

.. image:: https://travis-ci.org/eht16/python-logstash-async.svg?branch=master
    :target: https://travis-ci.org/eht16/python-logstash-async
    :alt: Travis CI

.. image:: https://img.shields.io/pypi/pyversions/python-logstash-async.svg
    :target: https://pypi.org/project/python-logstash-async/
    :alt: Python Versions

.. image:: https://img.shields.io/pypi/l/python-logstash-async.svg
    :target: https://pypi.org/project/python-logstash-async/
    :alt: License

Python Logstash Async is an asynchronous Python logging handler to submit
log events to a remote Logstash instance.

Unlike most other Python Logstash logging handlers, this package works asynchronously
by collecting log events from Python's logging subsystem and then transmitting the
collected events in a separate worker thread to Logstash.
This way, the main application (or thread) where the log event occurred, doesn't need to
wait until the submission to the remote Logstash instance succeeded.

This is especially useful for applications like websites or web services or any kind of
request serving API where response times matter.

For more details, configuration options and usage examples please see the
documentation at http://python-logstash-async.readthedocs.io/en/latest/.


Installation
------------

The easiest method is to install directly from pypi using pip::

    pip install python-logstash-async


If you prefer, you can download python-logstash-async and install it
directly from source::

    python setup.py install


Get the Source
--------------

The source code is available at https://github.com/eht16/python-logstash-async/.


Contributing
------------

Found a bug or got a feature request? Please report it at
https://github.com/eht16/python-logstash-async/issues.


Author
------

Enrico Tröger <enrico.troeger@uvena.de>
