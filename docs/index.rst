.. python-logstash-async documentation master file

Python Logstash Async
=====================

Python Logstash Async is an asynchronous Python logging handler to submit
log events to a remote Logstash instance.

Unlike most other Python Logstash logging handlers, this package works asynchronously
by collecting log events from Python's logging subsystem and then transmitting the
collected events in a separate worker thread to Logstash.
This way, the main application (or thread) where the log event occurred, doesn't need to
wait until the submission to the remote Logstash instance succeeded.

This is especially useful for applications like websites or web services or any kind of
request serving API where response times matter.


Contents
--------

.. toctree::
   :maxdepth: 2

   about.rst
   installation.rst
   usage.rst
   config.rst
   config_logstash.rst
