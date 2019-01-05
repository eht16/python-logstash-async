About
=====

This Python logging handler is a fork of
https://github.com/vklochan/python-logstash.

It adds the following features:

  * Asynchronous transport of log events
  * Store log events temporarily in a cache until transport
    to the Logstash server has been successful
  * Transport of events via TCP, UDP the Beats protocol
  * TCP transport optionally SSL-encrypted
  * Special formatter ready to be used in Django projects


Asynchronous processing
-----------------------

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
local cache for a later attempt sending the events.

Whenever the application stops, to be more exact whenever
Python' logging subsystem is shutdown, the worker thread
is signaled to send any queued events and clean up itself
before shutdown.

The interval and timeout settings used for transmitting
can be configured in the ``logstash_async.constants``
module.
See :ref:`module-constants` for details.


License
-------

.. literalinclude:: ../LICENSE
    :language: none


ChangeLog
---------

1.5.0 (Jan 05 2018)
+++++++++++++++++++

  * Add new constant QUEUED_EVENTS_BATCH_SIZE to limit events sent once
    (related to #31)
  * Add "Beats" transport (logstash-input-beats, related to #31)
  * Add "timeout" argument to transport classes for more flexible
    setting
  * Docs: better document the shared database between handlers (#30)
  * Perform tests also against Python 3.7
  * Docs: explain Formatter extra dict in more detail (#23)
  * Docs: minor improvements


1.4.1 (Jan 20 2018)
+++++++++++++++++++

  * Handle possible non-bytes result in Formatter (#18, rmihael)


1.4.0 (Nov 22 2017)
+++++++++++++++++++

  * Implement rate limiting of LogProcessingWorker error messages
  * Add a constant to configure the timeout for the Sqlite database


1.3.1 (Oct 30 2017)
+++++++++++++++++++

  * Call flush on worker thread only if it is running
    (prevent errors when application shuts down before
    anything was logged)
  * Rewrite utils.ichunked to not raise StopIteration
    (for future Python 3.7 compability)


1.3.0 (Oct 23 2017)
+++++++++++++++++++

  * Added in-memory cache back (#12, loganasherjones)
  * Added support for TTL of messages (loganasherjones)
  * Minor Python3 compability fixes
  * Implement AsynchronousLogstashHandler::flush method
    to manually flushed queued events (#15, Vladislav Pakhomov)
  * Ease modification of constants from the calling application (#14)
  * Add Formatter parameter 'ensure_ascii' to workaround potential
    encoding errors on some setups (#9, Sergei Lobastov)


1.2.0 (May 06, 2017)
++++++++++++++++++++

  * Require path setting to the Sqlite database
    (the previous default value ":memory:" doesn't help, see #5)
  * Fix a Python3 incompatibility (#3)
  * Fix a Django 1.8 / local Django development server
    incompatibility (#3)


1.1.1 (Apr 05, 2017)
++++++++++++++++++++

  * Improve handling on locked Sqlite database on high event load


1.1.0 (Dec 31, 2016)
++++++++++++++++++++

  * Add documentation (built by Sphinx, hosted at readthedocs.org)
  * Fix installing of "six" dependency on package install


1.0.1 (Nov 26, 2016)
++++++++++++++++++++

  * Fix "dictionary changed size during iteration" error (#2)


1.0.0 (Oct 29, 2016)
++++++++++++++++++++

  * Initial release
