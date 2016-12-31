About
=====

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
local SQLite database for a later sending attempt.

Whenever the application stops, to be more exact whenever
Python' logging subsystem is shutdown, the worker thread
is signaled to send any queued events and clean up itself
before shutdown.

The sending intervals and timeouts can be configured in the
``logstash_async.constants`` module by the corresponding
module-level constants, see below for details.


License
-------

.. literalinclude:: ../LICENSE
    :language: none


ChangeLog
---------


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
