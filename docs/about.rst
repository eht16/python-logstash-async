About
=====

This Python logging handler is a fork of
https://github.com/vklochan/python-logstash.

It adds the following features:

  * Asynchronous transport of log events
  * Store log events temporarily in a cache until transport
    to the Logstash server has been successful
  * Transport of events via TCP, UDP and the Beats protocol
  * TCP transport optionally SSL-encrypted
  * Special formatter ready to be used in Django projects
  * Special formatter ready to be used in Flask projects
  * Support for Elastic Common Schema (ECS,
    https://www.elastic.co/blog/introducing-the-elastic-common-schema)


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


Differences to using FileBeat
-----------------------------

While `FileBeat <https://www.elastic.co/de/products/beats/filebeat>`_
provides similar features like ``python-logstash-async``, there are
also a few differences which make this package worth using:

  - FileBeat needs to be installed and configured on the server
    independently from the application - this is an advantage and
    disadvantage - depending on the environment and deployment
    strategy.

    Deploying FileBeat server-side can be useful if multiple
    applications are hosted on a server and one FileBeat instance can
    handle the log files of all those applications.

    However, in a Docker / Kubernetes / whatever container world,
    one likely rather have an application as the single process running
    in the container and one does not want to have sidecar containers or
    so just to send the log events to Logstash.

  - FileBeat process log files, i.e. one need to write the log messages
    to a log file using a certain format and then have FileBeat or
    Logstash parse this format again to get a structured log event
    again - ``python-logstash-async`` sends a structured log event
    already to Logstash, no need for additional parsing and gives
    much more flexibility to add custom data to the the events without
    struggling with a logfile format.

  - When exceptions with stack traces included or other multi line
    messages are to be logged, FileBeat or Logstash needs to be
    configured carefully to properly detect and handle multiline log
    messages - with ``python-logstash-async`` no special handling of
    multiline log events is necessary as it cleanly integrates
    with Python's logging framework.

After all, both approaches are valid and have their own use cases.
Which fits best depends on the application and its requirements.


License
-------

.. literalinclude:: ../LICENSE
    :language: none


ChangeLog
---------

4.0.2 (Mar 16 2025)
+++++++++++++++++++

  * Fix hang on socket errors by not using the logging system
  * Do not try to "shutdown" UDP sockets (#107,  #108).


4.0.1 (Jan 27 2025)
+++++++++++++++++++

  * Properly require Python >= 3.11.
    The previous release had a wrong requirement set unfortunately.


4.0.0 (Jan 26 2025)
+++++++++++++++++++

  * Breaking change: drop support for 3.8, 3.9 and 3.10.
  * Catch errors on TCP/UDP socket closing to prevent requeuing of events
    (#98, #100).
  * Add new setting to configure batch sizes for Beats transport (#93).
  * Support URL path in HttpTransport (#103, Seyyed Mohammad Borghei).
  * LogstashFormatter: Move top_level_field_set creation to __init__
    to ease setting FORMATTER_LOGSTASH_MESSAGE_FIELD_LIST after
    importing the formatter class (#96, #97, feliixx).


3.0.0 (Feb 12 2024)
+++++++++++++++++++

  * Add ECS (Elastic Common Schema) formatter support (#91, Andrii Lahuta).
  * On closing UDP/TCP socket, make sure it is reset (#89, #92).
  * Ensure to not check for socket write buffer if disabled.


2.7.2 (Sep 14 2023)
+++++++++++++++++++

  * Implement get_non_flushed_event_count() for MemoryCache (#88).


2.7.1 (Sep 10 2023)
+++++++++++++++++++

  * Wait for empty socket write buffer only if "fnctl" is available (#82).
  * Wait at most 30s for empty socket write buffer (#83).
  * Read pending events from database on startup for immediate flushing (#85).


2.7.0 (Aug 20 2023)
+++++++++++++++++++

  * Add a wait until all data is sent, before closing socket on TCP
    transport (#81, Alisher Nazarkhanov).
  * Explicitly shutdown the socket connection in Udp/TcpTransport to
    prevent peer connection errors.
  * Implement optional database VACUUM on shutdown (#80).


2.6.0 (Jul 30 2023)
+++++++++++++++++++

  * Load certificate chain only if a certificate was specified (#79).
  * Handle network errors raised by "requests" in HttpTransport (#75).


2.5.0 (Apr 16 2022)
+++++++++++++++++++

  * Handle database disk errors (#72, Peter Mazarovich).
  * Use Python's PriorityQueue to reduce memory consumption
    (#73, Peter Mazarovich).


2.4.0 (Apr 04 2022)
+++++++++++++++++++

  * Update link to docs for rate limit string notation
    (#70, Garrett Hyde).
  * Log connection and network errors as warnings (#71).
  * Fix support for Django 4.0 by using Request.build_absolute_uri().
  * Use datetime as column type for "entry_date" in database.


2.3.0 (May 23 2021)
+++++++++++++++++++

  * Consider `set` also as sequence type when formatting events.
  * Improve formatter performance by converting simple types first
    (#64, Johann Schmitz).
  * Migrate from ssl.wrap_socket() to SSLContext.wrap_socket().


2.2.0 (Dec 05 2020)
+++++++++++++++++++

  * Add SynchronousLogstashHandler: operates like the
    AsynchronousLogstashHandler but synchronously and without any
    event queueing and retrying (#59, #60, Sascha Pfeiffer).


2.1.1 (Nov 04 2020)
+++++++++++++++++++

  * Fix missing message field in events (#58).


2.1.0 (Nov 02 2020)
+++++++++++++++++++

  * Remove "six" dependency.
  * Add "HTTP Input" transport (#56, Jürgen Löhel).
  * Skip logging stacktraces for common network errors
    (#55, #56, Walter Macomber).
  * Extend FORMATTER_RECORD_FIELD_SKIP_LIST to filter
    all record fields (#52).
  * Docs: Fix error in logging.config.fileConfig code example
    (#54, Guy).


2.0.0 (Aug 16 2020)
+++++++++++++++++++

  * Require Python >= 3.5.


1.6.7 (Aug 16 2020)
+++++++++++++++++++

  * Set `python_requires` to Python >=2.7 or Python >= 3.5 for
    smooth upgrade to upcoming Python3 only.
    This way Python2 only users will stay at this release.


1.6.6 (Jun 08 2020)
+++++++++++++++++++

  * Fix socket timeout setting ignored for filebeat
    (#50, Koert van der Veer).


1.6.5 (Jun 06 2020)
+++++++++++++++++++

  * Add "@metadata" to the generated event in Formatter, useful for
    common beats input configuration in Logstash
    (#49, Sudheer Satyanarayana).
  * Don't convert text to bytes in Formatter
    (fix #45) (#46, Sergey Trofimov).


1.6.4 (Jan 23 2020)
+++++++++++++++++++

  * Fix accessing request's META attribute in DjangoLogstashFormatter


1.6.3 (Jan 23 2020)
+++++++++++++++++++

  * Handle DisallowedHost exceptions in DjangoLogstashFormatter
    to not trigger an exception while formatting.


1.6.2 (Nov 30 2019)
+++++++++++++++++++

  * When sending all events, stop on errors.
    Otherwise retrying happens forever on non-recoverable errors.


1.6.1 (Nov 25 2019)
+++++++++++++++++++

  * Flush all pending events on shutdown


1.6.0 (Nov 12 2019)
+++++++++++++++++++

  * Docs: Explain the differences to FileBeat (#44)
  * Close TCP socket on connect timeouts
  * Add Flask formatter


1.5.1 (Jul 03 2019)
+++++++++++++++++++

  * Fix broken transport instantiation if callable is used (#42)
  * Fix tcp input codec in documentation


1.5.0 (Jan 05 2019)
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
