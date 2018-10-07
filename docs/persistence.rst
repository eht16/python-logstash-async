Persistence
-----------

Local database
^^^^^^^^^^^^^^

The recommended way to cache log events between emitting and
transmission to the Logstash server is using a local SQLite
database. This way log events are cached even across process
restarts (and crashes). Especially on network problems or
a longer unavailbility of the Logstash server this might come in handy.

.. note::
    Using multiple instances of `AsynchronousLogstashHandler` with
    different `database_path` settings won't work because there is only one
    `LogProcessingWorker` instance and it is configured with the
    `database_path` setting from the first handler
    which emits a log event.


In-memory cache
^^^^^^^^^^^^^^^

To use an in-memory cache to persist log events between transmissions,
simple do not provide a `database_path` to `AsynchronousLogstashHandler`.

There are a couple of things you should keep in mind if you choose to go down this path.
Cached events will not be kept across process restarts when using the in-memory cache.
This means **it is possible to lose messages**.
If you cannot lose messages, then you should set the `database_path` option.

In addition, you can also set a TTL to live on all of the messages that should be published. Simply
pass :code:`event_ttl` to the initializer and your events will be aged off from the cache. The TTL
is in seconds.
