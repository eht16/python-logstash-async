Persistence
-----------

By default, you do not need to provide a :code:`database_path` to the :code:`AsynchronousLogstashHandler`.
There are a couple of things you should keep in mind if you choose to go down this path.
With no database, the backend is a simple in-memory cache. Because it is in memory, your
messages will not be kept across process restarts. This means **it is possible to lose
messages**. If you cannot lose messages, then you should set the :code:`database_path` option.

In addition, you can also set a TTL to live on all of the messages that should be published. Simply
pass :code:`event_ttl` to the initializer and your events will be aged off from the cache. The TTL
is in seconds.
