# -*- coding: utf-8 -*-


# timeout in seconds for TCP connections
SOCKET_TIMEOUT = 5.0
# interval in seconds to check the internal queue for new messages to be cached in the database
QUEUE_CHECK_INTERVAL = 2.0
# interval in seconds to send cached events from the database to Logstash
QUEUED_EVENTS_FLUSH_INTERVAL = 10.0
# count of cached events to send cached events from the database to Logstash; events are sent
# to Logstash whenever QUEUED_EVENTS_FLUSH_COUNT or QUEUED_EVENTS_FLUSH_INTERVAL is reached,
# whatever happens first
QUEUED_EVENTS_FLUSH_COUNT = 50
