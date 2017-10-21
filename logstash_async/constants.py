# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.


class Constants(object):
    """
    Collection of various constants which are meant to static but still changeable
    from the calling application at startup if necessary.

    The class should not instantiated directly but used via the module level `constant` variable.
    """
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


constants = Constants()
