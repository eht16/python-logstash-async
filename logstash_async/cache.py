# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from abc import ABC, abstractmethod


class Cache(ABC):

    # ----------------------------------------------------------------------
    @abstractmethod
    def add_event(self, event):
        """Add the event to the cache.

        This method is meant to be called by various other threads.
        All other methods in this class are for caching messages and
        will be called by the log processing worker threads.

        :param str event: A log message
        :return:
        """

    # ----------------------------------------------------------------------
    @abstractmethod
    def get_queued_events(self):
        """Get pending events and mark them to be deleted

        :return: A list of events to be published
        """

    # ----------------------------------------------------------------------
    @abstractmethod
    def requeue_queued_events(self, events):
        """Mark pending_delete for events passed in to False.

        Used when an error occurs attempting to publish to logstash. Upon
        failure, we rollback the deletion flag to False.

        :param events:
        :return:
        """

    # ----------------------------------------------------------------------
    @abstractmethod
    def delete_queued_events(self):
        """Delete events marked for deletion

        :return:
        """

    # ----------------------------------------------------------------------
    @abstractmethod
    def expire_events(self):
        """Expire events older than the TTL. If no TTL is set, no action is taken.

        :return:
        """

    # ----------------------------------------------------------------------
    @abstractmethod
    def get_non_flushed_event_count(self):
        """Determine the count of pending events in the cache which need to be sent to Logstash.

        :return: Count of pending events
        """
