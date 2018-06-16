# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class Cache(object):

    # ----------------------------------------------------------------------
    @abc.abstractmethod
    def add_event(self, event):
        """Add the event to the cache.

        This method is meant to be called by various other threads.
        All other methods in this class are for caching messages and
        will be called by the log processing worker threads.

        :param str event: A log message
        :return:
        """
        pass

    # ----------------------------------------------------------------------
    @abc.abstractmethod
    def get_queued_events(self):
        """Get pending events and mark them to be deleted

        :return: A list of events to be published
        """
        pass

    # ----------------------------------------------------------------------
    @abc.abstractmethod
    def requeue_queued_events(self, events):
        """Mark pending_delete for events passed in to False.

        Used when an error occurs attempting to publish to logstash. Upon
        failure, we rollback the deletion flag to False.

        :param events:
        :return:
        """
        pass

    # ----------------------------------------------------------------------
    @abc.abstractmethod
    def delete_queued_events(self):
        """Delete events marked for deletion

        :return:
        """
        pass

    # ----------------------------------------------------------------------
    @abc.abstractmethod
    def expire_events(self):
        """Expire events older than the TTL. If no TTL is set, no action is taken.

        :return:
        """
        pass
