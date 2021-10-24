# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from datetime import datetime, timedelta
from logging import getLogger as get_logger
import uuid

from logstash_async.cache import Cache
from logstash_async.constants import constants


class MemoryCache(Cache):
    """Backend implementation for python-logstash-async. Keeps messages in a local, in-memory cache
    while attempting to publish them to logstash. Does not persist through process restarts. Also,
    does not write to disk.

    :param cache: Usually just an empty dictionary
    :param event_ttl: Optional parameter used to expire events in the cache after a time
    """

    logger = get_logger(__name__)

    # ----------------------------------------------------------------------
    def __init__(self, cache, event_ttl=None):
        self._cache = cache
        self._event_ttl = event_ttl

    # ----------------------------------------------------------------------
    def add_event(self, event):
        event_id = uuid.uuid4()
        self._cache[event_id] = {
            "event_text": event,
            "pending_delete": False,
            "entry_date": datetime.now(),
            "id": event_id
        }

    # ----------------------------------------------------------------------
    def get_queued_events(self):
        events = []
        event_count = 0
        for event in self._cache.values():
            if not event['pending_delete']:
                events.append(event)
                event['pending_delete'] = True

                event_count += 1
                if event_count >= constants.QUEUED_EVENTS_BATCH_SIZE:
                    break
        return events

    # ----------------------------------------------------------------------
    def requeue_queued_events(self, events):
        for event in events:
            event_to_queue = self._cache.get(event['id'], None)
            # If they gave us an event which is not in the cache,
            # there is really nothing for us to do. Right now
            # this use-case does not raise an error. Instead, we
            # just log the message.
            if event_to_queue:
                event_to_queue['pending_delete'] = False
            else:
                self.logger.warning(
                    "Could not requeue event with id %s. It does not appear to be in the cache.",
                    event['id'])

    # ----------------------------------------------------------------------
    def delete_queued_events(self):
        ids_to_delete = [event['id'] for event in self._cache.values() if event['pending_delete']]
        self._delete_events(ids_to_delete)

    # ----------------------------------------------------------------------
    def expire_events(self):
        if self._event_ttl is None:
            return

        delete_time = datetime.now() - timedelta(seconds=self._event_ttl)
        ids_to_delete = [
            event['id']
            for event in self._cache.values()
            if event['entry_date'] < delete_time]
        self._delete_events(ids_to_delete)

    # ----------------------------------------------------------------------
    def _delete_events(self, ids_to_delete):
        for event_id in ids_to_delete:
            # If the event is not in the cache, is there anything
            # that we can do. This currently doesn't throw an error.
            event = self._cache.pop(event_id, None)
            if not event:
                self.logger.warning(
                    "Could not delete event with id %s. It does not appear to be in the cache.",
                    event_id)
