# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from datetime import datetime
from logging import getLogger as get_logger
from threading import Event, Thread

from six.moves.queue import Queue, Empty

from logstash_async.constants import (
    QUEUED_EVENTS_FLUSH_COUNT,
    QUEUED_EVENTS_FLUSH_INTERVAL,
    QUEUE_CHECK_INTERVAL)
from logstash_async.database import DatabaseCache, DatabaseLockedError
from logstash_async.utils import safe_log_via_print


class ProcessingError(Exception):
    """"""


class LogProcessingWorker(Thread):
    """"""

    # ----------------------------------------------------------------------
    def __init__(self, *args, **kwargs):
        self._host = kwargs.pop('host')
        self._port = kwargs.pop('port')
        self._transport = kwargs.pop('transport')
        self._ssl_enable = kwargs.pop('ssl_enable')
        self._ssl_verify = kwargs.pop('ssl_verify')
        self._keyfile = kwargs.pop('keyfile')
        self._certfile = kwargs.pop('certfile')
        self._ca_certs = kwargs.pop('ca_certs')
        self._database_path = kwargs.pop('database_path')

        super(LogProcessingWorker, self).__init__(*args, **kwargs)
        self.daemon = True
        self.name = self.__class__.__name__

        self._shutdown_event = Event()
        self._queue = Queue()

        self._event = None
        self._database = None
        self._last_event_flush_date = None
        self._non_flushed_event_count = None
        self._logger = None

    # ----------------------------------------------------------------------
    def enqueue_event(self, event):
        # called from other threads
        self._queue.put(event)

    # ----------------------------------------------------------------------
    def shutdown(self):
        # called from other threads
        self._shutdown_event.set()

    # ----------------------------------------------------------------------
    def run(self):
        self._reset_flush_counters()
        self._setup_logger()
        self._setup_database()
        try:
            self._fetch_events()
        except Exception as e:
            # we really should not get anything here, and if, the worker thread is dying
            # too early resulting in undefined application behaviour
            self._log_general_error(e)
        # check for empty queue and report if not
        self._warn_about_non_empty_queue_on_shutdown()

    # ----------------------------------------------------------------------
    def _reset_flush_counters(self):
        self._last_event_flush_date = datetime.now()
        self._non_flushed_event_count = 0

    # ----------------------------------------------------------------------
    def _setup_logger(self):
        self._logger = get_logger(self.name)

    # ----------------------------------------------------------------------
    def _setup_database(self):
        self._database = DatabaseCache(self._database_path)

    # ----------------------------------------------------------------------
    def _fetch_events(self):
        while True:
            try:
                self._fetch_event()
                self._process_event()
            except Empty:
                # Flush queued (in database) events after internally queued events has been
                # processed, i.e. the queue is empty.
                if self._shutdown_requested():
                    self._flush_queued_events(force=True)
                    return

                self._flush_queued_events()
                self._delay_processing()
            except (DatabaseLockedError, ProcessingError):
                if self._shutdown_requested():
                    return
                else:
                    self._requeue_event()
                    self._delay_processing()

    # ----------------------------------------------------------------------
    def _fetch_event(self):
        self._event = self._queue.get(block=False)

    # ----------------------------------------------------------------------
    def _process_event(self):
        try:
            self._write_event_to_database()
        except DatabaseLockedError:
            self._safe_log(
                u'debug',
                u'Database is locked, will try again later (queue length %d)',
                self._queue.qsize())
            raise
        except Exception as e:
            self._log_processing_error(e)
            raise ProcessingError()
        else:
            self._event = None

    # ----------------------------------------------------------------------
    def _log_processing_error(self, exception):
        self._safe_log(
            u'exception',
            u'Log processing error (queue size: %3s): %s',
            self._queue.qsize(),
            exception)

    # ----------------------------------------------------------------------
    def _delay_processing(self):
        self._shutdown_event.wait(QUEUE_CHECK_INTERVAL)

    # ----------------------------------------------------------------------
    def _shutdown_requested(self):
        return self._shutdown_event.is_set()

    # ----------------------------------------------------------------------
    def _requeue_event(self):
        self._queue.put(self._event)

    # ----------------------------------------------------------------------
    def _write_event_to_database(self):
        self._database.add_event(self._event)
        self._non_flushed_event_count += 1

    # ----------------------------------------------------------------------
    def _flush_queued_events(self, force=False):
        # check if necessary and abort if not
        if not force and not self._queued_event_interval_reached() and not self._queued_event_count_reached():
            return

        try:
            queued_events = self._database.get_queued_events()
        except DatabaseLockedError:
            self._safe_log(
                u'debug',
                u'Database is locked, will try again later (queue length %d)',
                self._queue.qsize())
            return  # try again later
        except Exception as e:
            # just log the exception and hope we can recover from the error
            self._safe_log(u'exception', u'Error retrieving queued events: %s', e)
            return

        if queued_events:
            try:
                events = [event['event_text'] for event in queued_events]
                self._send_events(events)
            except Exception as e:
                self._safe_log(u'exception', u'An error occurred while sending events: %s', e)
                self._database.requeue_queued_events(queued_events)
            else:
                self._database.delete_queued_events()
                self._reset_flush_counters()

    # ----------------------------------------------------------------------
    def _queued_event_interval_reached(self):
        delta = datetime.now() - self._last_event_flush_date
        return delta.total_seconds() > QUEUED_EVENTS_FLUSH_INTERVAL

    # ----------------------------------------------------------------------
    def _queued_event_count_reached(self):
        return self._non_flushed_event_count > QUEUED_EVENTS_FLUSH_COUNT

    # ----------------------------------------------------------------------
    def _send_events(self, events):
        self._transport.send(events)

    # ----------------------------------------------------------------------
    def _log_general_error(self, exc):
        self._safe_log(u'exception', u'An unexpected error occurred: %s', exc)

    # ----------------------------------------------------------------------
    def _safe_log(self, log_level, message, *args, **kwargs):
        # we cannot log via the logging subsystem any longer once it has been set to shutdown
        if self._shutdown_requested():
            safe_log_via_print(log_level, message, *args, **kwargs)
        else:
            log_func = getattr(self._logger, log_level)
            return log_func(message, *args, **kwargs)

    # ----------------------------------------------------------------------
    def _warn_about_non_empty_queue_on_shutdown(self):
        queue_size = self._queue.qsize()
        if queue_size:
            self._safe_log(
                'warn',
                u'Non-empty queue while shutting down ({} events pending). '
                u'This indicates a previous error.'.format(queue_size),
                extra=dict(queue_size=queue_size))
