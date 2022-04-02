# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from datetime import datetime
from logging import getLogger as get_logger
from queue import Empty, Queue
from socket import gaierror as socket_gaierror
from threading import Event, Thread

from limits import parse as parse_rate_limit
from limits.storage import MemoryStorage
from limits.strategies import FixedWindowRateLimiter

from logstash_async.constants import constants
from logstash_async.database import DatabaseCache, DatabaseLockedError
from logstash_async.memory_cache import MemoryCache
from logstash_async.utils import safe_log_via_print


class ProcessingError(Exception):
    """"""


class LogProcessingWorker(Thread):  # pylint: disable=too-many-instance-attributes
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
        self._memory_cache = kwargs.pop('cache')
        self._event_ttl = kwargs.pop('event_ttl')

        super().__init__(*args, **kwargs)
        self.daemon = True
        self.name = self.__class__.__name__

        self._shutdown_event = Event()
        self._flush_event = Event()
        self._queue = Queue()

        self._event = None
        self._database = None
        self._last_event_flush_date = None
        self._non_flushed_event_count = None
        self._logger = None
        self._rate_limit_storage = None
        self._rate_limit_strategy = None
        self._rate_limit_item = None

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
        except Exception as exc:
            # we really should not get anything here, and if, the worker thread is dying
            # too early resulting in undefined application behaviour
            self._log_general_error(exc)
        # check for empty queue and report if not
        self._warn_about_non_empty_queue_on_shutdown()

    # ----------------------------------------------------------------------
    def force_flush_queued_events(self):
        self._flush_event.set()

    # ----------------------------------------------------------------------
    def _reset_flush_counters(self):
        self._last_event_flush_date = datetime.now()
        self._non_flushed_event_count = 0

    # ----------------------------------------------------------------------
    def _clear_flush_event(self):
        self._flush_event.clear()

    # ----------------------------------------------------------------------
    def _setup_logger(self):
        self._logger = get_logger(self.name)
        # rate limit our own messages to not spam around in case of temporary network errors, etc
        rate_limit_setting = constants.ERROR_LOG_RATE_LIMIT
        if rate_limit_setting:
            self._rate_limit_storage = MemoryStorage()
            self._rate_limit_strategy = FixedWindowRateLimiter(self._rate_limit_storage)
            self._rate_limit_item = parse_rate_limit(rate_limit_setting)

    # ----------------------------------------------------------------------
    def _setup_database(self):
        if self._database_path:
            self._database = DatabaseCache(path=self._database_path, event_ttl=self._event_ttl)
        else:
            self._database = MemoryCache(cache=self._memory_cache, event_ttl=self._event_ttl)

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

                force_flush = self._flush_requested()
                self._flush_queued_events(force=force_flush)
                self._delay_processing()
                self._expire_events()
            except (DatabaseLockedError, ProcessingError):
                if self._shutdown_requested():
                    return

                self._requeue_event()
                self._delay_processing()

    # ----------------------------------------------------------------------
    def _fetch_event(self):
        self._event = self._queue.get(block=False)

    # ----------------------------------------------------------------------
    def _process_event(self):
        try:
            self._write_event_to_database()
        except DatabaseLockedError as exc:
            self._safe_log(
                'debug',
                'Database is locked, will try again later (queue length %d)',
                self._queue.qsize(),
                exc=exc)
            raise
        except Exception as exc:
            self._log_processing_error(exc)
            raise ProcessingError from exc
        else:
            self._event = None

    # ----------------------------------------------------------------------
    def _expire_events(self):
        try:
            self._database.expire_events()
        except DatabaseLockedError:
            # Nothing to handle, if it fails, we will either successfully publish
            # these messages next time or we will delete them on the next pass.
            pass

    # ----------------------------------------------------------------------
    def _log_processing_error(self, exception):
        self._safe_log(
            'exception',
            'Log processing error (queue size: %3s): %s',
            self._queue.qsize(),
            exception,
            exc=exception)

    # ----------------------------------------------------------------------
    def _delay_processing(self):
        self._shutdown_event.wait(constants.QUEUE_CHECK_INTERVAL)

    # ----------------------------------------------------------------------
    def _shutdown_requested(self):
        return self._shutdown_event.is_set()

    # ----------------------------------------------------------------------
    def _flush_requested(self):
        return self._flush_event.is_set()

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
        if not force and not self._queued_event_interval_reached() and \
                not self._queued_event_count_reached():
            return

        self._clear_flush_event()

        while True:
            queued_events = self._fetch_queued_events_for_flush()
            if not queued_events:
                break

            try:
                events = [event['event_text'] for event in queued_events]
                self._send_events(events)
            # Log connection and network errors as warnings as they are rather harmless
            except (ConnectionError, TimeoutError, socket_gaierror) as exc:
                self._safe_log(
                    'warning',
                    'An error occurred while sending events: %s',
                    exc)
                self._database.requeue_queued_events(queued_events)
                break
            except Exception as exc:
                self._safe_log(
                    'exception',
                    'An error occurred while sending events: %s',
                    exc,
                    exc=exc)
                self._database.requeue_queued_events(queued_events)
                break
            else:
                self._delete_queued_events_from_database()
                self._reset_flush_counters()

    # ----------------------------------------------------------------------
    def _fetch_queued_events_for_flush(self):
        try:
            return self._database.get_queued_events()
        except DatabaseLockedError as exc:
            self._safe_log(
                'debug',
                'Database is locked, will try again later (queue length %d)',
                self._queue.qsize(),
                exc=exc)
        except Exception as exc:
            # just log the exception and hope we can recover from the error
            self._safe_log('exception', 'Error retrieving queued events: %s', exc, exc=exc)

        return None

    # ----------------------------------------------------------------------
    def _delete_queued_events_from_database(self):
        try:
            self._database.delete_queued_events()
        except DatabaseLockedError:
            pass  # nothing to handle, if it fails, we delete those events in a later run

    # ----------------------------------------------------------------------
    def _queued_event_interval_reached(self):
        delta = datetime.now() - self._last_event_flush_date
        return delta.total_seconds() > constants.QUEUED_EVENTS_FLUSH_INTERVAL

    # ----------------------------------------------------------------------
    def _queued_event_count_reached(self):
        return self._non_flushed_event_count > constants.QUEUED_EVENTS_FLUSH_COUNT

    # ----------------------------------------------------------------------
    def _send_events(self, events):
        use_logging = not self._shutdown_requested()
        self._transport.send(events, use_logging=use_logging)

    # ----------------------------------------------------------------------
    def _log_general_error(self, exc):
        self._safe_log('exception', 'An unexpected error occurred: %s', exc, exc=exc)

    # ----------------------------------------------------------------------
    def _safe_log(self, log_level, message, *args, **kwargs):
        # we cannot log via the logging subsystem any longer once it has been set to shutdown
        if self._shutdown_requested():
            safe_log_via_print(log_level, message, *args, **kwargs)
        else:
            rate_limit_allowed = self._rate_limit_check(kwargs)
            if rate_limit_allowed <= 0:
                return  # skip further logging due to rate limiting
            if rate_limit_allowed == 1:
                # extend the message to indicate future rate limiting
                message = \
                    f'{message} (rate limiting effective, further equal messages will be limited'

            self._safe_log_impl(log_level, message, *args, **kwargs)

    # ----------------------------------------------------------------------
    def _rate_limit_check(self, kwargs):
        exc = kwargs.pop('exc', None)
        if self._rate_limit_strategy is not None and exc is not None:
            key = self._factor_rate_limit_key(exc)
            # query curent counter for the caller
            _, remaining = self._rate_limit_strategy.get_window_stats(self._rate_limit_item, key)
            # increase the rate limit counter for the key
            self._rate_limit_strategy.hit(self._rate_limit_item, key)
            return remaining

        return 2  # any value greater than 1 means allowed

    # ----------------------------------------------------------------------
    def _factor_rate_limit_key(self, exc):  # pylint: disable=no-self-use
        module_name = getattr(exc, '__module__', '__no_module__')
        class_name = exc.__class__.__name__
        key_items = [module_name, class_name]
        if hasattr(exc, 'errno') and isinstance(exc.errno, int):
            # in case of socket.error, include the errno as rate limiting key
            key_items.append(str(exc.errno))
        return '.'.join(key_items)

    # ----------------------------------------------------------------------
    def _safe_log_impl(self, log_level, message, *args, **kwargs):
        log_func = getattr(self._logger, log_level)
        log_func(message, *args, **kwargs)

    # ----------------------------------------------------------------------
    def _warn_about_non_empty_queue_on_shutdown(self):
        queue_size = self._queue.qsize()
        if queue_size:
            self._safe_log(
                'warn',
                f'Non-empty queue while shutting down ({queue_size} events pending). '
                'This indicates a previous error.',
                extra=dict(queue_size=queue_size))
