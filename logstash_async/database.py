# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from contextlib import contextmanager
import sqlite3
import sys

from logstash_async.cache import Cache
from logstash_async.constants import constants
from logstash_async.utils import ichunked


DATABASE_SCHEMA_STATEMENTS = [
    '''
    CREATE TABLE IF NOT EXISTS `event` (
    `event_id`          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `event_text`        TEXT NOT NULL,
    `pending_delete`    INTEGER NOT NULL,
    `entry_date`        DATETIME NOT NULL);
    ''',
    '''CREATE INDEX IF NOT EXISTS `idx_pending_delete` ON `event` (pending_delete);''',
    '''CREATE INDEX IF NOT EXISTS `idx_entry_date` ON `event` (entry_date);''',
]


class DatabaseLockedError(Exception):
    pass


class DatabaseDiskIOError(Exception):
    pass


class DatabaseCache(Cache):
    """
        Backend implementation for python-logstash-async. Keeps messages on disk in a SQL-lite DB
        while attempting to publish them to logstash. Persists log messages through restarts
        of a process.

        :param path: Path to the SQLite database
        :param event_ttl: Optional parameter used to expire events in the database after a time
    """

    # ----------------------------------------------------------------------
    def __init__(self, path, event_ttl=None):
        self._database_path = path
        self._connection = None
        self._event_ttl = event_ttl

    @contextmanager
    def _connect(self):
        try:
            self._open()
            with self._connection as connection:
                yield connection
        except sqlite3.OperationalError:
            self._handle_sqlite_error()
            raise
        finally:
            self._close()

    # ----------------------------------------------------------------------
    def _open(self):
        self._connection = sqlite3.connect(
            self._database_path,
            timeout=constants.DATABASE_TIMEOUT,
            isolation_level='EXCLUSIVE')
        self._connection.row_factory = sqlite3.Row
        self._initialize_schema()

    # ----------------------------------------------------------------------
    def _close(self):
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    # ----------------------------------------------------------------------
    def _initialize_schema(self):
        cursor = self._connection.cursor()
        try:
            for statement in DATABASE_SCHEMA_STATEMENTS:
                cursor.execute(statement)
        except sqlite3.OperationalError:
            self._close()
            self._handle_sqlite_error()
            raise

    # ----------------------------------------------------------------------
    def add_event(self, event):
        query = '''
            INSERT INTO `event`
            (`event_text`, `pending_delete`, `entry_date`) VALUES (?, ?, datetime('now'))'''
        with self._connect() as connection:
            connection.execute(query, (event, False))

    # ----------------------------------------------------------------------
    def _handle_sqlite_error(self):
        _, exc, _ = sys.exc_info()
        if str(exc) == 'database is locked':
            raise DatabaseLockedError from exc
        if str(exc) == 'disk I/O error':
            raise DatabaseDiskIOError from exc
        if str(exc) == "unable to open database file":
            raise DatabaseDiskIOError from exc
        if str(exc) == "attempt to write a readonly database":
            raise DatabaseDiskIOError from exc

    # ----------------------------------------------------------------------
    def get_queued_events(self):
        query_fetch = '''
            SELECT `event_id`, `event_text` FROM `event` WHERE `pending_delete` = 0 LIMIT ?;'''
        query_update_base = 'UPDATE `event` SET `pending_delete`=1 WHERE `event_id` IN (%s);'
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(query_fetch, (constants.QUEUED_EVENTS_BATCH_SIZE,))
            events = cursor.fetchall()
            self._bulk_update_events(cursor, events, query_update_base)

        return events

    # ----------------------------------------------------------------------
    def _bulk_update_events(self, cursor, events, statement_base):
        event_ids = [event[0] for event in events]
        # split into multiple queries as SQLite has a maximum 1000 variables per query
        for event_ids_subset in ichunked(event_ids, constants.DATABASE_EVENT_CHUNK_SIZE):
            statement = statement_base % ','.join('?' * len(event_ids_subset))
            cursor.execute(statement, event_ids_subset)

    # ----------------------------------------------------------------------
    def requeue_queued_events(self, events):
        query_update_base = 'UPDATE `event` SET `pending_delete`=0 WHERE `event_id` IN (%s);'
        with self._connect() as connection:
            cursor = connection.cursor()
            self._bulk_update_events(cursor, events, query_update_base)

    # ----------------------------------------------------------------------
    def delete_queued_events(self):
        query_delete = 'DELETE FROM `event` WHERE `pending_delete`=1;'
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(query_delete)

    # ----------------------------------------------------------------------
    def expire_events(self):
        if self._event_ttl is None:
            return

        query_delete = "DELETE FROM `event` WHERE " \
                       f"`entry_date` < datetime('now', '-{self._event_ttl} seconds');"
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(query_delete)
