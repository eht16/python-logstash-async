# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

import sqlite3
import sys

import six

from logstash_async.utils import ichunked


DATABASE_SCHEMA_STATEMENTS = [
    '''
    CREATE TABLE IF NOT EXISTS `event` (
    `event_id`          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `event_text`        TEXT NOT NULL,
    `pending_delete`    INTEGER NOT NULL,
    `entry_date`        TEXT NOT NULL);
    ''',
    '''CREATE INDEX IF NOT EXISTS `idx_pending_delete` ON `event` (pending_delete);''',
    '''CREATE INDEX IF NOT EXISTS `idx_entry_date` ON `event` (entry_date);''',
]

EVENT_CHUNK_SIZE = 750  # maximum number of events to be updated within one SQLite statement


class DatabaseLockedError(Exception):
    pass


class DatabaseCache(object):

    # ----------------------------------------------------------------------
    def __init__(self, path):
        self._database_path = path
        self._connection = None

    # ----------------------------------------------------------------------
    def _open(self):
        self._connection = sqlite3.connect(
            self._database_path,
            timeout=5.0,
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
        for statement in DATABASE_SCHEMA_STATEMENTS:
            cursor.execute(statement)

    # ----------------------------------------------------------------------
    def add_event(self, event):
        query = u'''
            INSERT INTO `event`
            (`event_text`, `pending_delete`, `entry_date`) VALUES (?, ?, datetime('now'))'''
        self._open()
        try:
            with self._connection:  # implicit commit/rollback
                self._connection.execute(query, (event, False))
        except sqlite3.OperationalError:
            self._handle_sqlite_error()
            raise
        finally:
            self._close()

    # ----------------------------------------------------------------------
    def _handle_sqlite_error(self):
        _, e, traceback = sys.exc_info()
        if str(e) == 'database is locked':
            six.reraise(DatabaseLockedError, DatabaseLockedError(e), traceback)

    # ----------------------------------------------------------------------
    def get_queued_events(self):
        """
        Fetch pending events and mark them to be deleted soon, so other threads/processes
        won't fetch them as well.
        """
        query_fetch = 'SELECT `event_id`, `event_text` FROM `event` WHERE `pending_delete` = 0;'
        query_update_base = 'UPDATE `event` SET `pending_delete`=1 WHERE `event_id` IN (%s);'
        self._open()
        try:
            with self._connection:  # implicit commit/rollback
                cursor = self._connection.cursor()
                cursor.execute(query_fetch)
                events = cursor.fetchall()
                # mark retrieved events as pending_delete
                self._bulk_update_events(cursor, events, query_update_base)
        except sqlite3.OperationalError:
            self._handle_sqlite_error()
            raise
        finally:
            self._close()

        return events

    # ----------------------------------------------------------------------
    def _bulk_update_events(self, cursor, events, statement_base):
        event_ids = [event[0] for event in events]
        # split into multiple queries as SQLite has a maximum 1000 variables per query
        for event_ids_subset in ichunked(event_ids, EVENT_CHUNK_SIZE):
            statement = statement_base % ','.join('?' * len(event_ids_subset))
            cursor.execute(statement, event_ids_subset)

    # ----------------------------------------------------------------------
    def requeue_queued_events(self, events):
        query_update_base = 'UPDATE `event` SET `pending_delete`=0 WHERE `event_id` IN (%s);'
        self._open()
        try:
            with self._connection:  # implicit commit/rollback
                cursor = self._connection.cursor()
                self._bulk_update_events(cursor, events, query_update_base)
        except sqlite3.OperationalError:
            self._handle_sqlite_error()
            raise
        finally:
            self._close()

        return events

    # ----------------------------------------------------------------------
    def delete_queued_events(self):
        query_delete = 'DELETE FROM `event` WHERE `pending_delete`=1;'
        self._open()
        try:
            with self._connection:  # implicit commit/rollback
                cursor = self._connection.cursor()
                cursor.execute(query_delete)
        except sqlite3.OperationalError:
            self._handle_sqlite_error()
            raise
        finally:
            self._close()
