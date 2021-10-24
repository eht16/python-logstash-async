# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from logging import Handler

from logstash_async.constants import constants
from logstash_async.formatter import LogstashFormatter
from logstash_async.utils import import_string, safe_log_via_print
from logstash_async.worker import LogProcessingWorker
import logstash_async


class ProcessingError(Exception):
    """"""


class SynchronousLogstashHandler(Handler):
    """Sync Python logging handler for Logstash. Sends events over TCP by default.
    :param host: The host of the logstash server, required.
    :param port: The port of the logstash server, required.
    :param transport: Callable or path to a compatible transport class.
    :param ssl_enable: Should SSL be enabled for the connection? Default is False.
    :param ssl_verify: Should the server's SSL certificate be verified?
    :param keyfile: The path to client side SSL key file (default is None).
    :param certfile: The path to client side SSL certificate file (default is None).
    :param ca_certs: The path to the file containing recognized CA certificates.
    :param enable: Flag to enable log processing (default is True, disabling
                   might be handy for local testing, etc.)
    """

    # ----------------------------------------------------------------------
    # pylint: disable=too-many-arguments
    def __init__(self, host, port, transport='logstash_async.transport.TcpTransport',
                 ssl_enable=False, ssl_verify=True, keyfile=None, certfile=None, ca_certs=None,
                 enable=True, encoding='utf-8', **kwargs):
        super().__init__()
        self._host = host
        self._port = port
        self._transport_path = transport
        self._ssl_enable = ssl_enable
        self._ssl_verify = ssl_verify
        self._keyfile = keyfile
        self._certfile = certfile
        self._ca_certs = ca_certs
        self._enable = enable
        self._transport = None
        self._encoding = encoding
        self._setup_transport(**kwargs)

    # ----------------------------------------------------------------------
    def emit(self, record):
        if not self._enable:
            return  # we should not do anything, so just leave

        self._setup_transport()

        # basically same implementation as in logging.handlers.SocketHandler.emit()
        try:
            data = self._format_record(record)
            self._transport.send([data], use_logging=False)
        except Exception:
            self.handleError(record)

    # ----------------------------------------------------------------------
    def _setup_transport(self, **kwargs):
        if self._transport is not None:
            return

        transport_args = dict(
            host=self._host,
            port=self._port,
            timeout=constants.SOCKET_TIMEOUT,
            ssl_enable=self._ssl_enable,
            ssl_verify=self._ssl_verify,
            keyfile=self._keyfile,
            certfile=self._certfile,
            ca_certs=self._ca_certs,
            **kwargs)
        if isinstance(self._transport_path, str):
            transport_class = import_string(self._transport_path)
            self._transport = transport_class(**transport_args)
        elif callable(self._transport_path):
            self._transport = self._transport_path(**transport_args)
        elif hasattr(self._transport_path, 'send'):
            self._transport = self._transport_path
        else:
            raise RuntimeError(
                'Invalid transport path: must be an importable module path, '
                'a class or factory function or an instance.')

    # ----------------------------------------------------------------------
    def _format_record(self, record):
        self._create_formatter_if_necessary()
        formatted = self.formatter.format(record)
        if isinstance(formatted, str):
            formatted = formatted.encode(self._encoding)  # pylint: disable=redefined-variable-type
        return formatted + b'\n'

    # ----------------------------------------------------------------------
    def _create_formatter_if_necessary(self):
        if self.formatter is None:
            self.formatter = LogstashFormatter()

    # ----------------------------------------------------------------------
    def close(self):
        self.acquire()
        try:
            self.shutdown()
        finally:
            self.release()
        super().close()

    # ----------------------------------------------------------------------
    def shutdown(self):
        self._close_transport()

    # ----------------------------------------------------------------------
    def _close_transport(self):
        try:
            if self._transport is not None:
                self._transport.close()
        except Exception as exc:
            safe_log_via_print('error', f'Error on closing transport: {exc}')


class AsynchronousLogstashHandler(SynchronousLogstashHandler):
    """Python logging handler for Logstash. Sends events over TCP by default.
    (there are some more params coming from SynchronousLogstashHandler)
    :param database_path: The path to the file containing queued events, required.
                          Use None to use a in-memory cache.
    :param event_ttl: Amount of time in seconds to wait before expiring log messages in
                      the database. (Given in seconds. Default is None, and disables this feature)
    """

    _worker_thread = None

    # ----------------------------------------------------------------------
    # pylint: disable=too-many-arguments
    def __init__(self, host, port, database_path, transport='logstash_async.transport.TcpTransport',
                 ssl_enable=False, ssl_verify=True, keyfile=None, certfile=None, ca_certs=None,
                 enable=True, event_ttl=None, encoding='utf-8', **kwargs):

        self._database_path = database_path
        self._event_ttl = event_ttl

        super().__init__(host, port, transport,
                 ssl_enable, ssl_verify, keyfile, certfile, ca_certs,
                 enable, encoding, **kwargs)

    # ----------------------------------------------------------------------
    def emit(self, record):
        if not self._enable:
            return  # we should not do anything, so just leave

        self._setup_transport()
        self._start_worker_thread()

        # basically same implementation as in logging.handlers.SocketHandler.emit()
        try:
            data = self._format_record(record)
            AsynchronousLogstashHandler._worker_thread.enqueue_event(data)
        except Exception:
            self.handleError(record)

    # ----------------------------------------------------------------------
    def flush(self):
        if self._worker_thread_is_running():
            self._worker_thread.force_flush_queued_events()

    # ----------------------------------------------------------------------
    def _start_worker_thread(self):
        if self._worker_thread_is_running():
            return

        AsynchronousLogstashHandler._worker_thread = LogProcessingWorker(
            host=self._host,
            port=self._port,
            transport=self._transport,
            ssl_enable=self._ssl_enable,
            ssl_verify=self._ssl_verify,
            keyfile=self._keyfile,
            certfile=self._certfile,
            ca_certs=self._ca_certs,
            database_path=self._database_path,
            cache=logstash_async.EVENT_CACHE,
            event_ttl=self._event_ttl)
        AsynchronousLogstashHandler._worker_thread.start()

    # ----------------------------------------------------------------------
    @staticmethod
    def _worker_thread_is_running():
        worker_thread = AsynchronousLogstashHandler._worker_thread
        if worker_thread is not None and worker_thread.is_alive():
            return True

        return False

    # ----------------------------------------------------------------------
    def shutdown(self):
        if self._worker_thread_is_running():
            self._trigger_worker_shutdown()
            self._wait_for_worker_thread()
            self._reset_worker_thread()
            self._close_transport()
        else:
            pass

    # ----------------------------------------------------------------------
    def _trigger_worker_shutdown(self):
        AsynchronousLogstashHandler._worker_thread.shutdown()

    # ----------------------------------------------------------------------
    def _wait_for_worker_thread(self):
        AsynchronousLogstashHandler._worker_thread.join()

    # ----------------------------------------------------------------------
    def _reset_worker_thread(self):
        AsynchronousLogstashHandler._worker_thread = None
