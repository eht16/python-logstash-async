# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from logging import Handler

from six import string_types

from logstash_async.formatter import LogstashFormatter
from logstash_async.utils import import_string, safe_log_via_print
from logstash_async.worker import LogProcessingWorker


class ProcessingError(Exception):
    """"""


class AsynchronousLogstashHandler(Handler):
    """Python logging handler for Logstash. Sends events over TCP.
    :param host: The host of the logstash server.
    :param port: The port of the logstash server (default 5959).
    :param transport: Callable or path to a compatible transport class.
    :param ssl_enable: Should SSL be enabled for the connection? Default is False.
    :param ssl_verify: Should the server's SSL certificate be verified?
    :param keyfile: The path to client side SSL key file (default is None).
    :param certfile: The path to client side SSL certificate file (default is None).
    :param ca_certs: The path to the file containing recognized CA certificates.
    :param database_path: The path to the file containing queued events.
    :param enable Flag to enable log processing (default is True, disabling
                  might be handy for local testing, etc.)
    """

    _worker_thread = None

    # ----------------------------------------------------------------------
    def __init__(self, host, port=5959, transport='logstash_async.transport.TcpTransport',
                 ssl_enable=False, ssl_verify=True, keyfile=None, certfile=None, ca_certs=None,
                 database_path=':memory:', enable=True):
        super(AsynchronousLogstashHandler, self).__init__()
        self._host = host
        self._port = port
        self._transport_path = transport
        self._ssl_enable = ssl_enable
        self._ssl_verify = ssl_verify
        self._keyfile = keyfile
        self._certfile = certfile
        self._ca_certs = ca_certs
        self._database_path = database_path
        self._enable = enable
        self._transport = None
        self._setup_transport()

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
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handleError(record)

    # ----------------------------------------------------------------------
    def _setup_transport(self):
        if self._transport is not None:
            return

        if isinstance(self._transport_path, string_types):
            transport_class = import_string(self._transport_path)
            self._transport = transport_class(
                host=self._host,
                port=self._port,
                ssl_enable=self._ssl_enable,
                ssl_verify=self._ssl_verify,
                keyfile=self._keyfile,
                certfile=self._certfile,
                ca_certs=self._ca_certs)
        else:
            self._transport = self._transport_path

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
            database_path=self._database_path)
        AsynchronousLogstashHandler._worker_thread.start()

    # ----------------------------------------------------------------------
    @staticmethod
    def _worker_thread_is_running():
        worker_thread = AsynchronousLogstashHandler._worker_thread
        if worker_thread is not None and worker_thread.is_alive():
            return True

    # ----------------------------------------------------------------------
    def _format_record(self, record):
        self._create_formatter_if_necessary()
        return self.formatter.format(record) + b'\n'

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
        super(AsynchronousLogstashHandler, self).close()

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

    # ----------------------------------------------------------------------
    def _close_transport(self):
        try:
            if self._transport is not None:
                self._transport.close()
        except Exception as e:
            safe_log_via_print('error', u'Error on closing transport: {}'.format(e))
