# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

import json
import logging
import socket
import ssl
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Union


# Use fcntl to control socket buffering if available
try:
    import fcntl
    import struct
    import termios
except ImportError:
    fcntl = None

import pylogbeat
import requests
from requests.auth import HTTPBasicAuth

from logstash_async.constants import constants
from logstash_async.utils import ichunked


logger = logging.getLogger(__name__)


class TimeoutNotSet:
    pass


class Transport(ABC):
    """The :class:`Transport <Transport>` is the abstract base class of
    all transport protocols.

    :param host: The name of the host.
    :type host: str
    :param port: The TCP/UDP port.
    :type port: int
    :param timeout: The connection timeout.
    :type timeout: None or float
    :param ssl_enable: Activates TLS.
    :type ssl_enable: bool
    :param ssl_verify: Activates the TLS certificate verification.
    :type ssl_verify: bool or str
    :param use_logging: Use logging for debugging.
    :type use_logging: bool
    """

    def __init__(
            self,
            host: str,
            port: int,
            timeout: Union[None, float],
            ssl_enable: bool,
            ssl_verify: Union[bool, str],
            use_logging: bool,
    ):
        self._host = host
        self._port = port
        self._timeout = None if timeout is TimeoutNotSet else timeout
        self._ssl_enable = ssl_enable
        self._ssl_verify = ssl_verify
        self._use_logging = use_logging
        super().__init__()

    @abstractmethod
    def send(self, events: list, **kwargs):
        pass

    @abstractmethod
    def close(self):
        pass


class UdpTransport:

    _keep_connection = False

    # ----------------------------------------------------------------------
    # pylint: disable=unused-argument
    def __init__(self, host, port, timeout=TimeoutNotSet, **kwargs):
        self._host = host
        self._port = port
        self._timeout = timeout
        self._sock = None

    # ----------------------------------------------------------------------
    def send(self, events, use_logging=False):  # pylint: disable=unused-argument
        # Ideally we would keep the socket open but this is risky because we might not notice
        # a broken TCP connection and send events into the dark.
        # On UDP we push into the dark by design :)
        self._create_socket()
        try:
            self._send(events)
        finally:
            self._close()

    # ----------------------------------------------------------------------
    def _create_socket(self):
        if self._sock is not None:
            return

        # from logging.handlers.DatagramHandler
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self._timeout is not TimeoutNotSet:
            self._sock.settimeout(self._timeout)

    # ----------------------------------------------------------------------
    def _send(self, events):
        for event in events:
            self._send_via_socket(event)

    # ----------------------------------------------------------------------
    def _send_via_socket(self, data):
        data_to_send = self._convert_data_to_send(data)
        self._sock.sendto(data_to_send, (self._host, self._port))

    # ----------------------------------------------------------------------
    def _convert_data_to_send(self, data):
        if not isinstance(data, bytes):
            return bytes(data, 'utf-8')

        return data

    # ----------------------------------------------------------------------
    def _close(self, force=False):
        if not self._keep_connection or force:
            if self._sock:
                try:
                    self._wait_for_socket_buffer_empty()
                    self._try_to_close_socket()
                finally:
                    self._sock = None

    # ----------------------------------------------------------------------
    def _wait_for_socket_buffer_empty(self):
        wait_timeout = constants.SOCKET_CLOSE_WAIT_TIMEOUT
        interval = 0.05
        time_waited = 0
        # wait until the socket's write buffer is empty
        # but do not wait longer than SOCKET_CLOSE_WAIT_TIMEOUT
        while time_waited < wait_timeout and not self._is_sock_write_buff_empty():
            time_waited += interval
            time.sleep(interval)

    # ----------------------------------------------------------------------
    def _is_sock_write_buff_empty(self):
        if fcntl is None:
            return True

        socket_fd = self._sock.fileno()
        buffer_size = struct.pack('I', 0)
        ioctl_result = fcntl.ioctl(socket_fd, termios.TIOCOUTQ, buffer_size)
        buffer_size = struct.unpack('I', ioctl_result)[0]
        return not buffer_size

    # ----------------------------------------------------------------------
    def _try_to_close_socket(self):
        try:
            self._sock.shutdown(socket.SHUT_WR)
            self._sock.close()
        except Exception as exc:
            self._log_close_socket_error(exc)

    # ----------------------------------------------------------------------
    def _log_close_socket_error(self, exc):
        msg = f'Error on closing the transport socket: {exc}'
        logger.warning(msg)

    # ----------------------------------------------------------------------
    def close(self):
        self._close(force=True)


class TcpTransport(UdpTransport):

    # ----------------------------------------------------------------------
    def __init__(  # pylint: disable=too-many-arguments
            self,
            host,
            port,
            ssl_enable,
            ssl_verify,
            keyfile,
            certfile,
            ca_certs,
            timeout=TimeoutNotSet,
            **kwargs):
        super().__init__(host, port)
        self._ssl_enable = ssl_enable
        self._ssl_verify = ssl_verify
        self._keyfile = keyfile
        self._certfile = certfile
        self._ca_certs = ca_certs
        self._timeout = timeout

    # ----------------------------------------------------------------------
    def _create_socket(self):
        if self._sock is not None:
            return

        # from logging.handlers.SocketHandler
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self._timeout is not TimeoutNotSet:
            self._sock.settimeout(self._timeout)

        try:
            self._sock.connect((self._host, self._port))
            # non-SSL
            if not self._ssl_enable:
                return
            # SSL
            cert_reqs = ssl.CERT_REQUIRED
            ssl_context = ssl.create_default_context(cafile=self._ca_certs)
            if not self._ssl_verify:
                cert_reqs = ssl.CERT_OPTIONAL if self._ca_certs else ssl.CERT_NONE

            ssl_context.check_hostname = False
            ssl_context.verify_mode = cert_reqs
            if self._certfile and self._keyfile:
                ssl_context.load_cert_chain(self._certfile, self._keyfile)
            self._sock = ssl_context.wrap_socket(self._sock, server_side=False)
        except OSError:
            self._close()
            raise

    # ----------------------------------------------------------------------
    def _send_via_socket(self, data):
        data_to_send = self._convert_data_to_send(data)
        self._sock.sendall(data_to_send)


class BeatsTransport:

    # ----------------------------------------------------------------------
    def __init__(  # pylint: disable=too-many-arguments
            self,
            host,
            port,
            ssl_enable,
            ssl_verify,
            keyfile,
            certfile,
            ca_certs,
            timeout=TimeoutNotSet,
            **kwargs):
        timeout_ = None if timeout is TimeoutNotSet else timeout
        self._client_arguments = dict(
            host=host,
            port=port,
            timeout=timeout_,
            ssl_enable=ssl_enable,
            ssl_verify=ssl_verify,
            keyfile=keyfile,
            certfile=certfile,
            ca_certs=ca_certs,
            **kwargs)

    # ----------------------------------------------------------------------
    def close(self):
        pass  # nothing to do

    # ----------------------------------------------------------------------
    def send(self, events, use_logging=False):
        client = pylogbeat.PyLogBeatClient(use_logging=use_logging, **self._client_arguments)
        with client:
            for events_subset in ichunked(events, constants.QUEUED_EVENTS_BEATS_BATCH_SIZE):
                client.send(events_subset)


class HttpTransport(Transport):
    """The :class:`HttpTransport <HttpTransport>` implements a client for the
    logstash plugin `inputs_http`.

    For more details visit:
    https://www.elastic.co/guide/en/logstash/current/plugins-inputs-http.html

    :param host: The hostname of the logstash HTTP server.
    :type host: str
    :param port: The TCP port of the logstash HTTP server.
    :type port: int
    :param path: The path of the logstash HTTP server.
    :type path: str
    :param timeout: The connection timeout. (Default: None)
    :type timeout: float
    :param ssl_enable: Activates TLS. (Default: True)
    :type ssl_enable: bool
    :param ssl_verify: Activates the TLS certificate verification. If the flag
    is True the class tries to verify the TLS certificate with certifi. If you
    pass a string with a file location to CA certificate the class tries to
    validate it against it. (Default: True)
    :type ssl_verify: bool or str
    :param use_logging: Use logging for debugging.
    :type use_logging: bool
    :param username: Username for basic authorization. (Default: "")
    :type username: str
    :param password: Password for basic authorization. (Default: "")
    :type password: str
    :param max_content_length: The max content of an HTTP request in bytes.
    (Default: 100MB)
    :type max_content_length: int
    """

    def __init__(
            self,
            host: str,
            port: int,
            timeout: Union[None, float] = TimeoutNotSet,
            ssl_enable: bool = True,
            ssl_verify: Union[bool, str] = True,
            use_logging: bool = False,
            path: str = '',
            **kwargs
    ):
        super().__init__(host, port, timeout, ssl_enable, ssl_verify, use_logging)
        self._username = kwargs.get('username')
        self._password = kwargs.get('password')
        self._max_content_length = kwargs.get('max_content_length', 100 * 1024 * 1024)
        self._path = path
        self.__session = None

    @property
    def url(self) -> str:
        """The URL of the logstash pipeline based on the hostname, the port and
        the TLS usage.

        :return: The URL of the logstash HTTP pipeline.
        :rtype: str
        """
        protocol = 'http'
        if self._ssl_enable:
            protocol = 'https'
        return f'{protocol}://{self._host}:{self._port}/{self._path}'

    def __batches(self, events: list) -> Iterator[list]:
        """Generate dynamic sized batches based on the max content length.

        :param events: A list of events.
        :type events: list
        :return: A iterator which generates batches of events.
        :rtype: Iterator[list]
        """
        current_batch = []
        event_iter = iter(events)
        while True:
            try:
                current_event = next(event_iter)
            except StopIteration:
                current_event = None
                if not current_batch:
                    return
                yield current_batch
            if current_event is None:
                return
            if len(current_event) > self._max_content_length:
                msg = 'The event size <%s> is greater than the max content length <%s>.'
                msg += 'Skipping event.'
                if self._use_logging:
                    logger.warning(msg, len(current_event), self._max_content_length)
                continue
            obj = json.loads(current_event)
            content_length = len(json.dumps(current_batch + [obj]).encode('utf8'))
            if content_length > self._max_content_length:
                batch = current_batch
                current_batch = [obj]
                yield batch
            else:
                current_batch += [obj]

    def __auth(self) -> HTTPBasicAuth:
        """The authentication method for the logstash pipeline. If the username
        or the password is not set correctly it will return None.

        :return: A HTTP basic auth object or None.
        :rtype: HTTPBasicAuth
        """
        if self._username is None or self._password is None:
            return None
        return HTTPBasicAuth(self._username, self._password)

    def close(self) -> None:
        """Close the HTTP session.
        """
        if self.__session is not None:
            self.__session.close()

    def send(self, events: list, **kwargs):
        """Send events to the logstash pipeline.

        Max Events: `logstash_async.Constants.QUEUED_EVENTS_BATCH_SIZE`
        Max Content Length: `HttpTransport._max_content_length`

        The method receives a list of events from the worker. It tries to send
        as much of the events as possible in one request. If the total size of
        the received events is greater than the maximal content length the
        events will be divide into batches.

        :param events: A list of events
        :type events: list
        """
        self.__session = requests.Session()
        for batch in self.__batches(events):
            if self._use_logging:
                logger.debug('Batch length: %s, Batch size: %s',
                             len(batch), len(json.dumps(batch).encode('utf8')))
            response = self.__session.post(
                self.url,
                headers={'Content-Type': 'application/json'},
                json=batch,
                verify=self._ssl_verify,
                timeout=self._timeout,
                auth=self.__auth())
            if response.status_code != 200:
                self.close()
                response.raise_for_status()
        self.close()
