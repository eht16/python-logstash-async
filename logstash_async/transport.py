# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from abc import ABC, abstractmethod
from time import sleep
from typing import Union
import json
import random
import socket
import ssl

from requests.auth import HTTPBasicAuth
import pylogbeat
import requests

from logstash_async.utils import ichunked


class Transport(ABC):
    """The :class:`Transport <Transport>` is the abstract base class of
    all transport protocols.

    :param host: The name of the host
    :type host: str
    :param port: The port number of the service
    :type port: int
    :param timeout: The timeout for the connection
    :type timeout: float
    :param codec: The codec which will be used to de/encode the data (eg. plain
    or json)
    :type codec: str
    :param ssl_enable: Use TLS for the transport (Default: True)
    :type ssl_enable: bool
    :param ssl_verify: If True the class tries to verify the TLS certificate
    with certifi. If you pass a string with a file location to CA certificate
    the class tries to validate it against it. (Default: True)
    :type ssl_verify: bool or str
    """

    def __init__(
            self,
            host: str,
            port: int,
            timeout: float,
            codec: str,
            ssl_enable: bool = True,
            ssl_verify: bool = True
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.codec = codec
        self.ssl_enable = ssl_enable
        self.ssl_verify = ssl_verify
        super().__init__()

    @property
    def host(self) -> str:
        """host
        :param name: The name of the host
        :type name: str
        :return: The current name of the host
        :rtype: str
        """
        return self.__host

    @host.setter
    def host(self, name: str) -> None:
        self.__host = name

    @property
    def port(self) -> int:
        """port
        :param number: The port number of the service
        :type number: int
        :return: The current port number
        :rtype: int
        """
        return self.__port

    @port.setter
    def port(self, number: int) -> None:
        self.__port = number

    @property
    def timeout(self) -> float:
        """timout
        :param time: The waiting time for a response.
        :type time: float
        :return: The current timeout
        :rtype: float
        """
        return self.__timeout

    @timeout.setter
    def timeout(self, time: float) -> None:
        self.__timeout = time

    @property
    def codec(self) -> str:
        """codec
        :param name: The codec which will be used to transform the data
        :type name: str
        :return: The current codec
        :rtype: str
        """
        return self.__codec

    @codec.setter
    def codec(self, name: str) -> None:
        self.__codec = name

    @property
    def ssl_enable(self) -> bool:
        """ssl_enable
        :param use: Enables or disables the TLS usage
        :type use: bool
        :return: False if TLS is disabled and True if TLS enabled
        :rtype: bool
        """
        return self.__ssl_enable

    @ssl_enable.setter
    def ssl_enable(self, use: bool) -> None:
        self.__ssl_enable = use

    @property
    def ssl_verify(self) -> Union[bool, str]:
        """ssl_verify
        :param use: Enables or disables the verification of the TLS certificate
        :type use: bool or str
        :return: False if the certificate should be not verified and in case of
        a verification True or the path to a CA_BUNDLED file with with
        certificates of trusted CAs.
        :rtype: bool or str
        """
        return self.__ssl_verify

    @ssl_verify.setter
    def ssl_verify(self, use: Union[bool, str]) -> None:
        self.__ssl_verify = use

    @abstractmethod
    def send(self, events: list, **kwargs: dict):
        pass

    @abstractmethod
    def close(self):
        pass


class TimeoutNotSet:
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
                self._sock.close()
                self._sock = None

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
            timeout=TimeoutNotSet):
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
            if not self._ssl_verify:
                if self._ca_certs:
                    cert_reqs = ssl.CERT_OPTIONAL
                else:
                    cert_reqs = ssl.CERT_NONE
            self._sock = ssl.wrap_socket(
                self._sock,
                keyfile=self._keyfile,
                certfile=self._certfile,
                ca_certs=self._ca_certs,
                cert_reqs=cert_reqs)
        except socket.error:
            self._close()
            raise

    # ----------------------------------------------------------------------
    def _send_via_socket(self, data):
        data_to_send = self._convert_data_to_send(data)
        self._sock.sendall(data_to_send)


class BeatsTransport:

    _batch_size = 10

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
            timeout=TimeoutNotSet):
        timeout_ = None if timeout is TimeoutNotSet else timeout
        self._client_arguments = dict(
            host=host,
            port=port,
            timeout=timeout_,
            ssl_enable=ssl_enable,
            ssl_verify=ssl_verify,
            keyfile=keyfile,
            certfile=certfile,
            ca_certs=ca_certs)

    # ----------------------------------------------------------------------
    def close(self):
        pass  # nothing to do

    # ----------------------------------------------------------------------
    def send(self, events, use_logging=False):
        client = pylogbeat.PyLogBeatClient(use_logging=use_logging, **self._client_arguments)
        with client:
            for events_subset in ichunked(events, self._batch_size):
                client.send(events_subset)


class HttpTransport(Transport):
    """The :class:`HttpTransport <HttpTransport>` implements a client for the
    logstash plugin `inputs_http`.

    For more details visit:
    https://www.elastic.co/guide/en/logstash/current/plugins-inputs-http.html

    :param host: The name of the host
    :type host: str
    :param port: The port number of the service
    :type port: int
    :param timeout: The timeout for the connection (Default: 2.0 seconds)
    :type timeout: float
    :param codec: The codec which will be used to de/encode the data. Besides
    json everthing defaults to plain. (Default: json)
    :type codec: str
    :param ssl_enable: Use TLS for the transport (Default: True)
    :type ssl_enable: bool
    :param ssl_verify: If True the class tries to verify the TLS certificate
    with certifi. If you pass a string with a file location to CA certificate
    the class tries to validate it against it. (Default: True)
    :type ssl_verify: bool or str
    :param username: Username for basic authorization (Default: "")
    :type username: str
    :param password: Password for basic authorization (Default: "")
    :type password: str
    """

    def __init__(
            self,
            host: str,
            port: int,
            timeout: float = 2.0,
            codec: str = "json",
            ssl_enable: bool = True,
            ssl_verify: bool = True,
            **kwargs
    ):
        super().__init__(host, port, timeout, codec, ssl_enable, ssl_verify)
        self.username = kwargs.get("username", None)
        self.password = kwargs.get("password", None)
        self.__session = None
        self.__max_attempts = 3

    @property
    def username(self) -> Union[None, str]:
        """username
        :param name: The name of the user
        :type name: str
        :return: The current name of the user or None
        :rtype: None or str
        """
        return self.__username

    @username.setter
    def username(self, name: Union[None, str]) -> None:
        self.__username = name

    @property
    def password(self) -> Union[None, str]:
        """password
        :param word: The password of the user
        :type word: str
        :return: The current password or None
        :rtype: None or str
        """
        return self.__password

    @password.setter
    def password(self, word: Union[None, str]) -> None:
        self.__password = word

    @property
    def url(self) -> str:
        """The URL of the logstash pipeline based on the hostname, the port and
        the TLS usage.

        :return: The URL of the logstash pipeline
        :rtype: str
        """
        protocol = "http"
        if self.ssl_enable:
            protocol = "https"
        return f"{protocol}://{self.host}:{self.port}"

    def __auth(self):
        """The authentication method for the logstash pipeline. If the username
        or the password is not set correctly it will return None.

        :return: A HTTP basic auth object or None
        :rtype: HTTPBasicAuth
        """
        if self.username is None or self.password is None:
            return None
        return HTTPBasicAuth(self.username, self.password)

    @property
    def headers(self) -> dict:
        """The headers of the HTTP request

        :return: A dictionary with HTTP header fields
        :rtype: dict
        """
        request_headers = {
            "Content-Type": "text/plain",
        }
        if self.codec is None:
            return request_headers
        if self.codec.lower == "json":
            request_headers["Content-Type"] = "application/json"
        return request_headers

    def encode(self, data: bytes) -> str:
        """Encodes the data based on the chosen codec

        :param data: The input data
        :type data: bytes
        :return: The encoded data
        :rtype: str
        """
        if self.codec is None or data is None:
            return data
        string = data.decode("utf-8")
        if self.codec.lower() == "json":
            return json.loads(string)
        return string

    def close(self) -> None:
        """The HTTP connection does not need to be closed because it's
        stateless.
        """
        if self.__session is not None:
            self.__session.close()

    def __backoff(self, attempt, cap: int = 3000, base: int = 10):
        return random.randrange(0, min(cap, base * 2 ** attempt))

    def send(self, events: list, **kwargs: dict) -> None:
        """Send events to the logstash pipeline

        :param events: A list of events
        :type events: list
        :param use_logging: Not used!
        :type use_logging: bool
        """
        self.__session = requests.Session()
        if self.__auth() is not None:
            self.__session.auth = self.__auth()
        self.__session.verify = self.ssl_verify
        for event in events:
            attempt = 0
            while attempt < self.__max_attempts:
                if self.codec.lower() == "json":
                    response = requests.post(
                        self.url, json=self.encode(event), headers=self.headers)
                else:
                    response = requests.post(
                        self.url, data=self.encode(event), headers=self.headers)
                status_code = response.status_code
                if status_code == 200:
                    break
                if status_code == 429:
                    sleep(self.__backoff(attempt))
                    attempt += 1
                else:
                    self.close()
                    error_msg = f"Logstash respond with error {status_code}"
                    raise RuntimeError(error_msg)
        self.close()
