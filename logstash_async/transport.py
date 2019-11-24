# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

import socket
import ssl
import sys

import pylogbeat

from logstash_async.utils import ichunked


class TimeoutNotSet(object):
    pass


class UdpTransport(object):

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
        if sys.version_info < (3, 0):
            return data
        # Python3
        elif not isinstance(data, bytes):
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
        super(TcpTransport, self).__init__(host, port)
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


class BeatsTransport(object):

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
        timeout_ = None if timeout is not TimeoutNotSet else timeout
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
