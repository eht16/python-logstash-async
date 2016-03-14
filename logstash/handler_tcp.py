import ssl
from logging.handlers import SocketHandler
from logstash import formatter


# Derive from object to force a new-style class and thus allow super() to work
# on Python 2.6
class TCPLogstashHandler(SocketHandler, object):
    """Python logging handler for Logstash. Sends events over TCP.
    :param host: The host of the logstash server.
    :param port: The port of the logstash server (default 5959).
    :param message_type: The type of the message (default logstash).
    :param fqdn; Indicates whether to show fully qualified domain name or not (default False).
    :param version: version of logstash event schema (default is 0).
    :param tags: list of tags for a logger (default is None).
    :param ssl: Should SSL be enabled for the connection? Default is True.
    :param ssl_verify: Should the server's SSL certificate be verified?
    :param keyfile: The path to client side SSL key file (default is None).
    :param certfile: The path to client side SSL certificate file (default is None).
    :param ca_certs: The path to the file containing recognised CA certificates.
    """

    def __init__(self, host, port=5959, message_type='logstash', tags=None, fqdn=False, version=0, ssl=True, ssl_verify=True, keyfile=None, certfile=None, ca_certs=None):
        super(TCPLogstashHandler, self).__init__(host, port)

        self.ssl = ssl
        self.ssl_verify = ssl_verify
        self.keyfile = keyfile
        self.certfile = certfile
        self.ca_certs = ca_certs

        if version == 1:
            self.formatter = formatter.LogstashFormatterVersion1(message_type, tags, fqdn)
        else:
            self.formatter = formatter.LogstashFormatterVersion0(message_type, tags, fqdn)

    def makePickle(self, record):
        return self.formatter.format(record) + b'\n'

    def makeSocket(self, timeout=1):
        s = super(TCPLogstashHandler, self).makeSocket(timeout)
        cert_reqs = ssl.CERT_REQUIRED
        if not self.ssl_verify:
            if self.ca_certs:
                cert_reqs = ssl.CERT_OPTIONAL
            else:
                cert_reqs = ssl.CERT_NONE

        if self.ssl:
            return ssl.wrap_socket(s, keyfile=self.keyfile, certfile=self.certfile, ca_certs=self.ca_certs, cert_reqs=cert_reqs)
        return s
