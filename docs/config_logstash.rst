.. _logstash-config:

Example Logstash Configuration
------------------------------

Example ``logstash.conf`` for unencrypted TCP transport::

    input {
        tcp {
            host => "127.0.0.1"
            port => 5959
            mode => server
            codec => json
        }
    }


Example ``logstash.conf`` for SSL-encrypted TCP transport::

    input {
        tcp {
            host => "127.0.0.1"
            port => 5958
            mode => server
            codec => json

            ssl_enable => true
            ssl_verify => true
            ssl_extra_chain_certs => ["/etc/ssl/certs/logstash_ca.crt"]
            ssl_cert => "/etc/ssl/certs/logstash.crt"
            ssl_key => "/etc/ssl/private/logstash.key"
        }
    }
