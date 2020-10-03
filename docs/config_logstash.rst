.. _logstash-config:

Example Logstash Configuration
------------------------------

Example ``logstash.conf`` for unencrypted TCP transport::

    input {
        tcp {
            host => "127.0.0.1"
            port => 5959
            mode => server
            codec => json_lines {}
        }
    }


Example ``logstash.conf`` for SSL-encrypted TCP transport::

    input {
        tcp {
            host => "127.0.0.1"
            port => 5958
            mode => server
            codec => json_lines {}

            ssl_enable => true
            ssl_verify => true
            ssl_extra_chain_certs => ["/etc/ssl/certs/logstash_ca.crt"]
            ssl_cert => "/etc/ssl/certs/logstash.crt"
            ssl_key => "/etc/ssl/private/logstash.key"
        }
    }


Example ``logstash.conf`` for SSL-encrypted Beats transport::

    input {
        beats {
            host            => "127.0.0.1"
            port            => 5957
            ssl             => true
            ssl             => true
            ssl_verify_mode => "peer"
            ssl_certificate_authorities => ["/etc/ssl/certs/logstash_ca.crt"]
            ssl_certificate => "/etc/ssl/certs/logstash.crt"
            ssl_key         => "/etc/ssl/private/logstash.p8"
        }
    }


Example ``logstash.conf`` for HTTP transport with basic authentication::

  input {
      http {
          host      => "127.0.0.1"
          port      => 5959
          user      => "logstash"
          password  => "testing"
          codec     => "json"
      }
  }
