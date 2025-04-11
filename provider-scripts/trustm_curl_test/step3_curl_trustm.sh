#!/usr/bin/env sh

OPENSSL_CONF=cert_ext_trustm.cnf curl \
  --cacert ca/ca.cert.pem \
  --cert client1.crt \
  --key client1.key \
  --verbose \
  https://127.0.0.1:5000/
