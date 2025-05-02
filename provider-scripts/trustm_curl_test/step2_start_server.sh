#!/usr/bin/env sh

. ${PWD}/config.sh

openssl s_server \
  -cert ${SERVER_FILE}.crt \
  -key ${SERVER_FILE}.key \
  -accept 5000 \
  -verify_return_error \
  -Verify 1 \
  -CAfile $CERT_PATH/ca.cert.pem \
  -www
