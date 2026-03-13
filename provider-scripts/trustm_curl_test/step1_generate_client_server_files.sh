#!/usr/bin/env sh

set -eu

. ${PWD}/config.sh

echo "[*] Server1 (without Trust-M):"
openssl ecparam -name prime256v1 -genkey -noout -out ${SERVER_FILE}.key
openssl req -new -key ${SERVER_FILE}.key -config server.cnf -out ${SERVER_FILE}.csr
openssl x509 -req -in ${SERVER_FILE}.csr -CA $CERT_PATH/ca.cert.pem -CAkey $CERT_PATH/ca.key -CAcreateserial -out ${SERVER_FILE}.crt -days 365 -sha256 -extfile server.cnf -extensions req_ext
openssl x509 -in ${SERVER_FILE}.crt -text -noout

echo "[*] Client1:"
openssl pkey -provider trustm_provider -provider default -propquery provider=trustm -in 0xe0f1:*:NEW:0x03:0x13 -out ${CLIENT_FILE}.key
openssl req -new -provider trustm_provider -provider default -key ${CLIENT_FILE}.key -out ${CLIENT_FILE}.csr -subj "/C=SG/CN=TrustM"
openssl x509 -req -in ${CLIENT_FILE}.csr -CA $CERT_PATH/ca.cert.pem -CAkey $CERT_PATH/ca.key -CAcreateserial -out ${CLIENT_FILE}.crt -days 365 -sha256 -extfile cert_ext.cnf -extensions cert_ext
openssl x509 -in ${CLIENT_FILE}.crt -text -noout
