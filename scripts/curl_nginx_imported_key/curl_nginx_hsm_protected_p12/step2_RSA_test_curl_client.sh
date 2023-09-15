#!/bin/bash
source config.sh


set -e
## Using internal public key
export OPENSSL_CONF=/etc/ssl/openssl_curl_rsa.cnf  

echo "Client1:-----> test curl client RSA with 0xe0fc:^ "
curl -v --engine trustm_engine --tls-max 1.2 --cert-type ENG  --cert e0fc.p12 --cacert $CA_CERT https://127.0.0.1

## Using External public key
#~ echo "Client1:-----> test curl client RSA with 0xe0fc:client1_pubkey.pem "
#~ OPENSSL_CONF=openssl_curl_rsa.cnf curl --tls-max 1.2 -v --engine trustm_engine --key-type ENG --key $TRUST_M_RSA_KEY_EXT_OID --cert $CLIENT_CERT_NAME --cacert $CA_CERT https://127.0.0.1

