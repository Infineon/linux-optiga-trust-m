#!/bin/bash
source config.sh


set -e
## Using internal public key
#~ echo "Client1:-----> test curl client ECC with 0xe0f1:^ "
#~ OPENSSL_CONF=openssl_curl.cnf curl -v --engine trustm_engine --key-type ENG --key $TRUST_M_ECC_KEY_OID --cert $CLIENT_CERT_NAME --cacert $CA_CERT https://127.0.0.1


#~ ## Using External public key
echo "Client1:-----> test curl client ECC with 0xe0f1:client1_pubkey.pem "
OPENSSL_CONF=openssl_curl.cnf curl -v --engine trustm_engine --key-type ENG --key $TRUST_M_ECC_KEY_EXT_OID --cert $CLIENT_CERT_NAME --cacert $CA_CERT https://127.0.0.1
