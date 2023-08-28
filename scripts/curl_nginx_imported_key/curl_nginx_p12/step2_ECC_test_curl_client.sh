#!/bin/bash
source config.sh


set -e

#~ ## Using External public key
echo "Client1:-----> test curl client ECC with 0xe0f1:client1_pubkey.pem "
OPENSSL_CONF=openssl_curl.cnf curl -v --engine trustm_engine --key-type ENG --key "0x${TARGET_OID}:${TEMP_PUBKEY_KEY}" --cert $TEMP_CERT --cacert $CA_CERT https://127.0.0.1
