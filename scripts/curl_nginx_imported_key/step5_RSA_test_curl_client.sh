#!/bin/bash
source config.sh


set -e
## Using internal public key
echo "Client1:-----> test curl client RSA with 0xe0fc:^ "
curl -v --engine trustm_engine --key-type ENG --key $TRUST_M_RSA_KEY_OID --cert $CLIENT_CERT_NAME --cacert $CA_CERT https://127.0.0.1

## Using External public key
#~ echo "Client1:-----> test curl client RSA with 0xe0fc:client1_pubkey.pem "
#~ curl -v --engine trustm_engine --key-type ENG --key $TRUST_M_RSA_KEY_EXT_OID --cert $CLIENT_CERT_NAME --cacert $CA_CERT https://127.0.0.1
