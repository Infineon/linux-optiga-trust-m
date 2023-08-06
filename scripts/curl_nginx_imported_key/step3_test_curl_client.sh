#!/bin/bash
source config.sh


set -e
echo "Client1:-----> test curl client"
curl -v --engine trustm_engine --key-type ENG --key $KEY_OID --cert $CLIENT_CERT_NAME --cacert $CA_CERT https://127.0.0.1
