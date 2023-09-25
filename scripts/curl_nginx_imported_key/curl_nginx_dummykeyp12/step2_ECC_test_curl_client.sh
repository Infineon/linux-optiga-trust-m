#!/bin/bash
source config.sh


set -e

echo "Trust M protected P12 with Key OID(ECC256)"
echo "Export openssl_curl.cnf"
sudo cp openssl_curl.cnf /etc/ssl/openssl_curl.cnf
export OPENSSL_CONF=/etc/ssl/openssl_curl.cnf 

echo "Client1:-----> test curl client ECC with 0xe0f1:^ "
curl -v --cert-type P12 --cert client1_ecc.p12:1234 --cacert $CA_CERT https://127.0.0.1
