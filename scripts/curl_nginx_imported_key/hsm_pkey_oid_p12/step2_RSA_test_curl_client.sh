#!/bin/bash
source config.sh


set -e


echo "Trust M protected P12 with Key OID(RSA2048)"

sudo cp openssl_curl_rsa.cnf /etc/ssl/openssl_curl_rsa.cnf

export OPENSSL_CONF=/etc/ssl/openssl_curl_rsa.cnf  

echo "Client1:-----> test curl client RSA with 0xe0fc:^ "
curl -v --tls-max 1.2 --cert-type P12  --cert client1_rsa.p12:1234 --cacert $CA_CERT https://127.0.0.1

