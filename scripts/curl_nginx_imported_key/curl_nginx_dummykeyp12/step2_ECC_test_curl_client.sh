#!/bin/bash
source config.sh


set -e

echo "Export openssl_curl.cnf"
sudo cp openssl_curl.cnf /etc/ssl/openssl_curl.cnf
export OPENSSL_CONF=/etc/ssl/openssl_curl.cnf 

echo "Client1:-----> test curl client ECC with p12 with dummy key"
curl -v --cert-type P12 --cert client1_ecc.p12:1234 --cacert $CA_CERT https://127.0.0.1
