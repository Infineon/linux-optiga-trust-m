#!/bin/bash
source config.sh


set -e

#~ ## Using External public key
echo "Client1:-----> test curl client ECC with p12 with dummy key"
OPENSSL_CONF=openssl_curl.cnf curl -v --cert-type P12 --cert client1.p12 --cacert $CA_CERT https://127.0.0.1
