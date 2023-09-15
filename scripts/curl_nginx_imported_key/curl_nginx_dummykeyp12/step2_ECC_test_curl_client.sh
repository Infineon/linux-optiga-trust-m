#!/bin/bash
source config.sh


set -e

#~ ## Using External public key
echo "Client1:-----> test curl client ECC with p12 with dummy key"export 
export OPENSSL_CONF=/etc/ssl/openssl_curl.cnf 
curl -v --cert-type P12 --cert client1.p12:1234 --cacert $CA_CERT https://127.0.0.1
