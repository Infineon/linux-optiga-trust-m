#!/bin/bash
source config.sh


set -e


echo "Trust M protected P12 without private key(ECC)"
 
sudo cp openssl_curl.cnf /etc/ssl/openssl_curl.cnf

#~ export OPENSSL_CONF=/etc/ssl/openssl_curl.cnf  
echo " Using software P12 file"
curl -v --cert-type P12  --cert client1.p12:1234 --cacert $CA_CERT https://127.0.0.1

echo " Using HSM protected P12 file"
OPENSSL_CONF=/etc/ssl/openssl_curl.cnf curl -v --engine trustm_engine --cert-type ENG  --cert e0f1.p12 --cacert $CA_CERT https://127.0.0.1
