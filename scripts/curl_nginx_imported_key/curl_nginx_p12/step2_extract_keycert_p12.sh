#!/bin/bash
source config.sh



set -e

echo "Client1:-----> Exporting the private key from PKCS12 file"
openssl pkcs12 -in $CLIENT_PKCS12_FILE -nodes -nocerts | openssl ec -out $TEMP_KEY
echo "Client1:-----> Exporting the certificate from PKCS12 file"
openssl pkcs12 -in $CLIENT_PKCS12_FILE -nokeys -out $TEMP_CERT 
echo "Client1:-----> Extracting public key in PEM and DER from certificate"
openssl x509 -pubkey -noout -in $TEMP_CERT  > $TEMP_PUBKEY_KEY
openssl x509 -pubkey -noout -in $TEMP_CERT | openssl enc -base64 -d > $TEMP_PUBKEY_KEY_DER










