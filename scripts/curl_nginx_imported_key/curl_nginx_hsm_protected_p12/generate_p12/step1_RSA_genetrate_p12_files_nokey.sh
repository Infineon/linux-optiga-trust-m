#!/bin/bash
source config.sh

set -e

echo "Client1:-----> Extracting public key in PEM and DER from certificate"
openssl x509 -pubkey -noout -in client1_rsa.crt.pem  > temp_pubkey_rsa.pem
openssl x509 -pubkey -noout -in client1_rsa.crt.pem | openssl enc -base64 -d > temp_pubkey_rsa.der

echo "Client1:-----> Generate p12 file without key inside"
openssl pkcs12 -nodes -export -nokeys -password  pass:1234 -in client1_rsa.crt.pem -out e0fc.p12
openssl pkcs12 -info -in e0fc.p12 -password  pass:1234
echo "Client1:-----> Copy p12 file to destination"
cp e0fc.p12 ../
#~ cp temp_pubkey.pem ../
cp temp_pubkey_rsa.der ../
