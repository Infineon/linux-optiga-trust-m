#!/bin/bash
source config.sh

set -e
echo "Client1:-----> Extracting public key in PEM and DER from certificate"
openssl x509 -pubkey -noout -in client1_ecc.crt.pem  > temp_pubkey_ecc.pem
openssl x509 -pubkey -noout -in client1_ecc.crt.pem | openssl enc -base64 -d > temp_pubkey_ecc.der

echo "Client1:-----> Generate p12 file without key inside"
openssl pkcs12 -nodes -export -nokeys -password  pass:1234 -in client1_ecc.crt.pem -out e0f1.p12
openssl pkcs12 -info -in e0f1.p12 -password  pass:1234
echo "Client1:-----> Copy p12 file to destination"
cp e0f1.p12 ../
#~ cp temp_pubkey.pem ../
cp temp_pubkey_ecc.der ../

