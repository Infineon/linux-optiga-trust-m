#!/bin/bash
source config.sh
set -e

echo "Client1:-----> Extracting public key in PEM and DER from certificate"
openssl x509 -pubkey -noout -in client1_rsa.crt.pem  > temp_pubkey_rsa.pem
openssl x509 -pubkey -noout -in client1_rsa.crt.pem | openssl enc -base64 -d > temp_pubkey_rsa.der



#~ echo "Client1:-----> Preparing RSA priavte key for private exponent editing "
#~ openssl rsa -inform pem -in client1_rsa_privkey.pem -outform der -out client1_rsa_privkey.der
#~ openssl rsa -in client1_rsa_privkey.der -text -inform DER -noout
#~ cp client1_rsa_privkey.der rsa_pkey_e0fc.der

#Note: modify private exponent as follow
#privateExponent:
#    00:e0:fc:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
#    00:00
#~ echo "Client1:-----> convert modified DER private key back to PEM "
#~ openssl rsa -inform der -in rsa_pkey_e0fc.der -outform pem -out rsa_pkey_e0fc.pem

openssl rsa -in rsa_pkey_e0fc.pem -text -inform PEM -noout
echo "Client1:-----> Generate customed private key OID P12"
openssl pkcs12 -export -out client1_rsa.p12 -password pass:1234 -inkey rsa_pkey_e0fc.pem -in client1_rsa.crt.pem

cp client1_rsa.p12 ../
cp temp_pubkey_rsa.der ../
