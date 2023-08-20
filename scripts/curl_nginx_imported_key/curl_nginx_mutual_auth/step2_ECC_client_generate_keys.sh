#!/bin/bash
source config.sh



set -e


echo "Client1: -----> Generate Client ECC Private Key"
openssl ecparam -out $CLIENT_PRIVATE_KEY -name prime256v1 -genkey
echo "Client1:-----> Generate Client ECC Keys CSR"
openssl req -new  -key $CLIENT_PRIVATE_KEY -subj "/CN=TrustM/O=Infineon/C=SG" -out $CLIENT_CSR
echo "Client1:-----> Generate Client cetificate by using CA"
openssl x509 -req -in $CLIENT_CSR -CA $CA_CERT  -CAkey $CA_KEY -CAcreateserial -out $CLIENT_CERT_NAME -days 3650 -sha256 -extfile openssl.cnf -extensions cert_ext1
echo "Client1:-----> Extracting public key in PEM and DER from certificate"
openssl x509 -pubkey -noout -in $CLIENT_CERT_NAME  > $CLIENT_PUBKEY_KEY
openssl x509 -pubkey -noout -in $CLIENT_CERT_NAME | openssl enc -base64 -d > $CLIENT_PUBKEY_KEY_DER










