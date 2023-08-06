#!/bin/bash
source config.sh


rm *.pem

set -e



echo "Server1: -----> Generate Server ECC Private Key"
openssl ecparam -out server1_privkey.pem -name prime256v1 -genkey
echo "Server1:-----> Generate Server ECC Keys CSR"
openssl req -new  -key server1_privkey.pem -subj /CN=127.0.0.1/O=Infineon/C=SG -out $SERVER_CSR
echo "Server1:-----> Generate Server cetificate by using CA"
openssl x509 -req -in $SERVER_CSR -CA $CA_CERT  -CAkey $CA_KEY -CAcreateserial -out $SERVER_CERT_NAME -days 3650 -sha256 -extfile openssl.cnf -extensions cert_ext
#~ openssl x509 -in server1.crt -text -purpose



echo "Client1:-----> Creates new key length and Auth/Enc/Sign usage and generate a certificate request"
openssl req -keyform engine -engine trustm_engine -key $KEY_GEN -new -out $CLIENT_CSR -subj "/CN=TrustM/O=Infineon/C=SG"


echo "Client1:-----> Generate Client cetificate by using CA"
openssl x509 -req -in $CLIENT_CSR -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out $CLIENT_CERT_NAME -days 3650 -sha256 -extfile openssl.cnf -extensions cert_ext1
#~ openssl x509 -in $CLIENT_CERT_NAME -text -purpose




