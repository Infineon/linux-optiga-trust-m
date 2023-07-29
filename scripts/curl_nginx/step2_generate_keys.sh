#!/bin/bash
source config.sh
SERVER_CERT_NAME=server1.crt.pem
SERVER_PRIVATE_KEY=server1_privkey.pem
CLIENT_CERT_NAME=client1.crt.pem

rm *.pem

set -e

echo "Server1: -----> Generate Server ECC Private Key"
openssl ecparam -out server1_privkey.pem -name prime256v1 -genkey
openssl req -new -x509 -key $SERVER_PRIVATE_KEY -subj "/CN=Server/O=Infineon/C=SG" -out $SERVER_CERT_NAME

echo "Client1:-----> Generate Client Trust M Key with Engine"

openssl req -new -x509 -engine trustm_engine -keyform engine -key 0xe0f1:^:NEW:0x03:0x13 -subj "/CN=TrustM/O=Infineon/C=SG" -out $CLIENT_CERT_NAME
#~openssl req -new -x509 -engine trustm_engine -keyform engine -key 0xe0fc:^:NEW:0x42:0x13 -subj "/CN=TrustM/O=Infineon/C=SG" -out $CLIENT_CERT_NAME

#~openssl x509 -in $CERT_NAME -text -purpose


