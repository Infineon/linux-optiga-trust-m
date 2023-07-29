#!/bin/bash
source config.sh
SERVER_CERT_NAME=server1.crt.pem
SERVER_PRIVATE_KEY=server1_privkey.pem
CLIENT_CERT_NAME=client1.crt.pem

set -e
echo "Client1:-----> test curl client"
curl --insecure --engine trustm_engine --key-type ENG --key 0xe0f1:^ --cert $CLIENT_CERT_NAME https://127.0.0.1
