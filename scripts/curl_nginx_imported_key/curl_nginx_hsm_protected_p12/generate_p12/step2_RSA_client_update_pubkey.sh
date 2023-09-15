#!/bin/bash
source config.sh


set -e

echo "Client1:-----> Extracting public key in PEM and DER from certificate"
openssl x509 -pubkey -noout -in client1_rsa.crt.pem  > client1_rsa_pubkey.pem
openssl x509 -pubkey -noout -in client1_rsa.crt.pem | openssl enc -base64 -d > client1_rsa_pubkey.der


echo "Client1:-----> Update Public key into Optiga Trust M"
$EXEPATH/trustm_data -w 0xf1e0 -i client1_rsa_pubkey.der -e
