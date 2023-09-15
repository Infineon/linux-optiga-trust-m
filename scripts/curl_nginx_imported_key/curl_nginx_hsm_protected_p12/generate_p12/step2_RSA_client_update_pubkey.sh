#!/bin/bash
source config.sh


set -e

echo "Client1:-----> Extracting public key in PEM and DER from certificate"
openssl x509 -pubkey -noout -in client1.crt.pem  > client1_pubkey.pem
openssl x509 -pubkey -noout -in client1.crt.pem | openssl enc -base64 -d > client1_pubkey.der


echo "Client1:-----> Update Public key into Optiga Trust M"
$EXEPATH/trustm_data -w $TRUST_M_RSA_PUBKEY_OID -i client1_pubkey.der -e
