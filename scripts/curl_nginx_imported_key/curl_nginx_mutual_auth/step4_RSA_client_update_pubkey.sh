#!/bin/bash
source config.sh


set -e
echo "Client1:-----> Update Public key into Optiga Trust M"
$EXEPATH/trustm_data -w $TRUST_M_RSA_PUBKEY_OID -i client1_pubkey.der -e
