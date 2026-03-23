#!/bin/bash
source config.sh

set -e

echo "Performing protected update of RSA key to OID 0x$TARGET_RSA_OID"
$EXEPATH/trustm_protected_update_rsakey -k 0x$TARGET_RSA_OID -f rsa_fragment.dat -m rsa_manifest.dat 
echo "Save rsa public key into OID 0x$RSA_PUBKEY_OID"
$EXEPATH/trustm_data -w 0x$RSA_PUBKEY_OID -i "$RSA_PUBKEY_TO_UPDATE" -e
