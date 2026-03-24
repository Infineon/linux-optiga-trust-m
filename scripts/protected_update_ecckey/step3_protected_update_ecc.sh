#!/bin/bash
source config.sh

set -e

echo "Performing protected update of ECC key to OID 0x$TARGET_ECC_OID"
$EXEPATH/trustm_protected_update_ecckey -k 0x$TARGET_ECC_OID -f ecc_fragment.dat -m ecc_manifest.dat 
echo "Save ecc public key into OID 0x$ECC_PUBKEY_OID"
$EXEPATH/trustm_data -w 0x$ECC_PUBKEY_OID -i "$ECC_PUBKEY_TO_UPDATE" -e
