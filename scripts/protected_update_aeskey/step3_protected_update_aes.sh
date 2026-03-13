#!/bin/bash
source config.sh

set -e

echo "Performing protected update of AES key to OID 0x$TARGET_AES_OID"
$EXEPATH/trustm_protected_update_aeskey -k 0x$TARGET_AES_OID -f aes_fragment.dat -m aes_manifest.dat 
