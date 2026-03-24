#!/bin/bash
source config.sh

set -e

echo "Performing metadata protected update for OID 0x$TARGET_OID"
$EXEPATH/trustm_protected_update -k 0x$TARGET_OID -f metadata_fragment.dat -m metadata_manifest.dat 
echo "read out metadata for 0x$TARGET_OID"
$EXEPATH/trustm_metadata -r  0x$TARGET_OID -X
