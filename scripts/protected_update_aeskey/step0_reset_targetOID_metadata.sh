#!/bin/bash
source config.sh

set -e
 
RESET_META="2009C1020000D003E1FC07"

echo "Reset metadata for 0x$TARGET_AES_OID"
echo $RESET_META | xxd -r -p > reset_targetoid_metadata.bin
echo "Printout reset_targetoid_metadata.bin"
xxd reset_targetoid_metadata.bin
echo "Write reset_targetoid_metadata.bin as metadata of 0x$TARGET_AES_OID"
$EXEPATH/trustm_metadata -w 0x$TARGET_AES_OID -F reset_targetoid_metadata.bin
echo "Read out metadata for 0x$TARGET_AES_OID after reset"
$EXEPATH/trustm_metadata -r  0x$TARGET_AES_OID
