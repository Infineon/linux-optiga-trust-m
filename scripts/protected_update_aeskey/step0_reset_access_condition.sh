#!/bin/bash
source config.sh

set -e
 
RESET_ACCESS_META="2005D003E1FC07"

echo "Reset access condition for 0x$TARGET_AES_OID"
echo $RESET_ACCESS_META | xxd -r -p > reset_access_metadata.bin
echo "Printout reset_access_metadata.bin"
xxd reset_access_metadata.bin
echo "Write reset_access_metadata.bin as metadata of 0x$TARGET_AES_OID"
$EXEPATH/trustm_metadata -w 0x$TARGET_AES_OID -F reset_access_metadata.bin
echo "Read out metadata for 0x$PROTECTED_UPDATE_SECRET_OID after Provisioning"
$EXEPATH/trustm_metadata -r  0x$$TARGET_AES_OID
