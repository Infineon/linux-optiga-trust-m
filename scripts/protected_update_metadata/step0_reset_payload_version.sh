#!/bin/bash
source config.sh

set -e
 
RESET_PAYLOAD_VER_META="2004C1020000"

echo "Reset payload version for 0x$TARGET_OID"
echo $RESET_PAYLOAD_VER_META | xxd -r -p > reset_payload_ver_metadata.bin
echo "Printout reset_payload_ver_metadata.bin"
xxd reset_payload_ver_metadata.bin
echo "Write reset_payload_ver_metadata.bin as metadata of 0x$TARGET_OID"
$EXEPATH/trustm_metadata -w 0x$TARGET_OID -F reset_payload_ver_metadata.bin
echo "Read out metadata for 0x$TARGET_OID after reset"
$EXEPATH/trustm_metadata -r  0x$TARGET_OID
