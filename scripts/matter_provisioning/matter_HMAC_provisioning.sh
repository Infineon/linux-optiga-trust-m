#!/bin/bash
source config.sh


set -e

echo "Provisoning for HMAC Operation for Matter"
echo -e -n \\x20\\x11\\xC0\\x01\\x01\\xD0\\x03\\xE1\\xFC\\x07\\xD1\\01\\00\\xD3\\x01\\x00\\xE8\\x01\\x21 >metadata.bin
xxd metadata.bin
$EXEPATH/trustm_metadata -w 0xf1d9 -F metadata.bin
echo "Read the metadata for TRUSTM_HMAC_OID_KEY"
$EXEPATH/trustm_metadata -r 0xf1d9 
