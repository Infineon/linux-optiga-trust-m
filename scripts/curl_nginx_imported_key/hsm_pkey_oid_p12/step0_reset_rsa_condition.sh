#!/bin/bash
source config.sh
RESET="2005d003e1fc07"


set -e

echo $RESET | xxd -r -p > access_reset.bin
$EXEPATH/trustm_metadata -w 0x$TARGET_OID_RSA -F access_reset.bin
$EXEPATH/trustm_metadata -r 0x$TARGET_OID_RSA
