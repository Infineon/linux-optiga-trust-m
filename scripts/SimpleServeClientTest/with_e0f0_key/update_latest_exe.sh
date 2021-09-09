#!/bin/bash
source config.sh
set -e
echo "Copy simpleTest executable into current directory"
cp $EXEPATH/simpleTest* $PWD/
echo "Read out Certificate"
$EXEPATH/trustm_cert -r 0xe0e0 -o test_e0e0.crt


