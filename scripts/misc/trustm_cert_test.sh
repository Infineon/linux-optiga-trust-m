#!/bin/bash
source config.sh


set -e
echo "Executing trustm_cert commands"
echo "read certificate from 0xe0e0"
$EXEPATH/trustm_cert -X -r 0xe0e0 -o teste0e0.crt
cat teste0e0.crt 
echo "write certificate into 0xe0e1"
$EXEPATH/trustm_cert -X -w 0xe0e1 -i teste0e0.crt
echo "clear the certificate inside 0xe0e1"
$EXEPATH/trustm_cert -X -c 0xe0e1
