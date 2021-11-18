#!/bin/bash
source config.sh

# Perform multiple sequential read and write
for i in $(seq 1 1); do
echo "test $i"

$EXEPATH/trustm_cert -X -r 0xe0e0 -o teste0e0.crt
$EXEPATH/trustm_cert -X -w  0xe0e1 -i teste0e0.crt

done
