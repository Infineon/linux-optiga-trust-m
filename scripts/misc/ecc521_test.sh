#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "input" >mydata.txt

for i in $(seq 1 1); do
#~ set -e 
echo "test $i"

echo "Trust M key gen ECC521"
$EXEPATH/trustm_ecc_keygen -g 0xe0f3 -t 0x13 -k 0x05 -o test_e0f3_pub.pem -s

echo "------> Trust M sign ECC521 private key"
$EXEPATH/trustm_ecc_sign -X -k 0xe0f3 -o testsignature_521.bin -i mydata.txt -H 

echo "------> verify with Trust M"
$EXEPATH/trustm_ecc_verify -X -i mydata.txt -s testsignature_521.bin -p test_e0f3_pub.pem -H


echo "------> verify Trust M signature with openssl"
openssl dgst -verify test_e0f3_pub.pem -keyform pem -sha256 -signature testsignature_521.bin mydata.txt

done
