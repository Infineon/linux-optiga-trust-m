#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "input" >mydata.txt

set -e

for i in $(seq 1 1); do
echo "test $i"

echo "Testing Ecc256"
sudo $EXEPATH/trustm_ecc_keygen -g 0xe0f1 -t 0x13 -k 0x03 -o test_e0f1_pub.pem -s

echo "Ecc Signature256 by TrustM:"
$EXEPATH/trustm_ecc_sign -k 0xe0f1 -o testsignature_ECC256.bin -i mydata.txt -H 
xxd testsignature_ECC256.bin
echo "ECC Sign by openssl:"
openssl dgst -sign 0xe0f1 -engine trustm_engine -keyform engine -out testsignature_ECC256.sig mydata.txt
echo "Verify ECC Signature256 by TrustM:"
$EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_ECC256.sig -p test_e0f1_pub.pem -H
echo "verify with openssl sign by TrustM"
openssl dgst -verify test_e0f1_pub.pem -keyform pem -sha256 -signature testsignature_ECC256.bin mydata.txt

echo "verify with openssl sign by openssl TrustM Engine"
openssl dgst -verify test_e0f1_pub.pem -keyform pem -sha256 -signature testsignature_ECC256.sig mydata.txt


sleep 1
done
