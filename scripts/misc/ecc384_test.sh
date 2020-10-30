#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "input" >mydata.txt

set -e

for i in $(seq 1 1); do
echo "test $i"

echo "Testing ECC384"
$EXEPATH/trustm_ecc_keygen -g 0xe0f2 -t 0x13 -k 0x04 -o test_e0f2_pub.pem -s
openssl ec -pubin -in test_e0f2_pub.pem -pubout -out test_e0f2_pub.der -outform DER
echo "Printout ECC384 public key"
hd test_e0f2_pub.der
echo "sign by trustM"
#~ openssl dgst -sign 0xe0f2 -engine trustm_engine -keyform engine -out testsignature_e0f2.sig mydata.txt
$EXEPATH/trustm_ecc_sign -k 0xe0f2 -o testsignature_384.bin -i mydata.txt -H 
echo "Print out ECC384 signature"
xxd testsignature_384.bin
$EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_384.bin -p test_e0f2_pub.pem -H
echo "verify with openssl"
#~ openssl dgst -verify test_e0f2_pub.pem -keyform pem -sha256 -signature testsignature_e0f2.sig mydata.txt
openssl dgst -verify test_e0f2_pub.pem -keyform pem -sha256 -signature testsignature_384.bin mydata.txt

sleep 1
done
