#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "input" >mydata.txt

set -e

for i in $(seq 1 1); do
echo "test $i"

echo "Testing Brainpool512"
$EXEPATH/trustm_ecc_keygen -g 0xe0f3 -t 0x13 -k 0x16 -o test_e0f3_pub.pem -s
echo "Brain Pool Signature512 by TrustM:"
$EXEPATH/trustm_ecc_sign -k 0xe0f3 -o testsignature_BP512.bin -i mydata.txt -H 
xxd testsignature_BP512.bin
echo "Brain Pool Sign by openssl TrustM Engine:"
openssl dgst -sign 0xe0f3 -engine trustm_engine -keyform engine -out testsignature_BP512.sig mydata.txt
echo "Verify Brain Pool Signature512 by TrustM:"
$EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_BP512.bin -p test_e0f3_pub.pem -H
echo "Verify Brain Pool Signature512 by TrustM:"
$EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_BP512.sig -p test_e0f3_pub.pem -H
echo "verify with openssl sign by TrustM"
openssl dgst -verify test_e0f3_pub.pem -keyform pem -sha256 -signature testsignature_BP512.bin mydata.txt
echo "verify with openssl sign by openssl TrustM Engine"
openssl dgst -verify test_e0f3_pub.pem -keyform pem -sha256 -signature testsignature_BP512.sig mydata.txt


sleep 1
done
