#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "input" >mydata.txt
# Private Key OID FOR Brainpool256
KEY_OID_BP256=e0f1
# Private Key OID FOR Brainpool384
KEY_OID_BP384=e0f2

set -e

for i in $(seq 1 1); do
echo "test $i"

echo "Testing Brainpool256"
echo "Trust M key gen for Brainpool256 at 0x$KEY_OID_256"
$EXEPATH/trustm_ecc_keygen -g 0x$KEY_OID_BP256 -t 0x13 -k 0x13 -o test_pub_$KEY_OID_BP256.pem -s
echo "Brain Pool 256 Sign by TrustM:"
$EXEPATH/trustm_ecc_sign -k 0x$KEY_OID_BP256 -o testsignature_BP256.bin -i mydata.txt -H 
xxd testsignature_BP256.bin

echo "Verify Brain Pool 256 Signature by TrustM:"
$EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_BP256.bin -p test_pub_$KEY_OID_BP256.pem -H

echo "verify with openssl sign by TrustM"
openssl dgst -verify test_pub_$KEY_OID_BP256.pem -keyform pem -sha256 -signature testsignature_BP256.bin mydata.txt

echo "Testing Brainpool384"
echo "Trust M key gen for Brainpool384 at 0x$KEY_OID_BP384"
$EXEPATH/trustm_ecc_keygen -g 0x$KEY_OID_BP384 -t 0x13 -k 0x15 -o test_pub_$KEY_OID_BP384.pem -s
echo "Brain Pool 384 Sign by TrustM:"
$EXEPATH/trustm_ecc_sign -k 0x$KEY_OID_BP384 -o testsignature_BP384.bin -i mydata.txt -H sha384
xxd testsignature_BP384.bin

echo "Verify Brain Pool Signature by TrustM:"
$EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_BP384.bin -p test_pub_$KEY_OID_BP384.pem -H sha384
echo "verify with openssl sign by TrustM"
openssl dgst -verify test_pub_$KEY_OID_BP384.pem -keyform pem -sha384 -signature testsignature_BP384.bin mydata.txt

sleep 1
done
