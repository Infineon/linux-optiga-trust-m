#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "input" > mydata.txt

# Private Key OID
KEY_OID=e0f1

for i in $(seq 1 1); do
set +e 
echo "test $i"
rm testsignature_521.bin
set -e
echo "Trust M key gen for ECC521 at 0x$KEY_OID"
$EXEPATH/trustm_ecc_keygen -g 0x$KEY_OID -t 0x13 -k 0x05 -o test_pub_$KEY_OID.pem -s

echo "------> Trust M sign ECC521 private key"
$EXEPATH/trustm_ecc_sign -X -k 0x$KEY_OID -o testsignature_521.bin -i mydata.txt -H 

echo "------> verify with Trust M"
$EXEPATH/trustm_ecc_verify -X -i mydata.txt -s testsignature_521.bin -p test_pub_$KEY_OID.pem -H

echo "------> verify Trust M signature with openssl"
openssl dgst -verify test_pub_$KEY_OID.pem -keyform pem -sha256 -signature testsignature_521.bin mydata.txt

done
sleep 1
