#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "input" >mydata.txt

# Private Key OID
KEY_OID=e0f3

set -e

for i in $(seq 1 1); do
echo "test $i"

echo "Testing ECC384"
echo "Trust M key gen for ECC384 at 0x$KEY_OID"
$EXEPATH/trustm_ecc_keygen -g 0x$KEY_OID -t 0x13 -k 0x04 -o test_pub_$KEY_OID.pem -s
openssl ec -pubin -in test_pub_$KEY_OID.pem -pubout -out test_pub_$KEY_OID.der -outform DER
echo "Printout ECC384 public key"
hd test_pub_$KEY_OID.der
echo "sign by trustM"
$EXEPATH/trustm_ecc_sign -k 0x$KEY_OID -o testsignature_384.bin -i mydata.txt -H 

echo "sign by openssl"
openssl pkeyutl -provider trustm_provider -inkey 0x$KEY_OID:^  -sign -rawin -in mydata.txt -out testsignature_384.bin

echo "Print out ECC384 signature"
xxd testsignature_384.bin
$EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_384.bin -p test_pub_$KEY_OID.pem -H
echo "verify with openssl"
openssl dgst -verify test_pub_$KEY_OID.pem -keyform pem -sha256 -signature testsignature_384.bin mydata.txt

sleep 1
done
