#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "input" >mydata.txt
# Private Key OID
KEY_OID=e0f1

set -e

for i in $(seq 1 1); do
echo "test $i"

echo "Testing Brainpool512"
echo "Trust M key gen for Brainpool512 at 0x$KEY_OID"
#~ $EXEPATH/trustm_ecc_keygen -g 0x$KEY_OID -t 0x13 -k 0x16 -o test_pub_$KEY_OID.pem -s
$EXEPATH/trustm_ecc_keygen -g 0x$KEY_OID -t 0x13 -k 0x16 -o test_pub_$KEY_OID.pem 
echo "Brain Pool Signature512 by TrustM:"
$EXEPATH/trustm_ecc_sign -k 0x$KEY_OID -o testsignature_BP512.bin -i mydata.txt -H 
xxd testsignature_BP512.bin
echo "Brain Pool Sign by openssl TrustM Engine:"
openssl dgst -sign 0x$KEY_OID -engine trustm_engine -keyform engine -out testsignature_BP512.sig mydata.txt
echo "Verify Brain Pool Signature512 by TrustM:"
$EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_BP512.bin -p test_pub_$KEY_OID.pem -H
echo "Verify Brain Pool Signature512 by TrustM:"
$EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_BP512.sig -p test_pub_$KEY_OID.pem -H
echo "verify with openssl sign by TrustM"
openssl dgst -verify test_pub_$KEY_OID.pem -keyform pem -sha256 -signature testsignature_BP512.bin mydata.txt
echo "verify with openssl sign by openssl TrustM Engine"
openssl dgst -verify test_pub_$KEY_OID.pem -keyform pem -sha256 -signature testsignature_BP512.sig mydata.txt


sleep 1
done
