#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "input" >mydata.txt
# Private Key OID
KEY_OID=e0f1


for i in $(seq 1 1); do
echo "test $i"
set +e
rm testsignature_BP512.bin
set -e

echo "Testing Brainpool512"
echo "Trust M key gen for Brainpool512 at 0x$KEY_OID"
$EXEPATH/trustm_ecc_keygen -g 0x$KEY_OID -t 0x13 -k 0x16 -o test_pub_$KEY_OID.pem -s
#~ $EXEPATH/trustm_ecc_keygen -g 0x$KEY_OID -t 0x13 -k 0x16 -o test_pub_$KEY_OID.pem 

echo "Brain Pool Signature512 by TrustM:"
$EXEPATH/trustm_ecc_sign -k 0x$KEY_OID -o testsignature_BP512.bin -i mydata.txt -H sha512
xxd testsignature_BP512.bin

echo "Verify Brain Pool Signature512 by TrustM:"
$EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_BP512.bin -p test_pub_$KEY_OID.pem -H sha512
echo "verify with openssl sign by TrustM"
openssl dgst -verify test_pub_$KEY_OID.pem -keyform pem -sha512 -signature testsignature_BP512.bin mydata.txt

done
sleep 1
