#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "input" >mydata.txt

set -e

for i in $(seq 1 1); do
echo "test $i"

echo "Testing Brainpool256"
sudo $EXEPATH/trustm_ecc_keygen -g 0xe0f2 -t 0x10 -k 0x03 -o test_e0f2_pub.pem -s

#~ echo "Brain Pool Signature256 by TrustM:"
#~ $EXEPATH/trustm_ecc_sign -k 0xe0f1 -o testsignature_BP256.bin -i mydata.txt -H 
#~ xxd testsignature_BP256.bin
#~ echo "Brain Pool Sign by openssl:"
#~ openssl dgst -sign 0xe0f1 -engine trustm_engine -keyform engine -out testsignature_BP256.sig mydata.txt
#~ echo "Verify Brain Pool Signature256 by TrustM:"
#~ $EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_BP256.bin -p test_e0f1_pub.pem -H
#~ echo "verify with openssl sign by TrustM"
#~ openssl dgst -verify test_e0f1_pub.pem -keyform pem -sha256 -signature testsignature_BP256.bin mydata.txt

#~ echo "verify with openssl sign by openssl TrustM Engine"
#~ openssl dgst -verify test_e0f1_pub.pem -keyform pem -sha256 -signature testsignature_BP256.sig mydata.txt


#~ echo "Testing Brainpool384"
#~ $EXEPATH/trustm_ecc_keygen -g 0xe0f2 -t 0x13 -k 0x15 -o test_e0f2_pub.pem -s
#~ echo "Brain Pool 384 Sign by TrustM:"
#~ $EXEPATH/trustm_ecc_sign -k 0xe0f2 -o testsignature_BP384.bin -i mydata.txt -H 
#~ xxd testsignature_BP384.bin

#~ echo "Brain Pool Sign by openssl:"
#~ openssl dgst -sign 0xe0f2 -engine trustm_engine -keyform engine -out testsignature_BP384.sig mydata.txt

#~ echo "Verify Brain Pool Signature256 by TrustM:"
#~ $EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_BP384.bin -p test_e0f2_pub.pem -H
#~ echo "verify with openssl sign by TrustM"
#~ openssl dgst -verify test_e0f2_pub.pem -keyform pem -sha256 -signature testsignature_BP384.bin mydata.txt


#~ echo "verify with openssl sign by openssl TrustM Engine"
#~ openssl dgst -verify test_e0f2_pub.pem -keyform pem -sha256 -signature testsignature_BP384.sig mydata.txt


sleep 1
done
