#!/bin/bash
source config.sh


set -e
echo "Executing trustm_rsa_keygen commands"
$EXEPATH/trustm_rsa_keygen -g 0xe0fc -t 0x13 -k 0x41 -o test_e0fc_pub.pem -s
cat test_e0fc_pub.pem 
$EXEPATH/trustm_data -r 0xf1e0

echo "Executing trustm_rsa_sign commands"
$EXEPATH/trustm_rsa_sign -k 0xe0fc -o testsignature.bin -i helloworld.txt -H
hd testsignature.bin

echo "Executing trustm_rsa_verify commands"
$EXEPATH/trustm_rsa_verify -i helloworld.txt -s testsignature.bin -p test_e0fc_pub.pem -H

echo "Executing trustm_rsa_enc commands"
$EXEPATH/trustm_rsa_enc -p test_e0fc_pub.pem -o test_e0fc.enc -i helloworld.txt

echo "Executing trustm_rsa_dec commands"
$EXEPATH/trustm_rsa_dec -k 0xe0fc -o test_e0fc.dec -i test_e0fc.enc 
cat test_e0fc.dec 
