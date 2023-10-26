#!/bin/bash
source config.sh


set -e
echo "Executing trustm_ecc_keygen commands"
$EXEPATH/trustm_ecc_keygen -g 0xe0f3 -t 0x13 -k 0x03 -o test_e0f3_pub.pem -s
cat test_e0f3_pub.pem
$EXEPATH/trustm_data -r 0xf1d3

echo "Executing trustm_ecc_sign commands"
echo "Hello World" > helloworld.txt
$EXEPATH/trustm_ecc_sign -k 0xe0f3 -o testsignature.bin -i helloworld.txt -H
hd testsignature.bin

echo "Executing trustm_ecc_verify commands"
$EXEPATH/trustm_ecc_verify -i helloworld.txt -s testsignature.bin -p test_e0f3_pub.pem -H
