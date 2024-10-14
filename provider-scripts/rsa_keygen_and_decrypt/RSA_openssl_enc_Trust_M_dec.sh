#!/bin/bash

rm *.enc
rm *.dec

set -e
echo "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234" > data.txt
echo "-----> Generate RSA 2048 Key Pair using Trust M provider "
openssl pkey -provider trustm_provider -in 0xe0fd:*:NEW:0x42:0x13 -pubout -out e0fd_pub.pem
echo "-----> Print out public key"
xxd e0fd_pub.pem

#~ echo "-----> Extract out Public Key using Trust M provider"
#~ openssl pkey -provider trustm_provider -in 0xe0fd:^ -pubout -out e0fd_pub.pem
#~ echo "-----> Print out public key"
#~ xxd e0fd_pub.pem

#~ echo "-----> Encrypt using public key file"
#~ openssl pkeyutl -encrypt -pubin -inkey e0fd_pub.pem -in data.txt -out data.enc

echo "-----> Encrypt with public key using Trust M provider"
openssl pkeyutl -provider trustm_provider -inkey 0xe0fd:^ -encrypt -in data.txt -out data.enc
echo "-----> Print out data.enc"
xxd data.enc

echo "-----> Decrypt with private key using Trust M provider"
openssl pkeyutl -provider trustm_provider -inkey 0xe0fd:^ -decrypt -in data.enc -out data.dec
echo "-----> Print out data.dec"
xxd data.dec

