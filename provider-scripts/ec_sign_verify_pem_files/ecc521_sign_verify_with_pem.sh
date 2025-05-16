#!/bin/bash
source config.sh

rm *.sig

echo "Generate new ECC521 keypair"
openssl pkey -provider trustm_provider -provider default -propquery provider=trustm -in 0xe0f1:*:NEW:0x05:0x13 -out ecc521_key.pem

echo "Display the customized key file"
openssl ec -in ecc521_key.pem -text

echo "Extract out the public key"
openssl ec -in ecc521_key.pem -pubout -conv_form uncompressed -out ecc521_e0f1_pub.pem

echo -n "abcde12345abcde12345abcde12345ab" > testdata.txt
echo "-----> Sign the data using key file"
openssl pkeyutl -provider trustm_provider -provider default -sign -rawin -inkey ecc521_key.pem -in testdata.txt -out testdata.sig
echo "-----> Display the signature"
hd testdata.sig

echo "-----> Verify the Signature"
openssl pkeyutl -verify -pubin -inkey ecc521_e0f1_pub.pem -rawin -in testdata.txt -sigfile testdata.sig

