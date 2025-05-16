#!/bin/bash
source config.sh

rm *.sig

echo "Generate new ECC384 keypair"
openssl pkey -provider trustm_provider -provider default -propquery provider=trustm -in 0xe0f3:*:NEW:0x04:0x13 -out ecc384_key.pem

echo "Display the customized key file"
openssl ec -in ecc384_key.pem -text

echo "Extract out the public key"
openssl ec -in ecc384_key.pem -pubout -conv_form uncompressed -out ecc384_e0f3_pub.pem

echo -n "abcde12345abcde12345abcde12345ab" > testdata.txt
echo "-----> Sign the data using key file"
openssl pkeyutl -provider trustm_provider -provider default -sign -rawin -inkey ecc384_key.pem -in testdata.txt -out testdata.sig
echo "-----> Display the signature"
hd testdata.sig

echo "-----> Verify the Signature"
openssl pkeyutl -verify -pubin -inkey ecc384_e0f3_pub.pem -rawin -in testdata.txt -sigfile testdata.sig

