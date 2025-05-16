#!/bin/bash
source config.sh

rm *.sig

echo "Generate new brainpool256 keypair"
openssl pkey -provider trustm_provider -provider default -propquery provider=trustm -in 0xe0f1:*:NEW:0x13:0x13 -out brainpool256_key.pem

echo "Display the customized key file"
openssl ec -in brainpool256_key.pem -text

echo "Extract out the public key"
openssl ec -in brainpool256_key.pem -pubout -conv_form uncompressed -out brainpool256_e0f1_pub.pem

echo -n "abcde12345abcde12345abcde12345ab" > testdata.txt
echo "-----> Sign the data using key file"
openssl pkeyutl -provider trustm_provider -provider default -sign -rawin -inkey brainpool256_key.pem -in testdata.txt -out testdata.sig
echo "-----> Display the signature"
hd testdata.sig

echo "-----> Verify the Signature"
openssl pkeyutl -verify -pubin -inkey brainpool256_e0f1_pub.pem -rawin -in testdata.txt -sigfile testdata.sig

