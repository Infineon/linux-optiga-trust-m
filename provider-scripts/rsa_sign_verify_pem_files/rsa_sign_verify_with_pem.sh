#!/bin/bash
source config.sh

rm *.sig

echo "Generate new RSA2048 keypair"
openssl pkey -provider trustm_provider -provider default -propquery provider=trustm -in 0xe0fc:*:NEW:0x42:0x13 -out rsakey.pem

echo "Display the customized key file"
openssl rsa -in rsakey.pem -text -noout

echo "Extract out the public key"
openssl rsa -in rsakey.pem -pubout -out e0fc_pub.pem
openssl rsa -pubin -in e0fc_pub.pem -text -noout

echo -n "abcde12345abcde12345abcde12345ab" > testdata.txt
echo "-----> Sign the data"
openssl pkeyutl -provider trustm_provider -provider default -sign -rawin -inkey rsakey.pem -in testdata.txt -out testdata.sig

#~ echo "-----> Verify the Signature"
#~ openssl pkeyutl -verify -pubin -inkey e0fc_pub.pem -rawin -in testdata.txt -sigfile testdata.sig
