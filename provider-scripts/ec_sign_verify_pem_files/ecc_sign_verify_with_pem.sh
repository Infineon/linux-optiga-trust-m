#!/bin/bash
source config.sh

rm *.sig

echo "Generate new ECC256 keypair"
KEY_OID="E0F1"
openssl req -provider trustm_provider -key 0x${KEY_OID}:*:NEW:0x03:0x13 -new -out client1_e0f1.csr -subj "/C=SG/CN=TrustM/O=Infineon"

openssl ec -in key_${KEY_OID}.pem -pubout -conv_form uncompressed -out ${KEY_OID}_pub.pem
echo -n "abcde12345abcde12345abcde12345ab" > testdata.txt
echo "-----> Sign the data"
openssl pkeyutl -provider trustm_provider -provider default -sign -rawin -inkey key_${KEY_OID}.pem -in testdata.txt -out testdata.sig

echo "-----> Verify the Signature"
openssl pkeyutl -verify -pubin -inkey ${KEY_OID}_pub.pem -rawin -in testdata.txt -sigfile testdata.sig

