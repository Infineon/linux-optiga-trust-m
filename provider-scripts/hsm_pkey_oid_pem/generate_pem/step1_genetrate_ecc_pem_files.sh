#!/bin/bash
source config.sh

#~ echo "Generate new ECC keypair"
#~ openssl pkey -provider trustm_provider -in 0xe0f1:*:NEW:0x03:0x33 -pubout -out e0f1_pub.pem
#~ echo "Extract the public component (65B long)"
#~ openssl ec -pubin -inform PEM -outform DER -in e0f1_pub.pem | tail -c 65 > public_component.bin
#~ echo "craft a NIST p256 EC keypair with a dummy 32B private component containing key identifier (e0fx….000)"
#~ openssl ec -inform DER -text -in <(echo "30770201010420""e0f1000000000000000000000000000000000000000000000000000000000000""a00a06082A8648CE3D030107a144034200"$(xxd -ps -c 100 public_component.bin) | xxd -r -p) -out key.pem -outform pem

#~ echo "-----> Export the public key into separate file for verifier"
#~ openssl pkey -provider trustm_provider -in key.pem -pubout -out testkey.pub

echo -n "abcde12345abcde12345abcde12345ab" > testdata
echo "-----> Sign the data"
openssl pkeyutl -provider trustm_provider -sign -inkey key.pem -in testdata -out testdata.sig
