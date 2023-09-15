#!/bin/bash
source config.sh

echo "Client1:-----> Extracting public key in PEM and DER from certificate"
openssl x509 -pubkey -noout -in client1.crt.pem  > temp_pubkey.pem
openssl x509 -pubkey -noout -in client1.crt.pem | openssl enc -base64 -d > temp_pubkey.der
echo "Extract the public component (65B long)"
openssl ec -pubin -inform PEM -outform DER -in temp_pubkey.pem | tail -c 65 > public_component.bin
echo "craft a NIST p256 EC keypair with a dummy 32B private component containing key identifier (beef….000)"
openssl ec -inform DER -text -in <(echo "30770201010420""beef000000000000000000000000000000000000000000000000000000000000""a00a06082A8648CE3D030107a144034200"$(xxd -ps -c 100 public_component.bin) | xxd -r -p) -out key.pem -outform pem
echo "Convert to p12 file with dummy private key"
openssl pkcs12 -export -out client1.p12 -password pass:1234 -inkey key.pem -in client1.crt.pem
echo "Copy p12 file to destination folder"
cp client1.p12 ../
#~ cp temp_pubkey.pem ../
cp temp_pubkey.der ../
