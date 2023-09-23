#!/bin/bash
source config.sh

echo "Client1:-----> Extracting public key in PEM and DER from certificate"
openssl x509 -pubkey -noout -in client1_ecc.crt.pem  > temp_pubkey_ecc.pem
openssl x509 -pubkey -noout -in client1_ecc.crt.pem | openssl enc -base64 -d > temp_pubkey_ecc.der
echo "Extract the public component (65B long)"
openssl ec -pubin -inform PEM -outform DER -in temp_pubkey_ecc.pem | tail -c 65 > public_component.bin
echo "craft a NIST p256 EC keypair with a dummy 32B private component containing key identifier (e0fx….000)"
openssl ec -inform DER -text -in <(echo "30770201010420""e0f1000000000000000000000000000000000000000000000000000000000000""a00a06082A8648CE3D030107a144034200"$(xxd -ps -c 100 public_component.bin) | xxd -r -p) -out key.pem -outform pem
echo "Convert to p12 file with dummy private key"
openssl pkcs12 -export -out client1_ecc.p12 -password pass:1234 -inkey key.pem -in client1_ecc.crt.pem
echo "Copy p12 file to destination folder"
cp client1_ecc.p12 ../

cp temp_pubkey_ecc.der ../
