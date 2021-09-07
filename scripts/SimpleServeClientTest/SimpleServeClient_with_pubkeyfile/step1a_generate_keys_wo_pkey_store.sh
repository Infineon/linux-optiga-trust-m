#!/bin/bash
source config.sh



set -e


echo "Server1:-----> Creates new ECC 256 key length and Auth/Enc/Sign usage and generate a certificate request"
openssl req -keyform engine -engine trustm_engine -key 0xe0f1:*:NEW:0x03:0x13 -new -out server1.csr -subj /CN=server1
openssl req -in server1.csr -text

$EXEPATH/trustm_data -X -r  0xf1d1

echo "Server1:-----> extract public key from CSR"
openssl req -in server1.csr -out server1.pub -pubkey

echo "Server1:-----> Generate server cetificate by using CA"
openssl x509 -req -in server1.csr -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out server1.crt -days 365 -sha256 -extfile openssl.cnf -extensions cert_ext
#~ openssl x509 -in client1_e0f1.crt -text -purpose

echo "Server1:-----> Verify server cetificate by using CA"

openssl verify -CAfile OPTIGA_Trust_M_Infineon_Test_CA.pem -show_chain server1.crt
