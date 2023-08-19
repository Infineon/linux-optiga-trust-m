#!/bin/bash
source config.sh

rm *.csr
rm *.pem



set -e

echo "Server1: -----> Generate Server ECC Private Key"
openssl ecparam -out server1_privkey.pem -name prime256v1 -genkey
echo "Server1:-----> Generate Server ECC Keys CSR"
openssl req -new  -key server1_privkey.pem -subj /CN=Server1/O=Infineon/C=SG -out server1.csr
echo "Server1:-----> Generate Server cetificate by using CA"
openssl x509 -req -in server1.csr -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out server1.crt -days 365 -sha256 -extfile openssl.cnf -extensions cert_ext
#~ openssl x509 -in server1.crt -text -purpose



echo "Client1:-----> Creates new ECC 256 key length and Auth/Enc/Sign usage and generate a certificate request"
openssl req -keyform engine -engine trustm_engine -key 0xe0fd:^:NEW:0x42:0x13 -new -out client1_rsa.csr -subj "/CN=TrustM/O=Infineon/C=SG"
openssl req -in client1_rsa.csr -text

echo "Client1:-----> extract public key from CSR"
openssl req -in client1_rsa.csr -out client1_rsa.pub -pubkey

echo "Client1:-----> Generate Client cetificate by using CA"
openssl x509 -req -in client1_rsa.csr -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out client1_rsa.crt -days 365 -sha256 -extfile openssl.cnf -extensions cert_ext1
#~ openssl x509 -in client1_rsa.crt -text -purpose


