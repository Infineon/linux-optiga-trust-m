#!/bin/bash
source config.sh

rm *.csr
rm *.pem

set -e

# Server operations with Trust M
echo "Server: -----> Generate Server ECC Private Key on Trust M"
# Note: Adjust the following command to use Trust M for generating the server key.
openssl req -provider trustm_provider -key 0xe0f2:*:NEW:0x03:0x13 -new -out test_e0f2.csr -subj "/C=SG/CN=TrustM/O=Infineon"
openssl req -in test_e0f2.csr -text

echo "Server: -----> Extract Public Key from Server CSR"
openssl req -in test_e0f2.csr -pubkey -noout -out test_e0f2.pub
openssl pkey -in test_e0f2.pub -pubin -text

echo "Server: -----> Generate Server certificate by using CA"
openssl x509 -req -in test_e0f2.csr -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out test_e0f2.crt -days 365 -sha256 -extfile ../openssl.cnf -extensions cert_ext

# Client-side operations (assuming no Trust M, adjust if needed)
echo "Client:-----> Generate Client ECC Private Key"
openssl ecparam -out privkey.pem -name prime256v1 -genkey

echo "Client:-----> Generate Client CSR"
openssl req -new  -key privkey.pem -subj "/C=SG/CN=Server1/O=Infineon" -out client.csr

echo "Client:-----> Generate Client certificate by using CA"
openssl x509 -req -in client.csr -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out client.crt -days 365 -sha256
openssl x509 -in client.crt -text -purpose
