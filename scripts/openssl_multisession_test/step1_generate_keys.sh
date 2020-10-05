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

echo "Server2: -----> Generate Server ECC Private Key"
openssl ecparam -out server2_privkey.pem -name prime256v1 -genkey
echo "Server2:-----> Generate Server ECC Keys CSR"
openssl req -new  -key server2_privkey.pem -subj /CN=Server2/O=Infineon/C=SG -out server2.csr
echo "Server2:-----> Generate Server cetificate by using CA"
openssl x509 -req -in server2.csr -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out server2.crt -days 365 -sha256 -extfile openssl.cnf -extensions cert_ext
#~ openssl x509 -in server2.crt -text -purpose

echo "Server3: -----> Generate Server ECC Private Key"
openssl ecparam -out server3_privkey.pem -name prime256v1 -genkey
echo "Server3:-----> Generate Server ECC Keys CSR"
openssl req -new  -key server3_privkey.pem -subj /CN=Server3/O=Infineon/C=SG -out server3.csr
echo "Server3:-----> Generate Server cetificate by using CA"
openssl x509 -req -in server3.csr -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out server3.crt -days 365 -sha256 -extfile openssl.cnf -extensions cert_ext
#~ openssl x509 -in server3.crt -text -purpose


echo "Client1:-----> Creates new ECC 256 key length and Auth/Enc/Sign usage and generate a certificate request"
openssl req -keyform engine -engine trustm_engine -key 0xe0f1:^:NEW:0x03:0x13 -new -out client1_e0f1.csr -subj /CN=Client1
openssl req -in client1_e0f1.csr -text

echo "Client1:-----> extract public key from CSR"
openssl req -in client1_e0f1.csr -out client1_e0f1.pub -pubkey

echo "Client1:-----> Generate Client cetificate by using CA"
openssl x509 -req -in client1_e0f1.csr -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out client1_e0f1.crt -days 365 -sha256 -extfile openssl.cnf -extensions cert_ext1
#~ openssl x509 -in client1_e0f1.crt -text -purpose

echo "Client2:-----> Creates new ECC 256 key length and Auth/Enc/Sign usage and generate a certificate request"
openssl req -keyform engine -engine trustm_engine -key 0xe0f2:^:NEW:0x03:0x13 -new -out client1_e0f2.csr -subj /CN=Client2
openssl req -in client1_e0f2.csr -text

echo "Client2:-----> extract public key from CSR"
openssl req -in client1_e0f2.csr -out client1_e0f2.pub -pubkey

echo "Client2:-----> Generate Client cetificate by using CA"
openssl x509 -req -in client1_e0f2.csr -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out client1_e0f2.crt -days 365 -sha256 -extfile openssl.cnf -extensions cert_ext1
#~ openssl x509 -in client1_e0f2.crt -text -purpose


echo "Client3:-----> Creates new ECC 256 key length and Auth/Enc/Sign usage and generate a certificate request"
openssl req -keyform engine -engine trustm_engine -key 0xe0f3:^:NEW:0x03:0x13 -new -out client1_e0f3.csr -subj /CN=Client3
openssl req -in client1_e0f3.csr -text

echo "Client3:-----> extract public key from CSR"
openssl req -in client1_e0f3.csr -out client1_e0f3.pub -pubkey

echo "Client3:-----> Generate Client cetificate by using CA"
openssl x509 -req -in client1_e0f3.csr -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out client1_e0f3.crt -days 365 -sha256 -extfile openssl.cnf -extensions cert_ext1
