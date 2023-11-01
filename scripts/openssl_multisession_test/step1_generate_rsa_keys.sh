#!/bin/bash
source config.sh

rm *.csr
rm *.pem

set -e


echo "Server1: -----> Generate Server RSA Private Key and CSR"
openssl req -new -nodes -subj "/CN=Server1/O=Infineon/C=SG" -out server1.csr
openssl rsa -in privkey.pem -out server1_privkey.pem

echo "Server1:-----> Generate Server cetificate by using CA"
openssl x509 -req -in server1.csr -CA  $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out server1.crt \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext2



echo "Server2: -----> Generate Server RSA Private Key and CSR"
openssl req -new -nodes -subj "/CN=Server2/O=Infineon/C=SG" -out server2.csr
openssl rsa -in privkey.pem -out server2_privkey.pem

echo "Server2:-----> Generate Server cetificate by using CA"
openssl x509 -req -in server2.csr -CA  $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out server2.crt \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext2




echo "Client1:-----> Creates new RSA 2048 key length and Auth/Enc/Sign usage and generate a certificate request"
openssl req -provider trustm_provider \
-key 0xe0fc:*:NEW:0x42:0x13 \
-new \
-subj "/CN=Client1/" \
-out client1_e0fc.csr


echo "Client1:-----> Generate Client cetificate by using CA"
openssl x509 -req -in client1_e0fc.csr \
-CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out client1_e0fc.crt  \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext1




echo "Client2:-----> Creates new RSA 2048 key length and Auth/Enc/Sign usage and generate a certificate request"
openssl req -provider trustm_provider \
-key 0xe0fd:*:NEW:0x42:0x13 \
-new \
-subj "/CN=Client2/" \
-out client2_e0fd.csr


echo "Client2:-----> Generate Client cetificate by using CA"
openssl x509 -req -in client2_e0fd.csr \
-CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out client2_e0fd.crt  \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext1



