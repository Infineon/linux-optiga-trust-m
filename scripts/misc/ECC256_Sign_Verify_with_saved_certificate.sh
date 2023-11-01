#!/bin/bash
source config.sh

sudo rm *.csr
sudo rm *.pem

set -e

echo "helloworld" >  helloworld.txt 
echo "---->Generate csr for ECC256 using trustm Engine"
#~ openssl req -keyform engine -engine trustm_engine -key 0xe0f3:*:NEW:0x03:0x13 -new -out test_e0f3.csr -verify 
openssl req -provider trustm_provider -key 0xe0f3:^:NEW:0x03:0x13 -new -out test_e0f3.csr -subj /CN=trustm
echo "---->Generate certificate using trustm Engine"
openssl x509 -req -in test_e0f3.csr -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out test_e0f3.pem -days 365 -sha256 -extfile openssl.cnf -extensions cert_ext1
echo "-----> Extract public key from cert"
openssl x509 -pubkey -noout -in test_e0f3.pem  > test_e0f3_pubkey.pem
echo "-----> Write certificate into OID 0xe0f3"
$EXEPATH/trustm_cert -w 0xe0e3 -i test_e0f3.pem
echo "-----> Signing"
$EXEPATH/trustm_ecc_sign -k 0xe0f3 -o testsignature.bin -i helloworld.txt -H 
#~ echo "---->verify using Host PEM"
#~ $EXEPATH/trustm_ecc_verify -i helloworld.txt -s testsignature.bin -p test_e0f3_pubkey.pem -H
echo "---->verify using certificate stored inside OID"
$EXEPATH/trustm_ecc_verify -i helloworld.txt -s testsignature.bin -k 0xe0e3 -H
