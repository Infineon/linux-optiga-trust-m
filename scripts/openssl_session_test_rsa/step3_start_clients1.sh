#!/bin/bash
source config.sh

echo "-----> Running the test client "
#~ openssl s_client -connect 127.0.0.1:5000 -client_sigalgs ECDSA+SHA256 -keyform engine -engine trustm_engine -cert client1_e0f1.crt -key 0xe0f1:^ -tls1_2 -CAfile $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -verify 1

openssl s_client -connect localhost:5000 -client_sigalgs RSA+SHA256 -keyform engine -engine trustm_engine -cert client1_rsa.crt -key 0xe0fd:^ -tls1_2 -CAfile $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem 
