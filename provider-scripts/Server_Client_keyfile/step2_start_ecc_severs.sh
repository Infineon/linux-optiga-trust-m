#!/bin/bash
source config.sh

echo "-----> Running the test server1"
lxterminal -e openssl s_server -cert server1.crt -key server1_privkey.pem -accept 5000 -verify_return_error -Verify 1 -CAfile $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem & 
