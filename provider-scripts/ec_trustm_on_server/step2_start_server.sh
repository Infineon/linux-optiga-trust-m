#!/bin/bash
source config.sh

echo "-----> Running the test server1"
lxterminal -e openssl s_server -cert test_e0f2.crt -provider trustm_provider -provider default -key 0xe0f2:^ -accept 5000 -verify_return_error -Verify 1 -CAfile $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem & 
