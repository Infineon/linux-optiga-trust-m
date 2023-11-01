#!/bin/bash
source config.sh

echo "-----> Running the test server2"
openssl s_server \
-cert server2.crt \
-key server2_privkey.pem -accept 5001 \
-verify_return_error \
-Verify 1 \
-CAfile $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-debug -sigalgs RSA+SHA256


