#!/bin/bash
source config.sh

echo "-----> Running the test client "
openssl s_client -provider trustm_provider -provider default \
-client_sigalgs RSA+SHA256 \
-cert client2_e0fd.crt \
-key 0xe0fd:^ \
-connect localhost:5001 \
-tls1_2 \
-CAfile $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-verify 1 \
-debug
