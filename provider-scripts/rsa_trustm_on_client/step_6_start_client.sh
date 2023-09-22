#!/bin/bash
set -exo pipefail

openssl s_client -provider trustm_provider -provider default \
-client_sigalgs RSA+SHA256 \
-cert test_e0fd.crt \
-key 0xe0fd:^ \
-connect localhost:5000 \
-tls1_2 \
-CAfile ../../../scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-verify 1 \
-debug
