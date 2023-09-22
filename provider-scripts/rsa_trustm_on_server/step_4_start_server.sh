#!/bin/bash
set -exo pipefail

openssl s_server -provider trustm_provider -provider default \
-cert test_e0fc.crt \
-key 0xe0fc:^ \
-accept 5000 \
-verify_return_error \
-CAfile ../certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-sigalgs RSA+SHA256 \
-debug
