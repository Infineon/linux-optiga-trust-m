#!/bin/bash

openssl s_server \
-cert test_opensslserver.crt \
-key privkey.pem -accept 5000 \
-verify_return_error \
-Verify 1 \
-CAfile ../certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-debug -sigalgs RSA+SHA256
