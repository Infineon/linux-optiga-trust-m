#!/bin/bash
set -exo pipefail

openssl s_client -CAfile ../certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-connect localhost:5000 -tls1_2 -debug -client_sigalgs RSA+SHA256
