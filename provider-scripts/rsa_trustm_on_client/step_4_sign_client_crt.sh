#!/bin/bash
set -exo pipefail

# sign csr using Infineon root CA key and certificate
openssl x509 -req -in test_e0fd.csr -CA  ../certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey ../certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out test_e0fd.crt \
-days 365 \
-sha256 \
-extfile ../openssl.cnf \
-extensions cert_ext1

# view certificate
openssl x509 -in test_e0fd.crt -text -noout
