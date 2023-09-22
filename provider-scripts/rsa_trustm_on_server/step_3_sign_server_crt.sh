#!/bin/bash
set -exo pipefail

# sign csr using Infineon root CA key and certificate
openssl x509 -req -in test_e0fc.csr -CA  ../../../scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey ../../../scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out test_e0fc.crt \
-days 365 \
-sha256 \
-extfile ../openssl.cnf \
-extensions cert_ext2

# view certificate
openssl x509 -in test_e0fc.crt -text -noout
