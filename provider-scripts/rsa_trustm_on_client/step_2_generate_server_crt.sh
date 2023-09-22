#!/bin/bash
set -exo pipefail

# generate new RSA 2048 bits keypair and CSR
openssl req -new -nodes -subj "/C=SG/O=Infineon" -out test_opensslserver.csr

# sign the generated CSR using Infineon CA cert and keys
openssl x509 -req -in test_opensslserver.csr \
-CA ../../../scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey ../../../scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out test_opensslserver.crt \
-days 365 \
-sha256 \
-extfile ../openssl.cnf \
-extensions cert_ext2
