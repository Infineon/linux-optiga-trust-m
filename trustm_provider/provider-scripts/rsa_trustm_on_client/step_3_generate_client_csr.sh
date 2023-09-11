#!/bin/bash
set -exo pipefail

# generate new RSA 2048 bits in OID 0xE0Fd (key usage auth/enc/sign) and create new CSR
openssl req -provider trustm_provider -key 0xe0fd:*:NEW:0x42:0x13 -new -subj "/C=SG/CN=TrustM/O=Infineon" -out test_e0fd.csr