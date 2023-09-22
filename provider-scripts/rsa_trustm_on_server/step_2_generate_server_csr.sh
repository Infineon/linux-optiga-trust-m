#!/bin/bash
set -exo pipefail

# generate new RSA 2048 bits in OID 0xE0FC (key usage auth/enc/sign) and create new CSR
openssl req -provider trustm_provider -key 0xe0fc:*:NEW:0x42:0x13 -new -subj "/C=SG/CN=TrustM/O=Infineon" -out test_e0fc.csr
