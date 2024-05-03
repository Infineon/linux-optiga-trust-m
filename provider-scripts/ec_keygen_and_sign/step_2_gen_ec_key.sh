#!/bin/bash
set -exo pipefail

# Generate ECC NIST P-256 ecc key in 0xE0F3 (key usage auth/enc/sign) and extract public key file
openssl pkey -provider trustm_provider -in 0xe0f3:*:NEW:0x03:0x33 -pubout -out e0f3_pub.pem
