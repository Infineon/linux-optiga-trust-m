#!/bin/bash
set -eufx pipefail

# alice exports public key as PEM (NIST P256, key usage auth/enc/sign/agree)
openssl pkey -provider trustm_provider -in 0xe0f2:*:NEW:0x03:0x33 -pubout -out testkey1.pub

# bob generates private key as PEM using OpenSSL 
openssl genpkey -algorithm EC -pkeyopt group:P-256 -out testkey2.priv

# bob also exports public key as PEM
openssl pkey -in testkey2.priv -pubout -out testkey2.pub

