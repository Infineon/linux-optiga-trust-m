#!/bin/bash
set -exo pipefail

echo "testing SHA-256 message digest" | openssl dgst -provider trustm_provider -sha256
