#!/usr/bin/env sh

set -eu

conf=root_ca.cnf

# Generate CA
echo "[*] Generating CA certificate"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -key ca.key -new -x509 -days 365 -SHA256 -subj "/C=SG/CN=CA" -out ca.cert.pem -config "$conf" -extensions v3_ca

touch index.txt
mkdir -p certs
