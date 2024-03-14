#!/bin/bash
PROJECT_DIR=$(dirname "$(dirname "$(pwd)")")
EXEPATH="$PROJECT_DIR/bin"


set -e

echo "CA:-----> Generate Trust M CA key and cert"
openssl req -x509 -keyform engine -engine trustm_engine -key 0xe0f1:^:NEW:0x03:0x13 -new -out ./demoCA/cacert.pem -subj /CN=trustmCA
openssl x509 -in ./demoCA/cacert.pem -text

echo "-----> Generate Device ECC Private Key"
openssl ecparam -out dev_privkey.pem -name prime256v1 -genkey
echo "Device:-----> Generate Device CSR"
openssl req -new  -key dev_privkey.pem -subj /CN=TrustM_Dev1/O=Infineon/C=SG -out dev.csr

echo "CA:-----> Generate device cetificate by using CA"
openssl ca -batch -create_serial -keyform engine -engine trustm_engine -keyfile 0xe0f1:^ -in dev.csr -out dev.pem -cert ./demoCA/cacert.pem -days 3650 -config openssl.cnf

openssl x509 -in dev.pem -text


