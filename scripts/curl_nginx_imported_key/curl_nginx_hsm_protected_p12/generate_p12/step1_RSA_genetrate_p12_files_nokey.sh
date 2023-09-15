#!/bin/bash
source config.sh

set -e

echo "Client1:-----> Generate p12 file without key inside"
openssl pkcs12 -nodes -export -nokeys -password  pass:1234 -in client1_rsa.crt.pem -out e0fc.p12
openssl pkcs12 -info -in e0fc.p12 -password  pass:1234
echo "Client1:-----> Copy p12 file to upper directory"
cp e0fc.p12 ../

