#!/bin/bash
source config.sh

set -e
openssl pkcs12 -nodes -export -nokeys -password  pass:1234 -in client1.crt.pem -out e0f1.p12




openssl pkcs12 -info -in e0f1.p12 -password  pass:1234
cp e0f1.p12 ../
#~ cp combined.crt.pem ../
