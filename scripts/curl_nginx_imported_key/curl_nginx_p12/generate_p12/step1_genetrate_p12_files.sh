#!/bin/bash
source config.sh


openssl pkcs12 -export -out client1.p12 -inkey client1_privkey.pem -in client1.crt.pem
