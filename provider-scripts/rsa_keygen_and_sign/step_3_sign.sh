#!/bin/bash
set -exo pipefail

#create the message file and store it in the test_sign.txt
echo test signing Trust M RSA key > test_sign.txt

#view the hexadecimal representation of the file
hd test_sign.txt

#sign the message using the trustM EC key and save the generated signature in the test_sign.sig file
openssl pkeyutl -provider trustm_provider -inkey 0xe0fd:^  -sign -rawin -in test_sign.txt -out test_sign.sig

#view the hexadecimal representation of the signature file
hd test_sign.sig
