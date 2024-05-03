#!/bin/bash
set -exo pipefail

echo test signing Trust M ECC key > test_sign.txt

hd test_sign.txt

openssl pkeyutl -provider trustm_provider -inkey 0xe0f3:^  -sign -rawin -in test_sign.txt -out test_sign.sig

hd test_sign.sig
