#!/bin/bash

# SPDX-FileCopyrightText: Copyright (c) 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

# Perform multiple sequential read
echo "input" > mydata.txt

# Private Key OID
KEY_OID=e0f1

for i in $(seq 1 10); do
set +e 
echo "test $i"
rm testsignature_521.bin
set -e
echo "Trust M key gen for ECC521 at 0x$KEY_OID"
openssl pkey -provider trustm_provider -in 0x$KEY_OID:*:NEW:0x05:0x11 -pubout -out pub_$KEY_OID.pem

echo "------> Trust M sign ECC521 private key"
openssl pkeyutl -provider trustm_provider -inkey 0x$KEY_OID:^  -sign -rawin -in mydata.txt -out testsignature_521.bin

echo "------> verify Trust M signature with openssl"
openssl dgst -verify pub_$KEY_OID.pem -keyform pem -sha256 -signature testsignature_521.bin mydata.txt


done
