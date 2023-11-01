#!/bin/bash
source config.sh


rm *.bin
rm *.enc
rm *.dec

set -e
echo "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234" > datain.txt
echo "-----> Trust M Generate RSA 2048 Privete key "
$EXEPATH/trustm_rsa_keygen -g 0xe0fc -t 0x13 -k 0x42 -o rsa_e0fc_pub.pem -s -X

echo "-----> Encrypt with public key with OpenSSL "
openssl pkeyutl -pubin -inkey rsa_e0fc_pub.pem -in datain.txt -encrypt -out datain.enc

$EXEPATH/trustm_rsa_dec -k 0xe0fc -o datain.dec -i datain.enc -X
cat datain.dec
