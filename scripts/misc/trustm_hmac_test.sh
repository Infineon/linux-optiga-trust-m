#!/bin/bash
source config.sh


set -e

echo "Executing trustm_hmac commands"
echo "sharedsecret1234567890" >shared_secret.txt
echo "hmactest12345678" >hmac.txt
echo "hmactest1234567890abcdefg1hmactest1234567890abcdefg2hmactest1234567890abcdefg3hmactest1234567890abcdefg4hmactest1234567890abcdefg5hmactest1234567890abcdefg6hmactest1234567890abcdefg7hmactest1234567890abcdefg8hmactest1234567890abcdefg9hmactest1234567890abcdefg10hmactest1234567890abcdefg11" >hmac1.txt

echo "Write shared secret into 0xF1D8(The max size for shared secret is 64bytes)"
$EXEPATH/trustm_data -e -w 0xf1d8 -i shared_secret.txt
echo -e -n \\x20\\x11\\xC0\\x01\\x01\\xD0\\x03\\xE1\\xFC\\x07\\xD1\\01\\00\\xD3\\x01\\x00\\xE8\\x01\\x21 >metadata.bin
xxd metadata.bin
$EXEPATH/trustm_metadata -w 0xf1d8 -F metadata.bin

echo "Generate MAC value using HMAC SHA256 with shared secret in 0xF1D8"
$EXEPATH/trustm_hmac -I 0xF1D8 -H 0X20 -i hmac.txt -o hmac_data.txt
