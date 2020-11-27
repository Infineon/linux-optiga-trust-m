#!/bin/bash
source config.sh

# Perform multiple sequential read

echo "sharedsecret1234567890" >shared_secret.txt
echo "hmactest12345678" >hmac.txt
echo "hmactest1234567890abcdefg1hmactest1234567890abcdefg2hmactest1234567890abcdefg3hmactest1234567890abcdefg4hmactest1234567890abcdefg5hmactest1234567890abcdefg6hmactest1234567890abcdefg7hmactest1234567890abcdefg8hmactest1234567890abcdefg9hmactest1234567890abcdefg10hmactest1234567890abcdefg11" >hmac1.txt

set -e

for i in $(seq 1 1); do
echo "test $i"

echo "Testing HMAC SHA256 function at 0xF1D0"
echo "Write shared secret into 0xF1D0"
$EXEPATH/trustm_data -e -w 0xf1d0 -i shared_secret.txt
#~echo -e -n \\x20\\x11\\xC0\\x01\\x01\\xD0\\x03\\xE1\\xFC\\x07\\xD1\\01\\00\\xD3\\x01\\x00\\xE8\\x01\\x21 >metadata.bin
xxd metadata.bin
$EXEPATH/trustm_metadata -w 0xf1d0 -F metadata.bin
$EXEPATH/trustm_hmac -I 0xF1D0 -H 0X20 -i hmac.txt -o hmac_f1d0_256.txt

echo "Testing HMAC SHA384 function at 0xF1D0"
$EXEPATH/trustm_hmac -I 0xF1D0 -H 0X21 -i hmac.txt -o hmac_f1d0_384.txt

echo "Testing HMAC SHA512 function at 0xF1D0"
$EXEPATH/trustm_hmac -I 0xF1D0 -H 0X21 -i hmac.txt -o hmac_f1d0_512.txt


sleep 1
done
