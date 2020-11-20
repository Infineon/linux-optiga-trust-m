#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "mydata123456789" >mydata.txt
echo "initializedv128" >iv_aes128.bin
echo "initializedv192" >iv_aes192.bin
echo "initializedv256" >iv_aes256.bin

set -e

for i in $(seq 1 1); do
echo "test $i"

echo "Testing AES128 CBC mode"
$EXEPATH/trustm_symmetric_keygen -t 0x02 -k 0x81
#~ echo "Encrypt message by TrustM AES128 CBC mode"
#~ $EXEPATH/trustm_symmetric_enc -m 0x09 -v iv_aes128.bin -i mydata.txt -o aes128.enc 
echo "Encrypt message by openssl AES128 CBC mode"
openssl enc -aes-128-cbc -iv "$(xxd -ps iv_aes128.bin)" -in mydata.txt -out aes128.enc -k PASS -p
echo "decrypt message by openssl AES128 CBC mode"
openssl enc -d -aes-128-cbc -iv "$(xxd -ps iv_aes128.bin)" -in aes128.enc -out aes128_cbc.dec -k PASS
#~ echo "decrypt message by TrustM AES128 CBC mode"
#~ $EXEPATH/trustm_symmetric_dec -m 0x09 -v iv_aes128.bin -i aes128.enc -o mydata.txt.dec

echo "Testing AES192 CBC mode"
$EXEPATH/trustm_symmetric_keygen -t 0x02 -k 0x82
echo "Encrypt message by TrustM AES192 CBC mode"
$EXEPATH/trustm_symmetric_enc -m 0x09 -v iv_aes192.bin -i mydata.txt -o aes192.enc
echo "Encrypt message by openssl AES192 CBC mode"
#~ openssl enc -aes-192-cbc -iv "$(xxd -ps iv_aes192.bin)"-in mydata.txt -out aes192.enc 
#~ openssl enc -d -aes-192-cbc -in aes192.enc -out aes192_cbc.dec
echo "decrypt message by TrustM AES192 CBC mode"
$EXEPATH/trustm_symmetric_dec -m 0x09 -v iv_aes192.bin -i aes192.enc -o mydata.txt.dec

echo "Testing AES256 CBC mode"
$EXEPATH/trustm_symmetric_keygen -t 0x02 -k 0x83
echo "Encrypt message by TrustM AES256 CBC mode"
$EXEPATH/trustm_symmetric_enc -m 0x09 -v iv_aes256.bin -i mydata.txt -o aes256.enc
echo "Encrypt message by openssl AES256 CBC mode"
#~ openssl enc -aes-256-cbc -iv "$(xxd -ps iv_aes256.bin)"-in mydata.txt -out aes256.enc 
#~ openssl enc -d -aes-256-cbc -in aes256.enc -out aes256_cbc.dec
echo "decrypt message by TrustM AES256 CBC mode"
$EXEPATH/trustm_symmetric_dec -m 0x09 -v iv_aes256.bin -i aes256.enc -o mydata.txt.dec


sleep 1
done
