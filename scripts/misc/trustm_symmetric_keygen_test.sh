#!/bin/bash
source config.sh


set -e

echo "Executing trustm_symmetric_keygen commands"
echo "mydata123456789" >mydata.txt
echo "initializedv256" >iv_aes256.bin

echo "Generate AES256 key with type Enc in OID 0xe200"
$EXEPATH/trustm_symmetric_keygen -t 0x02 -k 0x83

echo "Encrypt mydata.txt using AES256 CBC mode"
$EXEPATH/trustm_symmetric_enc -m 0x09 -v iv_aes256.bin -i mydata.txt -o aes256.enc 

echo "Decrypt aes256.enc using AES256 CBC mode"
$EXEPATH/trustm_symmetric_dec -m 0x09 -v iv_aes256.bin -i aes256.enc -o mydata.txt.dec
