#!/bin/bash
source config.sh
source /etc/environment

$EXEPATH/trustm_ecc_sign -k 0xe0f0 -o testsignature.bin -i test_files/signature.txt -H -X
$EXEPATH/trustm_ecc_verify -i test_files/signature.txt -s testsignature.bin -k $MATTER_DAC_LOC -H -X
rm testsignature.bin