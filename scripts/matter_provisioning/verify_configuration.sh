#!/bin/bash
source config.sh
source /etc/environment

$EXEPATH/trustm_ecc_sign -k 0xe0f0 -o testsignature.bin -i test_files/signature.txt -H -X 1>${DEBUG_OUTPUT}
$EXEPATH/trustm_ecc_verify -i test_files/signature.txt -s testsignature.bin -k $MATTER_DAC_LOC -H -X 1>${DEBUG_OUTPUT}
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Signature Verification Success ${NC}"
else 
    echo -e "${RED}Signature Verification Failure ${NC}"
    exit 1
fi
rm testsignature.bin