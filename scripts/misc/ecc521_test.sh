#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "input" >mydata.txt

for i in $(seq 1 4); do
#~ set -e 
echo "test $i"

echo "Trust M key gen ECC521"
$EXEPATH/trustm_ecc_keygen -g 0xe0f3 -t 0x13 -k 0x05 -o test_e0f3_pub.pem -s
echo "Printout ECC521 public key"
openssl ec -pubin -in test_e0f3_pub.pem -pubout -out test_e0f3_pub.der -outform DER
hd test_e0f3_pub.der

echo "------> Trust M sign ECC521 private key"
$EXEPATH/trustm_ecc_sign -X -k 0xe0f3 -o testsignature_521.bin -i mydata.txt -H 
xxd sign_b4_convert.bin
openssl asn1parse -i -inform DER -in sign_b4_convert.bin

xxd testsignature_521.bin
openssl asn1parse -i -inform DER -in testsignature_521.bin

echo "------> verify with Trust M"
$EXEPATH/trustm_ecc_verify -X -i mydata.txt -s testsignature_521.bin -p test_e0f3_pub.pem -H


echo "------> verify Trust M signature with openssl"
openssl dgst -verify test_e0f3_pub.pem -keyform pem -sha256 -signature testsignature_521.bin mydata.txt
$EXEPATH/trustm_data -X -r  0xe0c5


#~ echo "------> OpenSSL sign with engine using Trust M ECC521 private key"
#~ openssl dgst -sign 0xe0f3 -engine trustm_engine -keyform engine -out ssl_testsignature_521.bin mydata.txt
#~ xxd ssl_testsignature_521.bin


#~ echo "------> verify openssl signature"
#~ openssl dgst -verify test_e0f3_pub.pem -keyform pem -sha256 -signature ssl_testsignature_521.bin mydata.txt
#~ $EXEPATH/trustm_data -X -r  0xe0c5


#~ echo "---> Testing ECC521"
#~ $EXEPATH/trustm_ecc_keygen -g 0xe0f3 -t 0x13 -k 0x05 -o test_e0f2_pub.pem -s
#~ openssl pkey -inform PEM -pubin -in test_e0f2_pub.pem -noout -text

#~ $EXEPATH/trustm_ecc_sign  -k 0xe0f3 -o testsignature_521.bin -i mydata.txt -H 
#~ xxd testsignature_521.bin
#~ # $EXEPATH/trustm_ecc_verify -i mydata.txt -s testsignature_521.bin -p test_e0f2_pub.pem -H
#~ echo "verify with openssl"
#~ openssl dgst -verify test_e0f2_pub.pem -keyform pem -sha256 -signature testsignature_521.bin mydata.txt




done
