#!/bin/bash
source config.sh
rm *.bin
rm *.enc
rm *.dec, *.csr

#~ sudo rm -d -r /tmp/trustm


set -e
echo "input" >mydata.txt
#~ $EXEPATH/trustm_ecc_keygen -g 0xe0f1 -t 0x13 -k 0x03 -o test_e0f1_pub.pem -s |& tee out1.log

#~ echo "-----> Openssl Engine: ECC Key Gen"
#~ openssl req -keyform engine -engine trustm_engine -key 0xe0f1:^:NEW:0x03:0x13 -new -out client1_e0f1.csr -subj /CN=Client1 
#~ openssl req -keyform engine -engine trustm_engine -key 0xe0f2:^:NEW:0x03:0x13 -new -out client1_e0f2.csr -subj /CN=Client1 
#~ openssl req -keyform engine -engine trustm_engine -key 0xe0f3:^:NEW:0x03:0x13 -new -out client1_e0f3.csr -subj /CN=Client1 


for i in $(seq 1 100); do
echo "$(date +'%m/%d:%r') --------------> test $i"

#~ $EXEPATH/trustm_chipinfo 
openssl rand -engine trustm_engine -base64 32 &
openssl rand -engine trustm_engine -base64 32 &
openssl rand -engine trustm_engine -base64 32 &
openssl rand -engine trustm_engine -base64 32 &


echo "-----> Openssl Engine:Ecc Signature256 by TrustM:"
openssl dgst -sign 0xe0f1 -engine trustm_engine -keyform engine -out testsignature_ECC256_f1.bin mydata.txt &
echo "-----> Openssl Engine:Ecc Signature256 by TrustM:"
openssl dgst -sign 0xe0f2 -engine trustm_engine -keyform engine -out testsignature_ECC256_f2.bin mydata.txt &
echo "-----> Openssl Engine:Ecc Signature256 by TrustM:"
openssl dgst -sign 0xe0f3 -engine trustm_engine -keyform engine -out testsignature_ECC256_f3.bin mydata.txt &


$EXEPATH/trustm_cert -r 0xe0e0 -o cert_e0e0_1.pem &

$EXEPATH/trustm_cert -r 0xe0e0 -o cert_e0e0_2.pem &
#~ cat cert_e0e0_$i.pem

#~ $EXEPATH/trustm_data -X -r  0xe0c5
#~ echo "--------------> waiting 60s .."
#~ sleep 160
done
