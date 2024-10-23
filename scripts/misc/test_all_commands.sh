#!/bin/bash
source config.sh
rm *.bin
rm *.enc
rm *.dec, *.csr

#~ sudo rm -d -r /tmp/trustm


set -e
echo "input" >mydata.txt
#~ $EXEPATH/trustm_ecc_keygen -g 0xe0f1 -t 0x13 -k 0x03 -o e0f1_pub.pem -s |& tee out1.log

echo "-----> Openssl Provider: ECC Key Gen"
#~ openssl pkey -provider trustm_provider -in 0xe0f1:*:NEW:0x03:0x33 -pubout -out e0f1_pub.pem
#~ openssl pkey -provider trustm_provider -in 0xe0f2:*:NEW:0x03:0x33 -pubout -out e0f1_pub.pem
#~ openssl pkey -provider trustm_provider -in 0xe0f3:*:NEW:0x03:0x33 -pubout -out e0f1_pub.pem


for i in $(seq 1 5); do
echo "$(date +'%m/%d:%r') --------------> test $i"

#~ $EXEPATH/trustm_chipinfo 
openssl rand -provider trustm_provider -base64 32 &
openssl rand -provider trustm_provider -base64 32 &
openssl rand -provider trustm_provider -base64 32 &
openssl rand -provider trustm_provider -base64 32 &


echo "-----> Openssl Provider:Ecc Signature256 by TrustM:"
openssl pkeyutl -provider trustm_provider -inkey 0xe0f1:^  -sign -rawin -in mydata.txt -out test_sign_e0f1.sig &
echo "-----> Openssl Provider:Ecc Signature256 by TrustM:"
openssl pkeyutl -provider trustm_provider -inkey 0xe0f2:^  -sign -rawin -in mydata.txt -out test_sign_e0f2.sig &
echo "-----> Openssl Provider:Ecc Signature256 by TrustM:"
openssl pkeyutl -provider trustm_provider -inkey 0xe0f3:^  -sign -rawin -in mydata.txt -out test_sign_e0f3.sig &


$EXEPATH/trustm_cert -r 0xe0e0 -o cert_e0e0_1.pem &

$EXEPATH/trustm_cert -r 0xe0e0 -o cert_e0e0_2.pem &
#~ cat cert_e0e0_$i.pem

$EXEPATH/trustm_data -X -r  0xe0c5
#~ echo "--------------> waiting 60s .."
#~ sleep 160
done
