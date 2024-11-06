#!/bin/bash
source config.sh

echo "input1" >mydata1.txt
echo "input2" >mydata2.txt

for i in $(seq 1 5); do
echo "$(date +'%m/%d:%r') --------------> test $i"
set +e
rm *.enc
rm *.dec
set -e
echo "-----> Encrypt with public key using Trust M provider"
openssl pkeyutl -provider trustm_provider -inkey 0xe0fd:^ -encrypt -in mydata1.txt -out mydata1.enc &
P1=$!
echo "-----> Encrypt with public key using Trust M provider"
openssl pkeyutl -provider trustm_provider -inkey 0xe0fd:^ -encrypt -in mydata2.txt -out mydata2.enc &
P2=$!

wait $P1 $P2

echo "-----> Decrypt with private key using Trust M provider"
openssl pkeyutl -provider trustm_provider -inkey 0xe0fd:^ -decrypt -in mydata1.enc -out mydata1.dec &
P1=$!
echo "-----> Decrypt with private key using Trust M provider"
openssl pkeyutl -provider trustm_provider -inkey 0xe0fd:^ -decrypt -in mydata2.enc -out mydata2.dec &
P2=$!

wait $P1 $P2
done

