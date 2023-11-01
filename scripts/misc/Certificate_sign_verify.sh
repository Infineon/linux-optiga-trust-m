#!/bin/bash
source config.sh

CERT_OBJ_ID="0xe0e0"
KEY_OBJ_ID="0xe0f0"
DATA_IN="mydata.txt"


for i in $(seq 1 1); do
echo "test $i"

rm *.bin
rm *.pem
rm $DATA_IN

set -e
echo "-----> Read pre-provisioned cert"
$EXEPATH/trustm_cert -r $CERT_OBJ_ID -o cert_$CERT_OBJ_ID.pem -X
openssl x509 -in cert_$CERT_OBJ_ID.pem -text -noout 
$EXEPATH/trustm_data -X -r  0xe0c5 
echo "-----> Extract public key from cert"
openssl x509 -pubkey -noout -in cert_$CERT_OBJ_ID.pem  > pubkey_$CERT_OBJ_ID.pem
cat pubkey_$CERT_OBJ_ID.pem
$EXEPATH/trustm_data -X -r  0xe0c5

echo "-----> Hash and Sign Data with private key: "
echo "my data" > $DATA_IN
$EXEPATH/trustm_ecc_sign -k $KEY_OBJ_ID -o ecc_signature.bin -i $DATA_IN -H 
xxd ecc_signature.bin

$EXEPATH/trustm_data -X -r  0xe0c5

echo "-----> Hash and Verify data with public key: "
$EXEPATH/trustm_ecc_verify -i $DATA_IN -s ecc_signature.bin -p pubkey_$CERT_OBJ_ID.pem -H 
$EXEPATH/trustm_data -X -r  0xe0c5
done 
