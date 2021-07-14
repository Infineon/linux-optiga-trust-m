#!/bin/bash
source config.sh

THING_NAME="TrustM_IOT_DEVICE"
POLICY_NAME="IoT_Publish_Subscribe"

CERT_NAME="client1_e0e1"
KEY_OID="0xe0f1"
CERT_OID="0xe0e1"
#PRELOAD_CERTNAME="client1_e0e0"


if [ -d "temp" ] 
then
    echo "Existing device certificate exists. Proceed will overwrite the existing certificates."
    echo "Press Y to continue, other keys to exit..."
    
    read -r input
	if [ "$input" != "Y" ]; then
    	echo "End of Perso!"
	exit 0
	fi
	   
fi

rm -rf temp
mkdir temp

set -e

#~ # $EXEPATH/trustm_cert -r 0xe0e0 -o $PRELOAD_CERTNAME.pem
#~ # openssl x509 -in $PRELOAD_CERTNAME.pem -text
#~ # rm size.bin
#~ # aws iot register-certificate-without-ca --certificate-pem $PRELOAD_CERTNAME.pem --status ACTIVE

echo "Client1:-----> Creates new ECC 256 key length and Auth/Enc/Sign usage and generate a certificate request"
openssl req -keyform engine -engine trustm_engine -key $KEY_OID:^:NEW:0x03:0x13 -new -out temp/$CERT_NAME.csr -subj /CN=TrustM_Client1
openssl req -in temp/$CERT_NAME.csr -text


echo "Create AWS CA signed device cert "
aws iot create-certificate-from-csr  --certificate-signing-request file://temp/$CERT_NAME.csr --certificate-pem-outfile temp/$CERT_NAME.pem --set-as-active > temp/cli_output.jsn

echo "Creating Thing in AWS Core"
aws iot create-thing --thing-name $THING_NAME

echo "Attach device Certificate to thing"
aws iot attach-thing-principal --thing-name $THING_NAME --principal `cat temp/cli_output.jsn | grep "certificateArn" | cut -d '"' -f4`

echo "Attach Policy"
aws iot attach-policy --policy-name $POLICY_NAME --target `cat temp/cli_output.jsn | grep "certificateArn" | cut -d '"' -f4`

echo "Convert certificate to DER"
openssl x509 -in temp/$CERT_NAME.pem -out temp/$CERT_NAME.der -outform DER


size=$(stat -c %s temp/$CERT_NAME.pem)
size2=`expr $size + 3`
size3=`expr $size + 6`
printf "c0%04x\n" $size3 | xxd -r -p > temp/cert_tag.bin
printf "00%04x\n" $size2 | xxd -r -p >> temp/cert_tag.bin
printf "00%04x\n" $size | xxd -r -p >> temp/cert_tag.bin

cat temp/cert_tag.bin temp/$CERT_NAME.der > temp/$CERT_NAME.bin
xxd temp/$CERT_NAME.bin

echo "write into Trust M"
$EXEPATH/trustm_data -e -w $CERT_OID -i temp/$CERT_NAME.bin

echo "Personalization completed"


