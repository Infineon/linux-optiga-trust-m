#!/bin/bash
THING_NAME="TrustM_IOT_DEVICE"
POLICY_NAME="IoT_Publish_Subscribe"

CERT_NAME="client1_e0f1"

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

echo "Client1:-----> Creates new ECC 256 key length and Auth/Enc/Sign usage and generate a certificate request"
openssl req -keyform engine -engine trustm_engine -key 0xe0f1:^:NEW:0x03:0x13 -new -out temp/$CERT_NAME.csr -subj /CN=TrustM_Client1
openssl req -in temp/$CERT_NAME.csr -text


echo "Create AWS CA signed device cert "
aws iot create-certificate-from-csr  --certificate-signing-request file://temp/$CERT_NAME.csr --certificate-pem-outfile temp/$CERT_NAME.pem --set-as-active > temp/cli_output.jsn

echo "Creating Thing in AWS Core"
aws iot create-thing --thing-name $THING_NAME

echo "Attach device Certificate to thing"
aws iot attach-thing-principal --thing-name $THING_NAME --principal `cat temp/cli_output.jsn | grep "certificateArn" | cut -d '"' -f4`

echo "Attach Policy"
aws iot attach-policy --policy-name $POLICY_NAME --target `cat temp/cli_output.jsn | grep "certificateArn" | cut -d '"' -f4`

echo "Personalization completed"
echo "copy temp/$CERT_NAME.pem to aws-iot-device-sdk-embedded-C/certs"
