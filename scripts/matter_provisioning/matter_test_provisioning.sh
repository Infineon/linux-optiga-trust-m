#!/bin/bash
source config.sh
source /etc/environment

set -e

echo "-----> Read ifx pre-provisioned cert from 0xe0e0"
$EXEPATH/trustm_cert -r 0xe0e0 -o ifx_cert_e0e0.pem -X
openssl x509 -in ifx_cert_e0e0.pem -text -noout
echo "-----> Extract public key from cert"
openssl x509 -pubkey -noout -in ifx_cert_e0e0.pem >pubkey_e0e0.pem
cat pubkey_e0e0.pem
echo "---->Generate DAC csr using public key"
openssl req -new -key credentials/dummy.key -nodes -out request.csr -config test_files/openssl_matter.cnf
echo "---->Generate DAC certificate using public key, Signed by Matter test PAI"
openssl x509 -req -in request.csr -extfile test_files/v3.ext -CA credentials/Matter-Development-PAI-noPID-Cert.pem -CAkey credentials/Matter-Development-PAI-noPID-Key.pem -CAcreateserial -out DAC_Cert.pem -days 500 -sha256 -force_pubkey pubkey_e0e0.pem
echo "-----> Write test DAC into $MATTER_DAC_LOC"
$EXEPATH/trustm_cert -w $MATTER_DAC_LOC -i DAC_Cert.pem -X
echo "-----> DAC display"
openssl x509 -in DAC_Cert.pem -text -noout
echo "-----> Write Matter test PAI into $MATTER_PAI_LOC"
$EXEPATH/trustm_cert -w $MATTER_PAI_LOC -i credentials/Matter-Development-PAI-noPID-Cert.pem -X
echo "-----> Write test CD into $MATTER_CD_LOC"
$EXEPATH/trustm_data -e -w $MATTER_CD_LOC -i credentials/Chip-Test-CD-Cert.bin -X

rm *.csr
rm *.pem
