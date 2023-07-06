#!/bin/bash
source config.sh
source /etc/environment

rm *.csr

set -e

echo "-----> Read ifx pre-provisioned cert from 0xe0e0"
$EXEPATH/trustm_cert -r 0xe0e0 -o ifx_cert_e0e0.pem -X
openssl x509 -in ifx_cert_e0e0.pem -text -noout 
echo "-----> Extract public key from cert"
openssl x509 -pubkey -noout -in ifx_cert_e0e0.pem  > pubkey_e0e0.pem
cat pubkey_e0e0.pem
echo "---->Generate DAC csr using public key"
openssl req -new -newkey rsa:2048 -nodes -keyout private.key -out request.csr -config openssl_matter.cnf
echo "---->Generate DAC certificate using public key, Signed by Matter test PAI"
openssl x509 -req -in request.csr -extfile v3.ext -CA credentials/Matter-Development-PAI-noPID-Cert.pem -CAkey credentials/Matter-Development-PAI-noPID-Key.pem -CAcreateserial -out DAC_Cert.pem -days 500 -sha256 -force_pubkey pubkey_e0e0.pem
echo "-----> Write test DAC into 0xe0e3"
$EXEPATH/trustm_cert -w 0xe0e3 -i DAC_Cert.pem -X
echo "-----> DAC display"
openssl x509 -in DAC_Cert.pem -text -noout
echo "-----> Write Matter test PAI into 0xe0e8"
$EXEPATH/trustm_cert -w 0xe0e8 -i credentials/Matter-Development-PAI-noPID-Cert.pem -X
echo "-----> Write test CD into 0xf1e0"
$EXEPATH/trustm_data -e -w 0xf1e0 -i credentials/Chip-Test-CD-Cert.bin -X
