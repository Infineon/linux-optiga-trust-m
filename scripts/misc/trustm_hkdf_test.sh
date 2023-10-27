#!/bin/bash
source config.sh


set -e

echo "Executing trustm_hkdf commands"
echo "infovalue123" >info.bin
echo "salt123456789ab123456789" >salt.bin
echo "sharedsecret1234567890abcdefghi" >shared_secret.txt

echo "Write shared secret into 0xF1D0 and change metadata to PRESSEC"
$EXEPATH/trustm_data -e -w 0xf1d8 -i shared_secret.txt
echo -e -n \\x20\\x11\\xC0\\x01\\x01\\xD0\\x03\\xE1\\xFC\\x07\\xD1\\01\\00\\xD3\\x01\\x00\\xE8\\x01\\x21 >metadata.bin
xxd metadata.bin
$EXEPATH/trustm_metadata -w 0xf1d8 -F metadata.bin

echo "derive key using HKDF SHA256 with shared secret in 0xF1D8"
$EXEPATH/trustm_hkdf -i 0xf1d8 -H 0X08 -f info.bin -s salt.bin -o hkdf_f1d8_256.txt

echo "set metadata back to default for 0xF1D8"
echo -e -n \\x20\\x11\\xC0\\x01\\x01\\xD0\\x03\\xE1\\xFC\\x07\\xD1\\01\\00\\xD3\\x01\\xFF\\xE8\\x01\\x00 >default_metadata.bin
xxd default_metadata.bin
$EXEPATH/trustm_metadata -w 0xf1d8 -F default_metadata.bin
