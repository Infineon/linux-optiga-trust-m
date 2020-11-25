#!/bin/bash
source config.sh

# Perform multiple sequential read
echo "infovalue123" >info.bin
echo "salt123456789ab123456789" >salt.bin
echo "sharedsecret1234567890abcdefghi" >shared_secret.txt

set -e

for i in $(seq 1 1); do
echo "test $i"

echo "Testing HKDF SHA256 at 0xF1D0"
echo "Write shared secret into 0xF1D0"
$EXEPATH/trustm_data -e -w 0xf1d0 -i shared_secret.txt
echo "Change metadata(DType) to PRESSEC for 0xF1D0"
echo -e -n \\x20\\x11\\xC0\\x01\\x01\\xD0\\x03\\xE1\\xFC\\x07\\xD1\\01\\00\\xD3\\x01\\x00\\xE8\\x01\\x21 >metadata.bin
xxd metadata.bin
$EXEPATH/trustm_metadata -w 0xf1d0 -F metadata.bin
echo "Run HKDF SHA256 command to derive the key"
$EXEPATH/trustm_hkdf -i 0xF1D0 -H 0X08 -f info.bin -s salt.bin -o hkdf_f1d0_256.txt

echo "Run HKDF SHA384 command to derive the key"
$EXEPATH/trustm_hkdf -i 0xF1D0 -H 0X09 -f info.bin -s salt.bin -o hkdf_f1d0_384.txt

echo "Run HKDF SHA512 command to derive the key"
$EXEPATH/trustm_hkdf -i 0xF1D0 -H 0X0A -f info.bin -s salt.bin -o hkdf_f1d0_512.txt

echo "set metadata back to default for 0xF1D0"
echo -e -n \\x20\\x11\\xC0\\x01\\x01\\xD0\\x03\\xE1\\xFC\\x07\\xD1\\01\\00\\xD3\\x01\\xFF\\xE8\\x01\\x00 >default_metadata.bin
xxd default_metadata.bin
$EXEPATH/trustm_metadata -w 0xf1d0 -F default_metadata.bin


sleep 1
done
