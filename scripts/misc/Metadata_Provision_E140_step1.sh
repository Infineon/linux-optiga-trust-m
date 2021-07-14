#!/bin/bash
source config.sh

# Perform multiple sequential read

echo "Print out pre-secret."
echo "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40" | xxd -r -p > binary.dat
xxd binary.dat

for i in $(seq 1 1); do
echo "test $i"

echo "Provision for Metadata Update"
echo "Write Test Trust Anchor into 0xE0E3"
$EXEPATH/trustm_cert -w 0xe0e3 -i $CERT_PATH/Test_Trust_Anchor.pem
echo "read out metadata for 0xE0E3"
$EXEPATH/trustm_metadata -r  0xe0e3
echo "Write metadata for Trust Anchor 0xE0E3"
echo -e -n \\x20\\x06\\xD3\\x01\\x00\\xE8\\x01\\x11 >metadata_e0e3.bin
xxd metadata_e0e3.bin
$EXEPATH/trustm_metadata -w 0xe0e3 -F metadata_e0e3.bin

#~ echo "Set 0xE0E3 to OP"
#~ $EXEPATH/trustm_metadata -w 0xe0e3 -O

echo "set metadata for OID 0xE140 "
echo -e -n \\x20\\x0C\\xC1\\x02\\x00\\x00\\xD8\\x03\\x21\\xE0\\xE3\\xF0\\x01\\x01 > metadata_Inte0e3.bin
echo "Printout metadata_Inte0e3.bin"
xxd metadata_Inte0e3.bin
echo "write metadata_Inte0e3.bin as metadata of 0xE140"
$EXEPATH/trustm_metadata -w 0xe140 -F metadata_Inte0e3.bin
echo "read out metadata for 0xE140"
$EXEPATH/trustm_metadata -r  0xe140 

echo "write pre-secret into 0xE140"
$EXEPATH/trustm_data -w 0xe140 -i binary.dat
echo "read out data for 0xE140"
$EXEPATH/trustm_data -r 0xe140

#~ echo "Set 0xE140 to OP"
#~ $EXEPATH/trustm_metadata -w 0xe140 -O

sleep 1
done
