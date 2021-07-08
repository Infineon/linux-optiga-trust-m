#!/bin/bash
source config.sh

# Perform multiple sequential read

echo "Print out shared secret."
echo "49C9F492A992F6D4C54F5B12C57EDB27CED224048F25482AA149C9F492A992F649C9F492A992F6D4C54F5B12C57EDB27CED224048F25482AA149C9F492A992F6" | xxd -r -p > shared_secret.dat
#~ xxd shared_secret.dat
echo "Print out data."
echo "49C9F492A992F6D4C54F5B12C57EDB27CED224048F25482AA149C9F492A992F6" | xxd -r -p > data.dat
#~ xxd data.dat
echo "Print out new data."
echo "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20" | xxd -r -p > new_data.dat
#~ xxd new_data.dat

set -e

for i in $(seq 1 1); do
echo "test $i"
echo "Step1: Provision for HAC verify"
echo "set device type to autoref for 0xF1D0"
echo -e -n \\x20\\x11\\xC0\\x01\\x01\\xD0\\x03\\xE1\\xFC\\x07\\xD1\\x01\\x00\\xD3\\x01\\x00\\xE8\\x01\\x31 >autoref.bin
echo "Printout autoref.bin"
xxd autoref.bin
echo "write autoref.bin as metadata of 0xf1d0"
$EXEPATH/trustm_metadata -w 0xf1d0 -F autoref.bin
echo "Write shared secret into 0xF1D0"
$EXEPATH/trustm_data -e -w 0xf1d0 -i shared_secret.dat
echo "Write data into 0xF1D2"
$EXEPATH/trustm_data -e -w 0xf1d2 -i data.dat
xxd data.dat
echo "set 0xF1D2 Auto with 0xF1D0"
echo -e -n \\x03\\x23\\xF1\\xD0 > f1d2_auto_f1d0.bin
echo "Print out metadata of F1D2."
xxd f1d2_auto_f1d0.bin
echo "Set the metadata of 0xF1D2 to Auto change/Read with 0xF1D0."
$EXEPATH/trustm_metadata -w 0xf1d2 -Cf:f1d2_auto_f1d0.bin -Rf:f1d2_auto_f1d0.bin 
echo "Read data from 0xf1d2"
$EXEPATH/trustm_data -r 0xf1d2
echo "Write data into 0xf1d2"
$EXEPATH/trustm_data -e -w 0xf1d2 -i data.dat

sleep 1
done
