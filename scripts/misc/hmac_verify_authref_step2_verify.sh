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
#~ echo "Step2: Read out data after HAC verify sucessfully"
#~ $EXEPATH/trustm_hmac_verify_Auth -I 0xf1d0 -T 0xf1d2 -o data_f1d2.txt 
#~ xxd data_f1d2.txt 
echo "Verify HMAC SHA256 at 0xF1D0 and write new data into 0xF1D2"
$EXEPATH/trustm_hmac_verify_Auth -I 0xf1d0 -T 0xf1d2 -w data.dat -o data_f1d2.txt 
xxd data_f1d2.txt
#~ $EXEPATH/trustm_hmac_verify_Auth -I 0xf1d0 -T 0xf1d2 -w new_data.dat -o newdata_f1d2.txt 
#~ xxd newdata_f1d2.txt
#~ echo "Caution: Once the life cycle has been set to operational state,it is not reversible!!!!"
#~ echo "Set 0xf1d2 to OP"
#~ $EXEPATH/trustm_metadata -w 0xf1d2 -O 
#~ echo "Set metadata READ NEV for 0xf1d0"
#~ $EXEPATH/trustm_metadata -w 0xf1d0 -Rn


#~ echo "Step3: Set metadata of 0xF1D0 to OP"
#~ echo "Caution: Once the life cycle has been set to operational state,it is not reversible!!!!"
#~ echo "Set 0xf1d0 to OP"
#~ $EXEPATH/trustm_metadata -w 0xf1d0 -O



sleep 1
done
