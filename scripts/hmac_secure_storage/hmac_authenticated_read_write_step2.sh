#!/bin/bash
source config.sh

# Secret OID
SHARED_SECRET_OID=f1d0
# Data object OID
DATA_OBJECT_OID=f1d5

echo "Print out secret."
echo "49C9F492A992F6D4C54F5B12C57EDB27CED224048F25482AA149C9F492A992F649C9F492A992F6D4C54F5B12C57EDB27CED224048F25482AA149C9F492A992F6" | xxd -r -p > secret.dat
#~ xxd secret.dat
echo "Print out data."
echo "49C9F492A992F6D4C54F5B12C57EDB27CED224048F25482AA149C9F492A992F6" | xxd -r -p > data.dat
#~ xxd data.dat
echo "Print out new data."
echo "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20" | xxd -r -p > new_data.dat
#~ xxd new_data.dat

set -e

for i in $(seq 1 1); do

echo "test $i"

echo "Step2: Read out data after HMAC verify sucessfully"
$EXEPATH/trustm_hmac_verify_Auth -I 0x$SHARED_SECRET_OID -s secret.dat -r 0x$DATA_OBJECT_OID -o data_$DATA_OBJECT_OID.bin  
xxd data_$DATA_OBJECT_OID.bin 

echo "Verify HMAC SHA256 at 0x$SHARED_SECRET_OID and write new data into 0x$DATA_OBJECT_OID"
$EXEPATH/trustm_hmac_verify_Auth -I 0x$SHARED_SECRET_OID -s secret.dat -w 0x$DATA_OBJECT_OID -i new_data.dat 

echo "Verify HMAC SHA256 at 0x$SHARED_SECRET_OID and read out the new data in 0x$DATA_OBJECT_OID"
$EXEPATH/trustm_hmac_verify_Auth -I 0x$SHARED_SECRET_OID -s secret.dat -r 0x$DATA_OBJECT_OID -o data_$DATA_OBJECT_OID.bin 
xxd data_$DATA_OBJECT_OID.bin 

echo "Verify HMAC SHA256 at 0x$SHARED_SECRET_OID and write original data back into 0x$DATA_OBJECT_OID"
$EXEPATH/trustm_hmac_verify_Auth -I 0x$SHARED_SECRET_OID -s secret.dat -w 0x$DATA_OBJECT_OID -i data.dat 
xxd data_$DATA_OBJECT_OID.bin

#~ echo "Caution: Once the life cycle has been set to operational state,it is not reversible!!!!"
#~ echo "Set 0x$DATA_OBJECT_OID to OP"
#~ $EXEPATH/trustm_metadata -w 0x$DATA_OBJECT_OID -O 
#~ echo "Set metadata READ NEV for 0x$SHARED_SECRET_OID"
#~ $EXEPATH/trustm_metadata -w 0x$SHARED_SECRET_OID -Rn


#~ echo "Step3: Set metadata of 0x$SHARED_SECRET_OID to OP"
#~ echo "Caution: Once the life cycle has been set to operational state,it is not reversible!!!!"
#~ echo "Set 0x$SHARED_SECRET_OID to OP"
#~ $EXEPATH/trustm_metadata -w 0x$SHARED_SECRET_OID -O
sleep 3
done
