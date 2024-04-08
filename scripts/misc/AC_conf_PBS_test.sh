#!/bin/bash
source config.sh

# Perform multiple sequential read

#### Configurable Variables Start
# Binding secret OID
BINDING_SECRET_OID=e140

## Initial data to be written into the data object, object OID and metadata definitions
# Data object OID
DATA_OBJECT_OID=f1d6
# Initial data to be written
DATA_OBJECT="49C9F492A992F6D4C54F5B12C57EDB27CED224048F25482AA149C9F492A992F6"
# Initial data to be written
NEW_DATA_OBJECT="01020304050607098090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
# Protected Update metadata setting
DATA_OBJ_META="0320$BINDING_SECRET_OID"

#### Configurable Variables End

echo "Prepare binary data to be init."
echo $DATA_OBJECT | xxd -r -p > data.dat
#~ xxd data.dat
echo "Prepare new data to be writen."
echo $NEW_DATA_OBJECT | xxd -r -p > newdata.dat
#~ xxd data1.dat

set -e

for i in $(seq 1 1); do
echo "test $i"
echo "Step1: Provisioning initial data, metadata for AC=Conf(0x$BINDING_SECRET_OID) secure storage"
echo "set metadata for 0x$DATA_OBJECT_OID"
echo $DATA_OBJ_META | xxd -r -p > ac_conf_metadata.bin
echo "Printout ac_conf_metadata.bin"
xxd ac_conf_metadata.bin

echo "Set the metadata of 0x$DATA_OBJECT_OID to Read Conf(0x$BINDING_SECRET_OID) and Change Conf(0x$BINDING_SECRET_OID)."
$EXEPATH/trustm_metadata -w 0x$DATA_OBJECT_OID -Rf:ac_conf_metadata.bin -Cf:ac_conf_metadata.bin 

echo "Readout data from 0x$DATA_OBJECT_OID"
$EXEPATH/trustm_data -r 0x$DATA_OBJECT_OID 
echo "Readout data from 0x$DATA_OBJECT_OID without shield communication"
$EXEPATH/trustm_data -r 0x$DATA_OBJECT_OID -X

echo "write data into 0x$DATA_OBJECT_OID"
$EXEPATH/trustm_data -w 0x$DATA_OBJECT_OID -i data.dat
echo "write data into 0x$DATA_OBJECT_OID without shield communication"
$EXEPATH/trustm_data -w 0x$DATA_OBJECT_OID -i newdata.dat -X

echo "Read out metadata for 0x$DATA_OBJECT_OID"
$EXEPATH/trustm_metadata -r 0x$DATA_OBJECT_OID


sleep 1
done
