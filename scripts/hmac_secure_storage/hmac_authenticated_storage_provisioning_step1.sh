#!/bin/bash
source config.sh

#### Configurable Variables Start

## HMAC shared secret OID, Secret Value and Metadata settings
# Secret OID
SHARED_SECRET_OID=f1d0
# Shared Secret Data, must match with the host C codes
SHARED_SECRET="49C9F492A992F6D4C54F5B12C57EDB27CED224048F25482AA149C9F492A992F649C9F492A992F6D4C54F5B12C57EDB27CED224048F25482AA149C9F492A992F6"
# Shared secret metadata setting
SHARED_SECRET_META="2011C00101D003E1FC07D10100D30100E80131"

## Initial data to be written into the data object, object OID and metadata definitions
# Data object OID
DATA_OBJECT_OID=f1d2
# Initial data to be written
DATA_OBJECT="49C9F492A992F6D4C54F5B12C57EDB27CED224048F25482AA149C9F492A992F6"
# Data object auto with secret object
DATA_OBJ_META="0323$SHARED_SECRET_OID"
#### Configurable Variables End


# Perform multiple sequential read
echo "Prepare binary shared secret."
echo $SHARED_SECRET | xxd -r -p > shared_secret.dat
#~ xxd shared_secret.dat
echo "Prepare binary data to be init."
echo $DATA_OBJECT | xxd -r -p > data.dat
#~ xxd data.dat

set -e
for i in $(seq 1 1); do
echo "test $i"
echo "Step1: Provisioning initial data, metadata and shared secret for HMAC authenticated secure storage access"
echo "set device type to autoref for 0x$SHARED_SECRET_OID"
echo $SHARED_SECRET_META | xxd -r -p > secret_autoref_metadata.bin

echo "Printout secret_autoref_metadata.bin"
xxd secret_autoref_metadata.bin
echo "write secret_autoref_metadata.bin as metadata of 0x$SHARED_SECRET_OID"
$EXEPATH/trustm_metadata -w 0x$SHARED_SECRET_OID -F secret_autoref_metadata.bin
echo "Write shared secret into 0x$SHARED_SECRET_OID"
$EXEPATH/trustm_data -e -w 0x$SHARED_SECRET_OID -i shared_secret.dat
echo "Write intial data into 0x$DATA_OBJECT_OID"
$EXEPATH/trustm_data -e -w 0x$DATA_OBJECT_OID -i data.dat
xxd data.dat
echo "set 0x$DATA_OBJECT_OID Auto with 0x$SHARED_SECRET_OID"
echo "0323$SHARED_SECRET_OID" | xxd -r -p > data_object_auto_metadata.bin

echo "Print out metadata of 0x$DATA_OBJECT_OID."
xxd data_object_auto_metadata.bin
echo "Set the metadata of 0x$DATA_OBJECT_OID to Auto change/Read with 0x$SHARED_SECRET_OID."
$EXEPATH/trustm_metadata -w 0x$DATA_OBJECT_OID -Cf:data_object_auto_metadata.bin -Rf:data_object_auto_metadata.bin 
sleep 3
done
