#!/bin/bash
source config.sh


set -e

#### Configurable Variables Start
# Monotonic Counter
COUNTER_OID=e120
# Data object OID
DATA_OBJECT_OID=e0fd

# Protected Update metadata setting
DATA_OBJ_META="0340$COUNTER_OID"

echo "test $i"
echo "Hello World" > helloworld.txt
echo "set metadata for 0x$DATA_OBJECT_OID"
echo $DATA_OBJ_META | xxd -r -p > counter_metadata.bin
echo "Printout counter_metadata.bin"
xxd counter_metadata.bin

echo "Set the metadata of 0x$DATA_OBJECT_OID to excute Conf(0x$BINDING_SECRET_OID)."
$EXEPATH/trustm_metadata -w 0x$DATA_OBJECT_OID -Ef:counter_metadata.bin 
echo "Executing trustm_monotonic_counter commands"
echo "Setting threshold value to 100 and reset counter to zero"
$EXEPATH/trustm_monotonic_counter -w 0xe120 -i 5

echo "Count up monotonic counter in steps of 1"
$EXEPATH/trustm_monotonic_counter -u 0xe120 -s 1
$EXEPATH/trustm_monotonic_counter -r 0xe120
echo "-----> Trust M Generate RSA 2048 Privete key "
$EXEPATH/trustm_rsa_keygen -g 0x$DATA_OBJECT_OID -t 0x13 -k 0x41 -o rsa_e0fd_pub.pem -s 

for i in $(seq 1 7); do
echo "-----> Trust M Generate RSA 2048 Privete key "
$EXEPATH/trustm_rsa_sign -k 0x$DATA_OBJECT_OID -o testsignature.bin -i helloworld.txt -H

$EXEPATH/trustm_monotonic_counter -r 0xe120


sleep 1
done
