#!/bin/bash
source config.sh

#### Configurable Variables Start

## Target OID for metadata protected update, manifest and final fragment
# Target OID
TARGET_OID=e0e1
# Manifest used for metadata protected update (To Creation)
MANIFEST="8443A10126A10442E0E3583B8601F6F684210D03820000828220582582182958201267B0CCD50244E5B59386B5D3943B853F1A3FAB4727C79E19A4642B2A985A2DF6824042E0E15840F12F2F3095C9A2731F8A083C6611DEAEF09BC31A01B124C21CB8B72FF4233D95F8E5B25093C88E8C0E61C36E3FBE0299D321CC3EE50D409BA3A6E52B0F9561FB"
# Final fragment used for metadata protected update (To Creation)
FINAL_FRAGMENT="200BC00101D10100D003E1FC07"


#### Configurable Variables End

# Perform multiple sequential read
echo "Prepare binary shared secret."
echo $MANIFEST | xxd -r -p > manifest.dat
#~ xxd manifest.dat
echo "Prepare binary data to be init."
echo $FINAL_FRAGMENT | xxd -r -p > final_fragment.dat
#~ xxd final_fragment.dat

for i in $(seq 1 1); do
echo "test $i"

echo "Metadata protected update for 0x$TARGET_OID"
$EXEPATH/trustm_protected_update -k 0x$TARGET_OID -m manifest.dat -f final_fragment.dat
echo "read out metadata for 0x$TARGET_OID"
$EXEPATH/trustm_metadata -r  0x$TARGET_OID -X



sleep 1
done
