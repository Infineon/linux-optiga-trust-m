#!/bin/bash
source config.sh

#### Configurable Variables Start

## Trust Anchor OID and Metadata settings for integrity protect
# Trust Anchor OID
TRUST_ANCHOR_OID=e0e3
# Trust Anchor metadata setting
TRUST_ANCHOR_META="2011C00101D003E1FC07D10100D30100E80111"
# Target OID
TARGET_OID=e0e1
# Target OID metadata setting for protected update 
TARGET_OID_META="200CC1020000F00111D80321$TRUST_ANCHOR_OID"

#### Configurable Variables End

for i in $(seq 1 1); do
echo "test $i"

echo "Step1: Provisioning initial Trust Anchor, metadata for Trust Anchor"
echo "Write Test Trust Anchor into 0x$TRUST_ANCHOR_OID"
$EXEPATH/trustm_cert -w 0x$TRUST_ANCHOR_OID -i $CERT_PATH/Test_Trust_Anchor.pem
echo "Set device type to TA for 0x$TRUST_ANCHOR_OID "
echo $TRUST_ANCHOR_META | xxd -r -p > trust_anchor_metadata.bin
echo "Printout trust_anchor_metadata.bin"
xxd trust_anchor_metadata.bin
echo "write trust_anchor_metadata.bin as metadata of 0x$TRUST_ANCHOR_OID"
$EXEPATH/trustm_metadata -w 0x$TRUST_ANCHOR_OID -F trust_anchor_metadata.bin
echo "Read out metadata for 0x$TRUST_ANCHOR_OID"
$EXEPATH/trustm_metadata -r  0x$TRUST_ANCHOR_OID

echo "Step2: Provisioning metadata for 0x$TARGET_OID"
echo "Set protected update for 0x$TARGET_OID (Provision for Protected Update)"
echo $TARGET_OID_META | xxd -r -p > targetOID_metadata.bin
echo "Printout targetOID_metadata.bin"
xxd targetOID_metadata.bin
echo "Write targetOID_metadata.bin as metadata of 0x$TARGET_OID"
$EXEPATH/trustm_metadata -w 0x$TARGET_OID -F targetOID_metadata.bin
echo "Read out metadata for 0x$TARGET_OID"
$EXEPATH/trustm_metadata -r  0x$TARGET_OID 

#~ echo "Step3: Set 0x$TARGET_OID to Operational mode"
#~ echo "Change 0x$TARGET_OID Lcs0 to Operational mode"
#~ $EXEPATH/trustm_metadata -w  0x$TARGET_OID -O
#~ echo "read out metadata for 0x$TARGET_OID"
#~ $EXEPATH/trustm_metadata -r  0x$TARGET_OID 

sleep 1
done
