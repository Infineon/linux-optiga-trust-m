#!/bin/bash
source config.sh

# Perform multiple sequential read

#### Configurable Variables Start

## Trust Anchor OID, Binding secret OID and Metadata settings
# Trust Anchor OID
TRUST_ANCHOR_OID=e0e3
# Trust Anchor metadata setting
TRUST_ANCHOR_META="2011C00101D003E1FC07D10100D30100E80111"

## Binding secret to be written into the Binding secret object, Binding secret OID and metadata definitions
# Binding secret OID
BINDING_SECRET_OID=E140
# Binding secret to be written
BINDING_SECRET="0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40"
# metadata setting for protected update
BINDING_SECRET_META="200CC1020000F00101D80321$TRUST_ANCHOR_OID"
#### Configurable Variables End

echo "Prepare Binding Secret to be init."
echo $BINDING_SECRET | xxd -r -p > binding_secret.dat
#~ xxd binding_secret.dat


for i in $(seq 1 1); do
echo "test $i"
echo "Step1: Provisioning Trust Anchor, metadata for Trust Anchor"
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

#~ echo "Set 0x$TRUST_ANCHOR_OID to OP"
#~ $EXEPATH/trustm_metadata -w 0x$TRUST_ANCHOR_OID -O

echo "Set metadata for OID 0x$BINDING_SECRET_OID"
echo $BINDING_SECRET_META | xxd -r -p > binding_secret_metadata.bin
echo "Printout binding_secret_metadata.bin"
xxd binding_secret_metadata.bin
echo "write binding_secret_metadata.bin as metadata of 0x$BINDING_SECRET_OID"
$EXEPATH/trustm_metadata -w 0x$BINDING_SECRET_OID -F binding_secret_metadata.bin
echo "Read out metadata for 0x$BINDING_SECRET_OID"
$EXEPATH/trustm_metadata -r  0x$BINDING_SECRET_OID

echo "Write binding secret into 0x$BINDING_SECRET_OID"
$EXEPATH/trustm_data -w 0x$BINDING_SECRET_OID -i binding_secret.dat
echo "Read out data for 0x$BINDING_SECRET_OID"
$EXEPATH/trustm_data -r 0x$BINDING_SECRET_OID

#~ echo "Set 0x$BINDING_SECRET_OID to OP"
#~ $EXEPATH/trustm_metadata -w 0x$BINDING_SECRET_OID -O

sleep 1
done
