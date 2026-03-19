#!/bin/bash
source config.sh

set -e

echo "provisioning for metadata Protected Update"
echo "Step1: Provisioning initial Trust Anchor, metadata for Trust Anchor"
echo "Write sample_ec_256_cert.pem into 0x$TRUST_ANCHOR_OID"
$EXEPATH/trustm_cert -w 0x$TRUST_ANCHOR_OID -i "$TRUST_ANCHOR_CERT"
echo "Set device type to TA for 0x$TRUST_ANCHOR_OID "
echo $TRUST_ANCHOR_META | xxd -r -p > trust_anchor_metadata.bin
echo "Printout trust_anchor_metadata.bin"
xxd trust_anchor_metadata.bin
echo "write trust_anchor_metadata.bin as metadata of 0x$TRUST_ANCHOR_OID"
$EXEPATH/trustm_metadata -w 0x$TRUST_ANCHOR_OID -F trust_anchor_metadata.bin
echo "Read out metadata for 0x$TRUST_ANCHOR_OID"
$EXEPATH/trustm_metadata -r  0x$TRUST_ANCHOR_OID

echo "Step2: Provisioning Protected Update Secret OID, metadata for Protected Update Secret OID"
echo "Write Protected Update Secret into 0x$PROTECTED_UPDATE_SECRET_OID"
xxd -r -p "$PROTECTED_UPDATE_SECRET" > protected_update_secret.dat
$EXEPATH/trustm_data -e -w 0x$PROTECTED_UPDATE_SECRET_OID -i protected_update_secret.dat
echo "Set device type to UPDATSEC for 0x$PROTECTED_UPDATE_SECRET_OID "
echo $PROTECTED_UPDATE_SECRET_META | xxd -r -p > protected_update_secret_metadata.bin
echo "Printout protected_update_secret_metadata.bin"
xxd protected_update_secret_metadata.bin
echo "write protected_update_secret_metadata.bin as metadata of 0x$PROTECTED_UPDATE_SECRET_OID"
$EXEPATH/trustm_metadata -w 0x$PROTECTED_UPDATE_SECRET_OID -F protected_update_secret_metadata.bin
echo "Read out metadata for 0x$PROTECTED_UPDATE_SECRET_OID after Provisioning"
$EXEPATH/trustm_metadata -r  0x$PROTECTED_UPDATE_SECRET_OID

echo "Step3: Provisioning metadata for 0x$TARGET_OID"
echo "Set metadata for 0x$TARGET_OID (Provision for Protected Update)"
echo $TARGET_OID_META | xxd -r -p > targetOID_metadata.bin
echo "Printout targetOID_metadata.bin"
xxd targetOID_metadata.bin
echo "Write targetOID_metadata.bin as metadata of 0x$TARGET_OID"
$EXEPATH/trustm_metadata -w 0x$TARGET_OID -F targetOID_metadata.bin
echo "Change Lcso from creation to initialization for 0x$TARGET_OID (for testing)"
$EXEPATH/trustm_metadata -w 0x$TARGET_OID -I 
echo "Read out metadata of 0x$TARGET_OID"
$EXEPATH/trustm_metadata -r 0x$TARGET_OID 


