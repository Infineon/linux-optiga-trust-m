#!/bin/bash
source config.sh

set -e

#### Configurable Variables Start

## Trust Anchor OID and Metadata settings for integrity protect
# Trust Anchor OID
TRUST_ANCHOR_OID=e0e3
# Trust Anchor metadata setting
TRUST_ANCHOR_META="2003E80111"

## PROTECTED UPDATE OID and Metadata settings for confidentiality protect
# Protected Update OID
PROTECTED_UPDATE_SECRET_OID=f1d4
# Shared Secret Data, must match with the host C codes
PROTECTED_UPDATE_SECRET="49C9F492A992F6D4C54F5B12C57EDB27CED224048F25482AA149C9F492A992F649C9F492A992F6D4C54F5B12C57EDB27CED224048F25482AA149C9F492A992F6"
# Protected Update OID metadata setting
PROTECTED_UPDATE_SECRET_META="200BD103E1FC07D30100E80123"

# Target OID
TARGET_OID=e0f1
# Target OID metadata setting for ECC Key protected update
#~ TARGET_OID_META="2009C1020000D00321${TRUST_ANCHOR_OID}"
TARGET_OID_META="200dC1020000D00721${TRUST_ANCHOR_OID}FD20${PROTECTED_UPDATE_SECRET_OID}"

echo "Prepare binary protected update secret."
echo $PROTECTED_UPDATE_SECRET | xxd -r -p > protected_update_secret.dat


#### Configurable Variables End

for i in $(seq 1 1); do
echo "test $i"

#~ echo "Step1: Provisioning initial Trust Anchor, metadata for Trust Anchor"
#~ echo "Write sample_ec_256_cert.pem into 0x$TRUST_ANCHOR_OID"
#~ $EXEPATH/trustm_cert -w 0x$TRUST_ANCHOR_OID -i $CERT_PATH/sample_ec_256_cert.pem
#~ echo "Set device type to TA for 0x$TRUST_ANCHOR_OID "
#~ echo $TRUST_ANCHOR_META | xxd -r -p > trust_anchor_metadata.bin
#~ echo "Printout trust_anchor_metadata.bin"
#~ xxd trust_anchor_metadata.bin
#~ echo "write trust_anchor_metadata.bin as metadata of 0x$TRUST_ANCHOR_OID"
#~ $EXEPATH/trustm_metadata -w 0x$TRUST_ANCHOR_OID -F trust_anchor_metadata.bin
#~ echo "Read out metadata for 0x$TRUST_ANCHOR_OID"
#~ $EXEPATH/trustm_metadata -r  0x$TRUST_ANCHOR_OID

#~ echo "Step2: Provisioning Protected Update Secret OID, metadata for Protected Update Secret OID"
#~ echo "Write Protected Update Secret into 0x$PROTECTED_UPDATE_SECRET_OID"
#~ $EXEPATH/trustm_data -e -w 0x$PROTECTED_UPDATE_SECRET_OID -i protected_update_secret.dat
#~ echo "Set device type to UPDATSEC for 0x$PROTECTED_UPDATE_SECRET_OID "
#~ echo $PROTECTED_UPDATE_SECRET_META | xxd -r -p > protected_update_secret_metadata.bin
#~ echo "Printout protected_update_secret_metadata.bin"
#~ xxd protected_update_secret_metadata.bin
#~ echo "write protected_update_secret_metadata.bin as metadata of 0x$PROTECTED_UPDATE_SECRET_OID"
#~ $EXEPATH/trustm_metadata -w 0x$PROTECTED_UPDATE_SECRET_OID -F protected_update_secret_metadata.bin
#~ echo "Read out metadata for 0x$PROTECTED_UPDATE_SECRET_OID"
#~ $EXEPATH/trustm_metadata -r  0x$PROTECTED_UPDATE_SECRET_OID

echo "Step3: Provisioning metadata for 0x$TARGET_OID"
echo "Set AES protected update for 0x$TARGET_OID (Provision for Protected Update)"
echo $TARGET_OID_META | xxd -r -p > targetOID_metadata.bin
echo "Printout targetOID_metadata.bin"
xxd targetOID_metadata.bin
echo "Write targetOID_metadata.bin as metadata of 0x$TARGET_OID"
$EXEPATH/trustm_metadata -w 0x$TARGET_OID -F targetOID_metadata.bin
echo "Read out metadata for 0x$TARGET_OID"
$EXEPATH/trustm_metadata -r  0x$TARGET_OID 

#~ echo "Step4: Set 0x$TARGET_OID to Operational mode"
#~ echo "Change 0x$TARGET_OID Lcs0 to Operational mode"
#~ $EXEPATH/trustm_metadata -w  0x$TARGET_OID -O
#~ echo "read out metadata for 0x$TARGET_OID"
#~ $EXEPATH/trustm_metadata -r  0x$TARGET_OID 

sleep 1
done

