#!/bin/bash
source config.sh

set -e



echo "Client1:-----> Update Public key store into Optiga Trust M"
$EXEPATH/trustm_data -w 0x$PUBKEY_OID_RSA -i $TEMP_PUBKEY_KEY_DER_RSA -e

echo "Client1:-----> Generate Manifest"
$UPDATEPATH/trustm_protected_update_set payload_version=$PAYLOAD_VER trust_anchor_oid=$TRUST_ANCHOR target_oid=$TARGET_OID_RSA sign_algo=$SIGN_ALGO priv_key=$PRIV_KEY payload_type=key key_algo=65 key_usage=13 key_data=$TEMP_KEY_RSA secret=$SECRET label="ecc_key" seed_length=64 enc_algo="AES-CCM-16-64-128" secret_oid=$SECRET_OID
#~ rm $TEMP_KEY
echo "Protected RSA Key Update for 0x$TARGET_OID_RSA"
$EXEPATH/trustm_protected_update_rsakey -k 0x$TARGET_OID_RSA -m manifest2.dat -f fragment2.dat
echo "read out metadata for 0x$TARGET_OID_RSA"
$EXEPATH/trustm_metadata -r  0x$TARGET_OID_RSA -X





