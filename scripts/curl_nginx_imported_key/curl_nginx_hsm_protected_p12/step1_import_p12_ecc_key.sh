#!/bin/bash
source config.sh

set -e

echo "Client1:-----> Exporting the keys from PKCS12 file"

openssl pkcs12 -in $CLIENT_PKCS12_FILE -nodes -out $TEMP_KEY
openssl x509 -in $TEMP_KEY -out $TEMP_CERT


echo "Client1:-----> Extracting public key in PEM and DER from certificate"
openssl x509 -pubkey -noout -in $TEMP_CERT  > $TEMP_PUBKEY_KEY
#~ openssl x509 -pubkey -noout -in $TEMP_CERT | openssl enc -base64 -d > $TEMP_PUBKEY_KEY_DER


echo "Client1:-----> Generate Manifest"
$UPDATEPATH/trustm_protected_update_set payload_version=$PAYLOAD_VER trust_anchor_oid=$TRUST_ANCHOR target_oid=$TARGET_OID sign_algo=$SIGN_ALGO priv_key=$PRIV_KEY payload_type=key key_algo=03 key_usage=10 key_data=$TEMP_KEY secret=$SECRET label="ecc_key" seed_length=64 enc_algo="AES-CCM-16-64-128" secret_oid=$SECRET_OID
#~ rm $TEMP_KEY
echo "Protected ECC Key Update for 0x$TARGET_OID"
$EXEPATH/trustm_protected_update_ecckey -k 0x$TARGET_OID -m manifest1.dat -f fragment1.dat
echo "read out metadata for 0x$TARGET_OID"
$EXEPATH/trustm_metadata -r  0x$TARGET_OID -X





