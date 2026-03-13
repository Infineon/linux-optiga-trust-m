#!/bin/bash
source config.sh

echo "Read out metadata for 0x$TARGET_AES_OID"
$EXEPATH/trustm_metadata -r  0x$TARGET_AES_OID | tee aes_metadata.txt
payload_version_hex=$(grep -oP 'C1 02 \K(..) (..)' aes_metadata.txt | tr -d ' ')
PAYLOAD_VERSION=$(printf "%04X" $payload_version_hex)
NEW_PAYLOAD_VERSION=$((PAYLOAD_VERSION + 1))
AES_NEW_PAYLOAD_VERSION=$(printf "%04X" $NEW_PAYLOAD_VERSION)
echo "Current Payload version: 0x$PAYLOAD_VERSION"
echo "Increase payload version by 1: 0x$AES_NEW_PAYLOAD_VERSION"

echo "Generate manifest & fragment for AES key protected update"
raw_output=$($UPDATEPATH/trustm_protected_update_set payload_version="$AES_NEW_PAYLOAD_VERSION" trust_anchor_oid=$TRUST_ANCHOR_OID target_oid=$TARGET_AES_OID sign_algo=$SIGN_ALGO priv_key="$TRUST_ANCHOR_PRIV_KEY" payload_type=key key_algo="$KEY_ALGO" key_usage="$KEY_USAGE" key_data="$AES_KEY_TO_UPDATE" label="test" seed_length=64 enc_algo="AES-CCM-16-64-128" secret_oid=$PROTECTED_UPDATE_SECRET_OID secret="$PROTECTED_UPDATE_SECRET") 
manifest_hex=$(echo "$raw_output" | awk '
    /uint8_t manifest_data/ {p=1; next}
    p && /fragment_01/ {p=0}
    p {gsub(/0x|[, \t]/,""); if ($0 ~ /^[0-9a-fA-F]+$/) print}
' | tr -d '\n')

fragment_hex=$(echo "$raw_output" | awk '
    /uint8_t fragment_01/ {p=1; next}
    p && /}/ {p=0}
    p {gsub(/0x|[, \t]/,""); if ($0 ~ /^[0-9a-fA-F]+$/) print}
' | tr -d '\n')
echo -n "$manifest_hex"  | xxd -r -p > aes_manifest.dat 
echo "Printout aes_manifest.dat"
xxd aes_manifest.dat
echo -n "$fragment_hex"  | xxd -r -p > aes_fragment.dat
echo "Printout aes_fragment.dat"
xxd aes_fragment.dat
