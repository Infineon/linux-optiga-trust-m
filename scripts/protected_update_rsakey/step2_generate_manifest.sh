#!/bin/bash
source config.sh

echo "Read out metadata for 0x$TARGET_RSA_OID"
$EXEPATH/trustm_metadata -r  0x$TARGET_RSA_OID | tee rsa_metadata.txt
payload_version_hex=$(grep -oP 'C1 02 \K(..) (..)' rsa_metadata.txt | tr -d ' ')
PAYLOAD_VERSION=$((0x$payload_version_hex))
echo "Current payload version: 0x$(printf '%04X' "$PAYLOAD_VERSION")  (${PAYLOAD_VERSION})"
if ((PAYLOAD_VERSION >= 0x7FFF )); then
    echo "Reached maximum payload value 0x7FFF!"
    echo "Please run step0_reset_payload_version.sh to reset payload version!"
fi    
NEW_PAYLOAD_VERSION=$((PAYLOAD_VERSION + 1))
RSA_NEW_PAYLOAD_VERSION=$(printf "%04X" $NEW_PAYLOAD_VERSION)
echo "New payload version : 0x${RSA_NEW_PAYLOAD_VERSION}  (${NEW_PAYLOAD_VERSION})"

echo "Generate manifest & fragment for RSA key protected update"
raw_output=$($UPDATEPATH/trustm_protected_update_set payload_version="$NEW_PAYLOAD_VERSION" trust_anchor_oid=$TRUST_ANCHOR_OID target_oid=$TARGET_RSA_OID sign_algo=$SIGN_ALGO priv_key="$TRUST_ANCHOR_PRIV_KEY" payload_type=key key_algo="$KEY_ALGO" key_usage="$KEY_USAGE" key_data="$RSA_PRIKEY_TO_UPDATE" label="test" seed_length=64 enc_algo="AES-CCM-16-64-128" secret_oid=$PROTECTED_UPDATE_SECRET_OID secret="$PROTECTED_UPDATE_SECRET") 
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
echo -n "$manifest_hex"  | xxd -r -p > rsa_manifest.dat 
echo "Printout rsa_manifest.dat"
xxd rsa_manifest.dat
echo -n "$fragment_hex"  | xxd -r -p > rsa_fragment.dat
echo "Printout rsa_fragment.dat"
xxd rsa_fragment.dat
