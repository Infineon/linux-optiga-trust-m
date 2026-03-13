PROJECT_DIR=$(dirname "$(dirname "$(pwd)")")
EXEPATH="$PROJECT_DIR/bin"
CERT_PATH="$PROJECT_DIR/scripts/certificates"
UPDATEPATH="$PROJECT_DIR/ex_protected_update_data_set/Linux/bin"
PAYLOADPATH="$PROJECT_DIR/ex_protected_update_data_set/samples/payload/key"
SECRETPATH="$PROJECT_DIR/ex_protected_update_data_set/samples/confidentiality"

# OIDs for AES Key Protected Update
TRUST_ANCHOR_OID="e0e8"
PROTECTED_UPDATE_SECRET_OID="f1d4"               
TARGET_AES_OID="e200" 

# Paths to Required files (adjust to your actual paths)
TRUST_ANCHOR_CERT="$CERT_PATH/sample_ec_256_cert.pem"
TRUST_ANCHOR_PRIV_KEY="$CERT_PATH/sample_ec_256_priv.pem"
PROTECTED_UPDATE_SECRET="$SECRETPATH/secret.txt"
AES_KEY_TO_UPDATE="$PAYLOADPATH/aes_key_256.txt" 

# Metadata setting
TRUST_ANCHOR_META="2003E80111"
PROTECTED_UPDATE_SECRET_META="200BD103E1FC07D30100E80123"
TARGET_AES_OID_META="200dC1020000D00721${TRUST_ANCHOR_OID}FD20${PROTECTED_UPDATE_SECRET_OID}"

# Algorithms for AES Protected Update
SIGN_ALGO="ES_256"
AES_ENC_ALGO="AES-CCM-16-64-128"
KEY_USAGE="02"                  # AES key usage: 02 for Encryption and 13 for Auth/ENC/Sign
KEY_ALGO="131"                  # 131 for AES-256, 130 for AES-192 and 129 for AES-128

