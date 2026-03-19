PROJECT_DIR=$(dirname "$(dirname "$(pwd)")")
EXEPATH="$PROJECT_DIR/bin"
CERT_PATH="$PROJECT_DIR/scripts/certificates"
UPDATEPATH="$PROJECT_DIR/ex_protected_update_data_set/Linux/bin"
PAYLOADPATH="$PROJECT_DIR/ex_protected_update_data_set/samples/payload/metadata"
SECRETPATH="$PROJECT_DIR/ex_protected_update_data_set/samples/confidentiality"

# OIDs for metadata Protected Update
TRUST_ANCHOR_OID="e0e8"
PROTECTED_UPDATE_SECRET_OID="f1d4"               
TARGET_OID="f1d6" 

# Paths to Required files (adjust to your actual paths)
TRUST_ANCHOR_CERT="$CERT_PATH/sample_ec_256_cert.pem"
TRUST_ANCHOR_PRIV_KEY="$CERT_PATH/sample_ec_256_priv.pem"
PROTECTED_UPDATE_SECRET="$SECRETPATH/secret.txt"
METADATA_TO_UPDATE="$PAYLOADPATH/metadata.txt" 

# Metadata setting
TRUST_ANCHOR_META="2003E80111"
PROTECTED_UPDATE_SECRET_META="200BD103E1FC07D30100E80123"
TARGET_OID_META="2010C1020000F00111D80721${TRUST_ANCHOR_OID}FD20${PROTECTED_UPDATE_SECRET_OID}"

# Algorithms for metadata Protected Update
SIGN_ALGO="ES_256"
AES_ENC_ALGO="AES-CCM-16-64-128"
