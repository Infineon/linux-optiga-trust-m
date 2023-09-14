PROJECT_DIR=$(dirname "$(dirname "$(dirname "$(pwd)")")")
EXEPATH="$PROJECT_DIR/bin"
CERT_PATH="$PROJECT_DIR/scripts/certificates"
UPDATEPATH="$PROJECT_DIR/ex_protected_update_data_set/Linux/bin"


#~ Client certificate related definitions
CLIENT_PKCS12_FILE=client1.p12
TEMP_PUBKEY_KEY=temp_pubkey.pem
TEMP_PUBKEY_KEY_DER=temp_pubkey.der
TEMP_KEY=temp_key.pem
TEMP_CERT=client1.crt.pem


#Protected update relate definitions
PAYLOAD_VER=2
TRUST_ANCHOR=e0e8
TARGET_OID=e0f1
SECRET_OID=f1d4
SIGN_ALGO=ES_256
PRIV_KEY=$CERT_PATH/sample_ec_256_priv.pem
SECRET=./generate_p12/secret.txt

#~ Server certificate related defintions
SERVER_CSR=server1.csr
SERVER_CERT_NAME=server1.crt.pem
SERVER_PRIVATE_KEY=server1_privkey.pem

#~ Certificate Authority related parameters
## Note: do not use this as productive key or certifiacte
CA_KEY=$CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem
CA_CERT=$CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem
