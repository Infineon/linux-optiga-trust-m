PROJECT_DIR=$(dirname "$(dirname "$(dirname "$(pwd)")")")
EXEPATH="$PROJECT_DIR/bin"
CERT_PATH="$PROJECT_DIR/scripts/certificates"
UPDATEPATH="$PROJECT_DIR/ex_protected_update_data_set/Linux/bin"


#~ Client certificate related definitions

TEMP_PUBKEY_KEY_ECC=temp_pubkey_ecc.pem
TEMP_PUBKEY_KEY_DER_ECC=temp_pubkey_ecc.der
TEMP_KEY=./generate_p12/client1_ecc_privkey.pem
TEMP_CERT=./generate_p12/client1_ecc.crt.pem

TEMP_PUBKEY_KEY_RSA=./generate_p12/temp_pubkey_rsa.pem
TEMP_PUBKEY_KEY_DER_RSA=./generate_p12/temp_pubkey_rsa.der
TEMP_KEY_RSA=./generate_p12/client1_rsa_privkey.pem
TEMP_CERT_RSA=./generate_p12/client1_rsa.crt.pem




#Protected update relate definitions
PAYLOAD_VER=1
TRUST_ANCHOR=e0e8
TARGET_OID=e0f1
PUBKEY_OID=f1d1
#~ TARGET_OID=e0f2
#~ PUBKEY_OID=f1d2
#~ TARGET_OID=e0f3
#~ PUBKEY_OID=f1d3

TARGET_OID_RSA=e0fc
PUBKEY_OID_RSA=f1e0
#~ TARGET_OID_RSA=e0fd
#~ PUBKEY_OID_RSA=f1e1

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
