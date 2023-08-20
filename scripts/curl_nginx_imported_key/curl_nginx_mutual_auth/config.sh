PROJECT_DIR=$(dirname "$(dirname "$(dirname "$(pwd)")")")
EXEPATH="$PROJECT_DIR/bin"
CERT_PATH="$PROJECT_DIR/scripts/certificates"

#~ Server certificate related defintions
SERVER_CSR=server1.csr
SERVER_CERT_NAME=server1.crt.pem
SERVER_PRIVATE_KEY=server1_privkey.pem

#~ Client certificate related definitions
CLIENT_CSR=client1.csr
CLIENT_CERT_NAME=client1.crt.pem
CLIENT_PRIVATE_KEY=client1_privkey.pem
CLIENT_PUBKEY_KEY=client1_pubkey.pem
CLIENT_PUBKEY_KEY_DER=client1_pubkey.der

#~ Certificate Authority related parameters
## Note: do not use this as productive key or certifiacte
CA_KEY=$CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem
CA_CERT=$CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem

#~ Optiga Trust M Key OIDs definitions, 
## RSA Key parameters
TRUST_M_RSA_KEY_EXT_OID=0xe0fc:$CLIENT_PUBKEY_KEY
TRUST_M_RSA_KEY_OID=0xe0fc:^
TRUST_M_RSA_KEY_GEN=0xe0fc:^:NEW:0x42:0x13
TRUST_M_RSA_PUBKEY_OID=0xf1e0
## ECC Key parameters
TRUST_M_ECC_KEY_EXT_OID=0xe0f1:$CLIENT_PUBKEY_KEY
TRUST_M_ECC_KEY_OID=0xe0f1:^
TRUST_M_ECC_KEY_GEN=0xe0f1:^:NEW:0x03:0x13
TRUST_M_ECC_PUBKEY_OID=0xf1d1



