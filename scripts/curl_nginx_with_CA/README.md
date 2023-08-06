## CURL and NGINX with certificates issuance by Certificate Authority

The usage parameters in "config.sh" can be configured depends on application [config.sh](./config.sh)

```sh
#~ Server certificate related defintions
SERVER_CSR=server1.csr
SERVER_CERT_NAME=server1.crt.pem
SERVER_PRIVATE_KEY=server1_privkey.pem

#~ Client certificate related definitions
CLIENT_CSR=client1.csr
CLIENT_CERT_NAME=client1.crt.pem

#~ Certificate Authority related parameters
#~ Note: do not use this as productive key or certifiacte
CA_KEY=$CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem
CA_CERT=$CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem

#~ Optiga Trust M Key OIDs definitions, 
TRUST_M_RSA_KEY_OID=0xe0fc:^
TRUST_M_RSA_KEY_GEN=0xe0fc:^:NEW:0x42:0x13

TRUST_M_ECC_KEY_OID=0xe0f1:^
TRUST_M_ECC_KEY_GEN=0xe0f1:^:NEW:0x03:0x13

#~ Selection of RSA or ECC depends on application is done here
KEY_OID=$TRUST_M_ECC_KEY_OID
KEY_GEN=$TRUST_M_ECC_KEY_GEN
```

To change to RSA key change the KEY_OID and KEY_GEN parameters as follow:

```sh
KEY_OID=$TRUST_M_RSA_KEY_OID
KEY_GEN=$TRUST_M_RSA_KEY_GEN
```

## Generating Server/Clients certificates 

Run the [step1_generate_keys.sh](./step1_generate_keys.sh) , the server and client keys will be generated. Then the corresponding certificates will be issued by a test Certificate Authority(CA).

*Note: Do not use this Test CA in productive usage*

###   Server Key generation and Certificate Issuance

```sh
echo "Server1: -----> Generate Server ECC Private Key"
openssl ecparam -out server1_privkey.pem -name prime256v1 -genkey
echo "Server1:-----> Generate Server ECC Keys CSR"
openssl req -new  -key server1_privkey.pem -subj /CN=127.0.0.1/O=Infineon/C=SG -out $SERVER_CSR
echo "Server1:-----> Generate Server cetificate by using CA"
openssl x509 -req -in $SERVER_CSR -CA $CA_CERT  -CAkey $CA_KEY -CAcreateserial -out $SERVER_CERT_NAME -days 3650 -sha256 -extfile openssl.cnf -extensions cert_ext
```

###  Client Key generation and Certificate Issuance

This will generate client private key(ECC 256, Auth/Enc/Sing) in OPTIGA™ Trust M using using OID 0xe0f1 and certificate "client1.crt.pem" 

(see [req](#req) for input details)

```sh
echo "Client1:-----> Creates new key length and Auth/Enc/Sign usage and generate a certificate request"
openssl req -keyform engine -engine trustm_engine -key $KEY_GEN -new -out $CLIENT_CSR -subj "/CN=TrustM/O=Infineon/C=SG"

echo "Client1:-----> Generate Client cetificate by using CA"
openssl x509 -req -in $CLIENT_CSR -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out $CLIENT_CERT_NAME -days 3650 -sha256 -extfile openssl.cnf -extensions cert_ext1
```



### Setup NGINX 

This will setup the NGINX server to use openssl, setting the server key and certificate to use in the default file setting(/etc/nginx/sites-enabled/default).
The nginx service will be restarted for the new settings to take effect. Refer to  [step2_configure_nginx.sh](./step2_configure_nginx.sh)


Run the steps below:
```sh
sudo cp default /etc/nginx/sites-enabled/default
sudo cp server1.crt.pem /etc/nginx/server1.crt.pem
sudo cp server1_privkey.pem /etc/nginx/server1_privkey.pem
sudo service nginx restart
```
After running the steps above, the following changes will be made to "default" file:
```
listen 443 ssl default_server;
listen [::]:443 ssl default_server;
ssl_certificate server1.crt.pem; 
ssl_certificate_key server1_privkey.pem;
```
#### Testing CURL Client with OPTIGA™ Trust M Key 

This will connect the Client to the web server with engine key interface using OPTIGA™ Trust M.  Refer to [step3_test_curl_client.sh](./step3_test_curl_client.sh)

```sh
echo "Client1:-----> test curl client"
curl -v --engine trustm_engine --key-type ENG --key $KEY_OID --cert $CLIENT_CERT_NAME --cacert $CA_CERT https://127.0.0.1
```