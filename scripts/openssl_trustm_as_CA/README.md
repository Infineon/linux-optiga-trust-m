## Using OPTIGA™ Trust M as Certificate Authority

Run the **trustm_ca_gen_cert.sh** which will:

- Generate CA key and certificate with OPTIGA™ Trust M as HSM
- Generate example device ECC key and corresponding CSR with subject: **/CN=TrustM_Dev1/O=Infineon/C=SG**. Note that each CN field need to be unique for each certificate to be generated.
- Issue device certificate by signing CSR with OPTIGA™ Trust M. Certificate issued will be store in **demoCA/newcerts** folder.

```sh
#!/bin/bash
PROJECT_DIR=$(dirname "$(dirname "$(pwd)")")
EXEPATH="$PROJECT_DIR/bin"
mkdir -p ./demoCA/newcerts


set -e

echo "CA:-----> Generate Trust M CA key and cert"
echo "Executing 'openssl req -x509 -provider trustm_provider -provider default -key 0xe0f1:^:NEW:0x03:0x13 -new -out ./demoCA/cacert.pem -subj /CN=trustmCA -sha256 -extensions v3_req'"
openssl req -x509 -provider trustm_provider -provider default -key 0xe0f1:^:NEW:0x03:0x13 -new -out ./demoCA/cacert.pem -subj /CN=trustmCA -sha256 -extensions v3_req
echo "Executing'openssl x509 -in ./demoCA/cacert.pem -text'"
openssl x509 -in ./demoCA/cacert.pem -text


echo "-----> Generate Device ECC Private Key"
echo "Executing 'openssl ecparam -out dev_privkey.pem -name prime256v1 -genkey'"
openssl ecparam -out dev_privkey.pem -name prime256v1 -genkey
echo "Executing'openssl ec -in dev_privkey.pem -text -noout'"
openssl ec -in dev_privkey.pem -text -noout


echo "Device:-----> Generate Device CSR"
echo "Executing 'openssl req -new  -key dev_privkey.pem -subj /CN=TrustM_Dev1/O=Infineon/C=SG -out dev.csr'"
openssl req -new  -key dev_privkey.pem -subj /CN=TrustM_Dev1/O=Infineon/C=SG -out dev.csr


echo "CA:-----> Generate device cetificate by using CA"
echo "Executing 'openssl ca -batch -create_serial -provider trustm_provider -provider default -keyfile 0xe0f1:^ -in dev.csr -out dev.pem -cert ./demoCA/cacert.pem -days 3650 -config openssl.cnf -md sha256'"
openssl ca -batch -create_serial -provider trustm_provider -provider default -keyfile 0xe0f1:^ -in dev.csr -out ./demoCA/newcerts/dev.pem -cert ./demoCA/cacert.pem -days 3650 -config openssl.cnf -md sha256
echo "Executing 'openssl x509 -in dev.pem -text'"
openssl x509 -in ./demoCA/newcerts/dev.pem -text
```

Note: To reset the folder to initial state, run **clean.sh**. All certificates issued and tracking will be **permanently** erased.