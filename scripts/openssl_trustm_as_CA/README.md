## Using OPTIGA™ Trust M as Certificate Authority

Run the **trustm_ca_gen_cert.sh** which will:

- Generate CA key and certificate with OPTIGA™ Trust M as HSM
- Generate example device ECC key and corresponding CSR with subject: **/CN=TrustM_Dev1/O=Infineon/C=SG**. Note that each CN field need to be unique for each certificate to be generated.
- Issue device certificate by signing CSR with OPTIGA™ Trust M. Certificate issued will be store in **demoCA/newcerts** folder.

```sh
echo "CA:-----> Generate Trust M CA key and cert"
openssl req -x509 -keyform engine -engine trustm_engine -key 0xe0f1:^:NEW:0x03:0x13 -new -out ./demoCA/cacert.pem -subj /CN=trustmCA
openssl x509 -in ./demoCA/cacert.pem -text

echo "-----> Generate Device ECC Private Key"
openssl ecparam -out dev_privkey.pem -name prime256v1 -genkey
echo "Device:-----> Generate Device CSR"
openssl req -new  -key dev_privkey.pem -subj /CN=TrustM_Dev1/O=Infineon/C=SG -out dev.csr

echo "CA:-----> Generate device cetificate by using CA"
openssl ca -batch -create_serial -keyform engine -engine trustm_engine -keyfile 0xe0f1:^ -in dev.csr -out dev.pem -cert ./demoCA/cacert.pem -days 3650 -config openssl.cnf

openssl x509 -in dev.pem -text

```

Note: To reset the folder to initial state, run **clean.sh**. All certificates issued and tracking will be **permanently** erased.