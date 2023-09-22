# OPTIGA™ Trust M Provider for OpenSSL 3.x

1. [About](#about)
   * [Prerequisites](#prerequisites)
2. [Getting Started](#getting_started)
   * [Getting the Code from Github](#getting_code)
   * [First time building the library](#build_lib)
3. [OPTIGA™ Trust M OpenSSL Provider usage](#provider_usage)
   * [rand](#rand)
   * [req](#req)
   * [pkey](#pkey)
   * [pkeyutl](#pkeyutl)
   * [Testing TLS connection with RSA key](#test_tls_rsa)

## <a name="about"></a>About

This is the OpenSSL 3.x API Implementation for Infineon OPTIGA™ Trust M V3 Chip.


### <a name="prerequisites"></a>Prerequisites

Following is the software component to build the tools :

* GCC
* OpenSSL 3.x
* OPTIGA Trust M3 library (source code)
* pthread
* rt


Hardware platforms and boards:

* Raspberry PI 3/4 

* [OPTIGA™ Trust M](https://www.infineon.com/cms/en/product/evaluation-boards/s2go-security-optiga-m/)

* [Shield2Go Adapter for Raspberry Pi](https://www.infineon.com/cms/en/product/evaluation-boards/s2go-adapter-rasp-pi-iot/)

  Note: OPTIGA™ Trust M Provider is tested on Linux Raspberry PI 6.1.21-v7+ armv7l 

![](/pictures/connection_diagram1.png)

## <a name="getting_started"></a>Getting Started

### <a name="getting_code"></a>Getting the Code from Github

Getting the initial code from Github with submodules

```console
git clone --recurse-submodules 
https://github.com/Infineon/linux-optiga-trust-m.git
```

Note:  The following commands are optional and it is required only when switching between different branches.

```
cd linux-optiga-trust-m/
git checkout provider_dev
```

```
git submodule update -f
```

### <a name="build_lib"></a>First time building the library

Run the commands below in sequence to install the required dependencies and the OPTIGA™ Trust M provider. 

```
./provider_installation_script.sh
```

Note: 

1)Enable I2C interface for Raspberry Pi to communicate with optiga trustm m

2)The patch applied inside trustm_installation_script.sh will change the reset type to use soft reset as follow in the header file at "linux-optiga-trust-m/trustm_lib/optiga/include/optiga/"

- optiga_lib_config_m_v3.h for OPTIGA™ Trust M3 


```console
#define OPTIGA_COMMS_DEFAULT_RESET_TYPE     (1U)
```

To build for AARCH64, uncomment  this Marco in Makefile

```console 
#~ Uncomment this for AARCH64 or pass it as argument in command line
#~ AARCH64 = YES
```

Or run the script below:

    foo@bar:~$ ./provider_installation_aarch64_script.sh

Note: AARCH64 = YES is passed as argument in *provider_installation_aarch64_script.sh*.

## <a name="provider_usage"></a>OPTIGA™ Trust M3 OpenSSL Provider usage

The Provider is tested base on OpenSSL version 3.1.0

### <a name="rand"></a>rand

Usage : Random number generation
Example

```console 
openssl rand -provider trustm_provider -base64 32
```

*Note :* 
*If OPTIGA™ Trust M random number generation fails, there will still be random number output.* 
*This is control by OpenSSL provider do not have control over it.*

### <a name="req"></a>req

Usage : Certificate request / self signed cert / key generation

OPTIGA™ Trust M provider uses the -key parameter to pass input to the key generation/usage function.

Following is the input format:

-key **OID** : **public key input** : **NEW** :**key size** : **key usage**

where :

- **OID** for OPTIGA™ Trust M key

  - if OID 0xE0F0 is used no other input is needed

- **public key input**

  - public key file name in PEM format

  - \* = no public input

  - ^ = public key store in Application OID Key

    - 0xE0F1 store in 0xF1D1,

    - 0xE0F2 store in 0xF1D2,

    - 0xE0F3 store in 0xF1D3,

    - 0xE0FC store in 0xF1E0,

    - 0xE0FD store in 0xF1E1

      Note: For ECC521/BRAINPOOL512, the public key store in Application OID list as below:

    - 0xE0F1 store in 0xF1E0,

    - 0xE0F2 store in 0xF1E1

- **NEW**

  - Generate new key pair in OPTIGA™ Trust M

- **key size**

  - ECC
    - 0x03 = 256 key length  for NIST  256
    - 0x04 = 384 key length  for NIST  384
    - 0x05 = 521 key length  for NIST  521
    - 0x13 = 256 key length  for brainpoolP256r1
    - 0x15 = 384 key length  for brainpoolP384r1
    - 0x16 = 512 key length  for brainpoolP512r1
  - RSA
    - 0x41 = 1024 key length
    - 0x42 = 2048 key length

- **Key usage** 

  - Auth : 0x01 
  - Enc : 0x02 
  - HFWU : 0x04 
  - DevM : 0X08 
  - Sign : 0x10 
  - Agmt : 0x20

*Note: If wrong public is submitted the certificate generation will still go through but verification will fail.*

Example : Generating a certificate request using OID 0xE0F3 with new key generated, ECC 384 key length and Auth/Enc/Sign usage. Verify that public key match the private key in the OID.

```console 
openssl req -provider trustm_provider -key 0xe0f3:*:NEW:0x04:0x13 -new -out test_e0f3.csr -verify
```

*Note:*
*If wrong public is used or no pubkey is submitted the certificate generation will still* 
*go through but verification will fail. Pubic key input only in PEM*

### <a name="pkey"></a>pkey

Usage : Key tools / Key generation

OPTIGA™ Trust M provider uses the -in parameter to pass input to the key generation/usage function.

Following is the input format:

-in **OID** : **public key input** : **NEW** :**key size** : **key usage**

(see [req](#req) for input details)

Example: 

```console 
openssl pkey -provider trustm_provider -in 0xe0fd:*:NEW:0x42:0x13 -pubout -out e0fd_pub.pem
```

### <a name="pkeyutl"></a>pkeyutl

Usage : Sign and verify
Example:

Signing the message in the test_sign.txt file using the TrustM EC key and saving the generated signature in the test_sign.sig file.

```console 
openssl pkeyutl -provider trustm_provider -inkey 0xe0fd:^  -sign -rawin -in test_sign.txt -out test_sign.sig
```

Verifying the signature of the raw input data in test_sign.txt using the provided public key in eofd_pub.pem and the signature in test_sign.sig

```
openssl pkeyutl -verify -pubin -inkey e0fd_pub.pem -rawin -in test_sign.txt -sigfile test_sign.sig
```

### <a name="test_tls_rsa"></a>Testing TLS connection with RSA key

#### Scenario where Trust M is on the client :

*Note : To generate a test server certificate refer to [Generating a Test Server Certificate](#testServercert)* 

Creates new RSA 2048 key length and Auth/Enc/Sign usage and generate a certificate  request for OPTIGA™ Trust M key 0xE0FC

```console
openssl req -provider trustm_provider \
-key 0xe0fd:*:NEW:0x42:0x13 \
-new \
-subj "/C=SG/CN=TrustM/O=Infineon" \
-out test_e0fd.csr
```

Issue the certificate with keyUsage=digitalSignature,keyEncipherment on the client side with OPTIGA_Trust_M_Infineon_Test_CA.

*Note : Refer to [Generating a Test Server Certificate](#testServercert)  for openssl.cnf*

```console
openssl x509 -req -in test_e0fd.csr \
-CA scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out test_e0fd.crt \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext1
```

Running the test server : 

```console
openssl s_server \
-cert test_opensslserver.crt \
-key privkey.pem -accept 5000 \
-verify_return_error \
-Verify 1 \
-CAfile scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-sigalgs RSA+SHA256
```

Running the test client : *(open a new console)* 

```console
openssl s_client -provider trustm_provider -provider default \
-client_sigalgs RSA+SHA256 \
-cert test_e0fd.crt \
-key 0xe0fd:^ \
-connect localhost:5000 \
-tls1_2 \
-CAfile scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-verify 1 
```

#### Scenario where Trust M is on the server :

Creates new RSA 2048 key length and Auth/Enc/Sign usage and generate a certificate  request for OPTIGA™ Trust M key 0xE0FD

```console
openssl req -provider trustm_provider -key 0xe0fc:*:NEW:0x42:0x13 -new -subj "/C=SG/CN=TrustM/O=Infineon" -out test_e0fc.csr
```

Issue the certificate with keyUsage=keyCertSign, cRLSign, digitalSignature on the server side with OPTIGA_Trust_M_Infineon_Test_CA.

```console
openssl x509 -req -in test_e0fc.csr -CA  scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out test_e0fc.crt \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext2
```

Running the test server : 

```console
openssl s_server -provider trustm_provider -provider default \
-cert test_e0fc.crt \
-key 0xe0fc:^ \
-accept 5000 \
-verify_return_error \
-CAfile scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-sigalgs RSA+SHA256 
```

Running the test client : *(open a new console)* 

```console
openssl s_client \
-CAfile scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-connect localhost:5000 -tls1_2
-client_sigalgs RSA+SHA256
```

### <a name="testServercert"></a>Generating a Test Server Certificate

 Generate a new key pair and certificate request. Private key is output to private.pem

```console
openssl req -new -nodes -subj "/C=SG/O=Infineon" -out test_opensslserver.csr
```

 Run the command:

```console
cat openssl.cnf 
```

Creates and displays the openssl.cnf as shown below:

```console
[ cert_ext ]
subjectKeyIdentifier=hash
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth,serverAuth

[ cert_ext1 ]
subjectKeyIdentifier=hash
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth

[ cert_ext2 ]
subjectKeyIdentifier=hash
keyUsage=keyCertSign, cRLSign, digitalSignature
```

Issue the certificate with keyUsage=keyCertSign, cRLSign, digitalSignature on the server side with OPTIGA_Trust_M_Infineon_Test_CA.

```console
openssl x509 -req -in test_opensslserver.csr \
-CA scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey scripts/certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out test_opensslserver.crt \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext2
```
