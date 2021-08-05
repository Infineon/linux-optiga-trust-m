# Linux tools and examples</br> for OPTIGA™ Trust M1/M3 security solution

1. [About](#about)
    * [Prerequisites](#prerequisites)
2. [Getting Started](#getting_started)
    * [Getting the Code from Github](#getting_code)
    * [First time building the library](#build_lib)
3. [CLI Tools Usage](#cli_usage)
    * [trustm_cert](#trustm_cert)
    * [trustm_chipinfo](#trustm_chipinfo)
    * [trustm_data](#trustm_data)
    * [trustm_ecc_keygen](#trustm_ecc_keygen)
    * [trustm_ecc_sign](#trustm_ecc_sign)
    * [trustm_ecc_verify](#trustm_ecc_verify)
    * [trustm_errorcode](#trustm_errorcode)
    * [trustm_metadata](#trustm_metadata)
    * [trustm_monotonic_counter](#trustm_monotonic_counter)
    * [trustm_readmetadata_data](#trustm_readmetadata_data)
    * [trustm_readmetadata_private](#trustm_readmetadata_private)
    * [trustm_readmetadata_status](#trustm_readmetadata_status)
    * [trustm_read_status](#trustm_read_status)
    * [trustm_rsa_dec](#trustm_rsa_dec)
    * [trustm_rsa_enc](#trustm_rsa_enc)
    * [trustm_rsa_keygen](#trustm_rsa_keygen)
    * [trustm_rsa_sign](#trustm_rsa_sign)
    * [trustm_rsa_verify](#trustm_rsa_verify)
    * [trustm_symmetric_keygen](#trustm_symmetric_keygen)
    * [trustm_symmetric_enc](#trustm_symmetric_enc)
    * [trustm_symmetric_dec](#trustm_symmetric_dec)
    * [trustm_hkdf](#trustm_hkdf)
    * [trustm_hmac](#trustm_hmac)
4. [Trust M1/M3 OpenSSL Engine usage](#engine_usage)
    * [rand](#rand)
    * [req](#req)
    * [pkey](#pkey)
    * [dgst](#dgst)
    * [Testing TLS connection with ECC key](#test_tls_ecc)
    * [Testing TLS connection with RSA key](#test_tls_rsa)
    * [Using Trust M OpenSSL engine to sign and issue certificate](#issue_cert)
    * [Simple Example on OpenSSL using C language](#opensslc)
5. [AWS IoT C-SDK](./ex_aws-iot-device-sdk-embedded-C-1.1.2/README.md)
6. [Known observations](#known_observations)

## <a name="about"></a>About

This is a Linux Tools for OPTIGA Trust M1/M3 on Linux platform that consist of:

- [Command Line Interface examples](#cli_usage)
- [OpenSSL Engine](#engine_usage)
- [AWS IoT C SDK example](./ex_aws-iot-device-sdk-embedded-C-1.1.2/)


### <a name="prerequisites"></a>Prerequisites

Following is the software component to build the tools :
* GCC
* OpenSSL development library (libssl-dev)
* OpenSSL 1.1.1d
* OPTIGA Trust M1/M3 library (source code)
* pthread
* rt


Hardware platforms and boards:
* Raspberry PI 3/4  on Linux kernel >= 4.19

* [OPTIGA™ Trust M](https://www.infineon.com/cms/en/product/evaluation-boards/s2go-security-optiga-m/)

* [Shield2Go Adapter for Raspberry Pi](https://www.infineon.com/cms/en/product/evaluation-boards/s2go-adapter-rasp-pi-iot/)

  ![](/pictures/coonection_diagram1.png)

## <a name="getting_started"></a>Getting Started
### <a name="getting_code"></a>Getting the Code from Github

Getting the initial code from Github with submodules

```console
foo@bar:~$ git clone --recurse-submodules https://github.com/Infineon/linux-optiga-trust-m.git
```

Note:  The following commands are optional and it is required only when switching between different branches.

```
foo@bar:~$ git checkout development_v3
foo@bar:~$ git submodule update -f
```

Change the reset type to use software reset as follow in the header file at "**linux-optiga-trust-m/trustm_lib/optiga/include/optiga/**"

- optiga_lib_config_m_v3.h for OPTIGA™ Trust M3 or 
- optiga_lib_config_m_v1.h for OPTIGA™ Trust M1

```console
#define OPTIGA_COMMS_DEFAULT_RESET_TYPE     (1U)
```

### <a name="build_lib"></a>First time building the library
Install required dependencies:
```console
foo@bar:~$ sudo apt-get install libssl-dev
```
Go to the repository directory "linux-optiga-trust-m"
```console 
foo@bar:~$ make
```
 to install

*Note : In case install fail try performing the uninstall and redo make.*

```console 
foo@bar:~$ sudo make install
```

to uninstall

```console 
foo@bar:~$ sudo make uninstall
```

## <a name="cli_usage"></a>CLI Tools Usage

Note:  To pair the host with OPTIGA™ Trust M, please run the test script "write_default_shared_secret" inside "**linux-optiga-trust-m/scripts/misc/**" to write the default shared secret into OPTIGA™ Trust M.

### <a name="trustm_cert"></a>trustm_cert

Read/Write/Clear certificate from/to certificate data object. Output and input certificate in PEM format.

```console
foo@bar:~$ ./bin/trustm_cert
Help menu: trustm_cert <option> ...<option>
option:- 
-r <Cert OID>  	: Read Certificate from OID 0xNNNN 
-w <Cert OID>  	: Write Certificte to OID
-o <filename>  	: Output certificate to file 
-i <filename>  	: Input certificate to file 
-c <Cert OID>   : Clear cert OID data to zero 
-X              : Bypass Shielded Communication 
-h              : Print this help 
```

Example : read OID 0xE0E0 and output the certification to teste0e0.crt

```console
foo@bar:~$ ./bin/trustm_cert -r 0xe0e0 -o teste0e0.crt
========================================================
OID              : 0xE0E0 
Output File Name : teste0e0.crt 
Success!!!
========================================================

foo@bar:~$ cat teste0e0.crt 
-----BEGIN CERTIFICATE-----
MIIB2DCCAX6gAwIBAgIEERCFGjAKBggqhkjOPQQDAjByMQswCQYDVQQGEwJERTEh
MB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRMwEQYDVQQLDApPUFRJ
R0EoVE0pMSswKQYDVQQDDCJJbmZpbmVvbiBPUFRJR0EoVE0pIFRydXN0IE0gQ0Eg
MTAxMB4XDTE5MDYxODA2MzAxMFoXDTM5MDYxODA2MzAxMFowHDEaMBgGA1UEAwwR
SW5maW5lb24gSW9UIE5vZGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQRjgnP
/Cuv2C6aEHEiIib60TBi8TU0GN6LXMKAShMUNd6yYosO3Cv3XExwWVqkbeAIrXRo
gM3bPK7w5CRWu8hqo1gwVjAOBgNVHQ8BAf8EBAMCAIAwDAYDVR0TAQH/BAIwADAV
BgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFDwwjFzViuijXTKA5FSD
sv/Nhk0jMAoGCCqGSM49BAMCA0gAMEUCIQC5y2fv2p1VS41jSX72pl/B3am+Oboy
B1ItWszBjNzc0AIgEiPyApU78Oif0drcgQhH0qfxaKPJAFySCb2wpHYy6Uc=
-----END CERTIFICATE-----
```

Example : write certificate teste0e0.crt into OID 0xE0E1

```console
foo@bar:~$ ./bin/trustm_cert -w 0xe0e1 -i teste0e0.crt 
========================================================
Success!!!
========================================================
```

Example : clear certificate store in OID 0xE0E1

```console
foo@bar:~$ ./bin/trustm_cert -c 0xe0e1
========================================================
Cleared.
========================================================
```

### <a name="trustm_chipinfo"></a>trustm_chipinfo

Display the OPTIGA™ Trust M chip information

```console
foo@bar:~$ ./bin/trustm_chipinfo 
Read Chip Info [0xE0C2]: Success.
========================================================
CIM Identifier             [bCimIdentifer]: 0xcd
Platform Identifer   [bPlatformIdentifier]: 0x16
Model Identifer         [bModelIdentifier]: 0x33
ID of ROM mask                  [wROMCode]: 0x8201
Chip Type                    [rgbChipType]: 0x00 0x1c 0x00 0x05 0x00 0x00
Batch Number              [rgbBatchNumber]: 0x0a 0x09 0x1b 0x5c 0x00 0x07
X-coordinate              [wChipPositionX]: 0x0020
Y-coordinate              [wChipPositionY]: 0x008e
Firmware Identifier [dwFirmwareIdentifier]: 0x80101071
Build Number                 [rgbESWBuild]: 08 09

Chip software build: 
OPTIGA(TM) Trust M rev.1; Firmware Version: 1.30.809
========================================================
```

### <a name="trustm_data"></a>trustm_data

Read/Write/Erase OID data object in raw format.

```console
foo@bar:~$ ./bin/trustm_data 
Help menu: trustm_data <option> ...<option>
option:- 
-r <OID>      : Read from OID 0xNNNN 
-w <OID>      : Write to OID
-i <filename> : Input file 
-I <value>    : Input byte value 
-o <filename> : Output file 
-p <offset>   : Offset position 
-e            : Erase and wirte 
-X            : Bypass Shielded Communication 
-h            : Print this help  
```

Example : writing text file 1234.txt into OID 0xE0E1 and reading after writing

```console
foo@bar:~$ cat 1234.txt 
1234

foo@bar:~$ ./bin/trustm_data -w 0xe0e1 -i 1234.txt
========================================================
Device Public Key           [0xE0E1] Offset: 0
Input data : 
	31 32 33 34 0a 
Write Success.
========================================================

foo@bar:~$ ./bin/trustm_data -r 0xe0e1
========================================================
Device Public Key           [0xE0E1] [Size 0005] : 
	31 32 33 34 0a 
========================================================
```

Example : erase with offset OID 0xE0E1

```console
foo@bar:~$ ./bin/trustm_data -w 0xe0e1 -e -p 10 -i 1234.txt
========================================================
Device Public Key           [0xE0E1] Offset: 10
Input data : 
	31 32 33 34 0a 
Write Success.
========================================================

foo@bar:~$ ./bin/trustm_data -r 0xe0e1
========================================================
Device Public Key           [0xE0E1] [Size 0015] : 
	00 00 00 00 00 00 00 00 00 00 31 32 33 34 0a 
========================================================
```

### <a name="trustm_ecc_keygen"></a>trustm_ecc_keygen

Generate OPTIGA™ Trust M ECC key pair. Key type can be or together to form multiple type.

```console
foo@bar:~$ ./bin/trustm_ecc_keygen 
Help menu: trustm_ecc_keygen <option> ...<option>
option:- 
-g <Key OID>    : Generate ECC Key in OID 0xNNNN 
-t <key type>   : Key type Auth:0x01 Enc :0x02 HFWU:0x04
                           DevM:0X08 Sign:0x10 Agmt:0x20
                           [default Auth]
-k <key size>   : Key size ECC256:0x03 ECC384:0x04 ECC521:0x05
                           BRAINPOOL256:0x13 BRAINPOOL384:0x15 BRAINPOOL512:0x16
                           [default ECC256]
-o <filename>   : Output Pubkey to file in PEM format
-s              : Save Pubkey in <Key OID + 0x10E0>
                  For ECC521/BRAINPOOL512: 
                  Save Pubkey in <Key OID + 0x10ED>
-X              : Bypass Shielded Communication 
-h              : Print this help 
```

Example : generate an ECC256 key with type Auth/Enc/Sign in OID 0xE0F3 and save pubkey in OID 0xF1D3.

```console
foo@bar:~$ ./bin/trustm_ecc_keygen -g 0xe0f3 -t 0x13 -k 0x03 -o test_e0f3_pub.pem -s
========================================================
Generating Key to 0xE0F3
Output File Name : test_e0f3_pub.pem 
Pubkey :
	30 59 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 
	86 48 CE 3D 03 01 07 03 42 00 04 F1 55 65 CB 42 
	FB 3E 58 DB C6 9F 67 E8 FC D3 48 F6 AA 5F 13 2D 
	F6 3B A7 90 22 B4 B6 D3 4E 5B BB 98 AB 46 97 BD 
	2A 03 A6 27 A5 4D FB 95 C2 BB 9A D3 AF A9 4E A7 
	D6 A1 63 9F 93 B6 71 57 07 E6 00 
Write Success to OID: 0xF1D3.
========================================================

foo@bar:~$ cat test_e0f3_pub.pem 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8VVly0L7Pljbxp9n6PzTSPaqXxMt
9junkCK0ttNOW7uYq0aXvSoDpielTfuVwrua06+pTqfWoWOfk7ZxVwfmAA==
-----END PUBLIC KEY-----

foo@bar:~$ ./bin/trustm_data -r 0xf1d3
========================================================
App DataStrucObj type 3     [0xF1D3] [Size 0091] : 
	30 59 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 
	86 48 CE 3D 03 01 07 03 42 00 04 F1 55 65 CB 42 
	FB 3E 58 DB C6 9F 67 E8 FC D3 48 F6 AA 5F 13 2D 
	F6 3B A7 90 22 B4 B6 D3 4E 5B BB 98 AB 46 97 BD 
	2A 03 A6 27 A5 4D FB 95 C2 BB 9A D3 AF A9 4E A7 
	D6 A1 63 9F 93 B6 71 57 07 E6 00 
========================================================
```

### <a name="trustm_ecc_sign"></a>trustm_ecc_sign

Simple demo to show the process to sign using OPTIGA™ Trust M ECC key.

*Note : to output OpenSSL signature format used -o*

```console
foo@bar:~$ ./bin/trustm_ecc_sign 
Help menu: trustm_ecc_sign <option> ...<option>
option:- 
-k <OID Key>  : Select ECC key for signing OID (0xE0F0-0xE0F3) 
-o <filename> : Output to file with header
-O <filename> : Output to file without header
-i <filename> : Input Data file
-H            : Hash before sign
-X            : Bypass Shielded Communication 
-h            : Print this help 
```

Example : Hash and sign the file helloworld.txt with key OID 0xE0F3 and output to testsignature.bin

```console
foo@bar:~$ ./bin/trustm_ecc_sign -k 0xe0f3 -o testsignature.bin -i helloworld.txt -H
========================================================
OID Key          : 0xE0F3
Output File Name : testsignature.bin 
Input File Name  : helloworld.txt 
Hash Success : SHA256
	8C D0 7F 3A 5F F9 8F 2A 78 CF C3 66 C1 3F B1 23 
	EB 8D 29 C1 CA 37 C7 9D F1 90 42 5D 5B 9E 42 4D 
	
filesize: 11
Success
========================================================

foo@bar:~$ hd testsignature.bin 
00000000  30 44 02 20 14 ea 77 98  ed 26 89 40 22 bb a0 60  |0D. ..w..&.@"..`|
00000010  c5 1f 01 8f 65 21 7a 98  0d 63 73 03 4e ea 13 39  |....e!z..cs.N..9|
00000020  0c ed 58 8a 02 20 2a 7b  fc 7a dd 2e 75 86 41 f5  |..X.. *{.z..u.A.|
00000030  43 14 ec e8 14 34 6b 2a  20 68 23 eb 14 ec 59 2f  |C....4k* h#...Y/|
00000040  37 04 37 44 62 c9                                 |7.7Db.|
00000046
```

### <a name="trustm_ecc_verify"></a>trustm_ecc_verify

Simple demo to show the process to verify using OPTIGA™ Trust M library.

```console
foo@bar:~$ ./bin/trustm_ecc_verify 
Help menu: trustm_ecc_verify <option> ...<option>
option:- 
-k <OID Key>   : Use Certificate from OID [0xE0E1-E0E3]
-p <pubkey>    : Use Pubkey file
-i <filename>  : Input Data file
-s <signature> : Signature file
-H             : Hash input before verify
-X             : Bypass Shielded Communication 
-h             : Print this help
```

Example : verifying a signature using external public key.

```console
foo@bar:~$ ./bin/trustm_ecc_verify -i helloworld.txt -s testsignature.bin -p test_e0f3_pub.pem -H
========================================================
Pubkey file         : test_e0f3_pub.pem
Input File Name     : helloworld.txt 
Signature File Name : testsignature.bin 
Hash Digest : 
	8C D0 7F 3A 5F F9 8F 2A 78 CF C3 66 C1 3F B1 23 
	EB 8D 29 C1 CA 37 C7 9D F1 90 42 5D 5B 9E 42 4D 
	
Signature : 
	02 20 14 EA 77 98 ED 26 89 40 22 BB A0 60 C5 1F 
	01 8F 65 21 7A 98 0D 63 73 03 4E EA 13 39 0C ED 
	58 8A 02 20 2A 7B FC 7A DD 2E 75 86 41 F5 43 14 
	EC E8 14 34 6B 2A 20 68 23 EB 14 EC 59 2F 37 04 
	37 44 62 C9 
Pub key : [256]
	03 42 00 04 F1 55 65 CB 42 FB 3E 58 DB C6 9F 67 
	E8 FC D3 48 F6 AA 5F 13 2D F6 3B A7 90 22 B4 B6 
	D3 4E 5B BB 98 AB 46 97 BD 2A 03 A6 27 A5 4D FB 
	95 C2 BB 9A D3 AF A9 4E A7 D6 A1 63 9F 93 B6 71 
	57 07 E6 00 
Verify Success.
========================================================
```

Example : verifying using certificate store in OID 0xE0E3.

*Note :  This example assume you have a valid x.509 certificate with key usage for signature store in OID 0xE0E3 and data is signed by the private key of the x.509 certificate.*  

```console
foo@bar:~$ ./bin/trustm_ecc_verify -i helloworld.txt -s testsignature.bin -k 0xe0e3 -H
========================================================
OID Cert            : 0xE0E3
Input File Name     : helloworld.txt 
Signature File Name : testsignature.bin 
Hash Digest : 
	8C D0 7F 3A 5F F9 8F 2A 78 CF C3 66 C1 3F B1 23 
	EB 8D 29 C1 CA 37 C7 9D F1 90 42 5D 5B 9E 42 4D 
	
Signature : 
	02 20 14 EA 77 98 ED 26 89 40 22 BB A0 60 C5 1F 
	01 8F 65 21 7A 98 0D 63 73 03 4E EA 13 39 0C ED 
	58 8A 02 20 2A 7B FC 7A DD 2E 75 86 41 F5 43 14 
	EC E8 14 34 6B 2A 20 68 23 EB 14 EC 59 2F 37 04 
	37 44 62 C9 
Verify Success.

========================================================
```

### <a name="trustm_errorcode"></a>trustm_errorcode

List all the known OPTIGA™ Trust M error code with description

### <a name="trustm_metadata"></a>trustm_metadata

Modify OPTIGA™ Trust M OID metadata.

***Warning : Any manipuldation with the lifecycle state LcsO like -I, -O and -T option might lock the data/key slot permanently. Depending on the access condition cofiguration "locking"  means you would be able to use it, but, for instance, not change.**.* 

The Lcs is implemented in a way that the four primary states only progress in one direction from a lower value to a higher value(e.g. initialization(in)=>operational(op) state). Once Lcs0 is set to higher value, it is not reversible and can not be set to lower value any more.

```console
foo@bar:~$ ./bin/trustm_metadata 
Help menu: trustm_metadata <option> ...<option>
option:- 
-r <OID>  : Read metadata of OID 0xNNNN 
-w <OID>  : Write metadata of OID
-C <data> : Set Change mode (a:ALW,
                             n:NEV,
                             i:Lsc0 < 0x03,
                             o:Lsc0 < 0x07,
                             t:Lsc0 < 0xFF,
                             f:<input file for complex setting>)
-R <data> : Set Read mode   (a:ALW,
                             n:NEV,
                             i:Lsc0 < 0x03,
                             o:Lsc0 < 0x07,
                             t:Lsc0 < 0xFF,
                             f:<input file for complex setting>)
-E <data> : Set Change mode (a:ALW,
                             n:NEV,
                             i:Lsc0 < 0x03,
                             o:Lsc0 < 0x07,
                             t:Lsc0 < 0xFF,
                             f:<input file for complex setting>)
-F <file> : Custom input
          : (Need to input the full Metadata to be written)
-I        : Set Initialization State (Lsc0: 0x03)
-O        : Set Operational State (Lsc0: 0x07)
-T        : Set Termination State (Lsc0: 0xFF)
-X        : Bypass Shielded Communication 
-h        : Print this help 
```

Example : changing OID 0xE0E1 metadata to read only and reading the metadata after changing

```console
foo@bar:~$ ./bin/trustm_metadata -w 0xe0e1 -Cn -Ra
========================================================
Device Public Key           [0xE0E1] 
	20 06 D0 01 FF D1 01 00 
	C:NEV, R:ALW, 
Write Success.
========================================================

foo@bar:~$ ./bin/trustm_metadata -r 0xe0e1
========================================================
Device Public Key           [0xE0E1] [Size 0025] : 
	20 17 c0 01 01 c4 02 06 c0 c5 02 01 dc d0 01 ff 
	d1 01 00 d3 01 00 e8 01 12 
	LcsO:0x01, Max:1728, Used:476, C:NEV, R:ALW, E:ALW, DType:DEVCERT, 

========================================================
```

Example : charging OID 0xE0E1 metadata using complex setting (LcsO>3||LcsG<4) for Change mode

```console
foo@bar:~$ echo -e -n \\x07\\xe1\\xfb\\x03\\xfe\\x70\\xfc\\x04 > complexsetting.bin

foo@bar:~$ hd complexsetting.bin 
00000000  07 e1 fb 03 fe 70 fc 04                           |.....p..|
00000008

foo@bar:~$ ./bin/trustm_metadata -w 0xe0e1 -Cf:complexsetting.bin 
========================================================
Device Public Key           [0xE0E1] 
	20 09 D0 07 E1 FB 03 FE 70 FC 04 
	C:LcsO>3||LcsG<4, 
Write Success.
========================================================

foo@bar:~$ ./bin/trustm_metadata -r 0xe0e1
========================================================
Device Public Key           [0xE0E1] [Size 0031] : 
	20 1d c0 01 01 c4 02 06 c0 c5 02 01 dc d0 07 e1 
	fb 03 fe 70 fc 04 d1 01 00 d3 01 00 e8 01 12 
	LcsO:0x01, Max:1728, Used:476, C:LcsO>3||LcsG<4, R:ALW, E:ALW, DType:DEVCERT, 

========================================================
```

### <a name="trustm_monotonic_counter"></a>trustm_monotonic_counter

Simple demo to show the OPTIGA™ Trust M monotonic counter.

```console
foo@bar:~$ ./bin/trustm_monotonic_counter 
Help menu: trustm_monotonic_counter <option> ...<option>
option:- 
-r <OID>      : Read from OID [0xE120-0xE123] 
-w <OID>      : Write to OID [0xE120-0xE123] 
-u <OID>      : Update Counter [0xE120-0xE123] 
-i <value>    : Input Value 
-s <value>    : Increment Steps 
-X            : Bypass Shielded Communication 
-h            : Print this help
```

Example : Setting the threshold value to 10 and resetting the counter to zero

```console
foo@bar:~$ ./bin/trustm_monotonic_counter -w 0xe120 -i 10
========================================================
Input Value : 10 [0x0000000A]
	00 00 00 00 00 00 00 0a 
Write Success.
========================================================
```

Example : Count up the monotonic counter in steps of 2

```console
foo@bar:~$ ./bin/trustm_monotonic_counter -u 0xe120 -s 2
========================================================
Steps Value : 2 [0x00000002]
Update Counter Success.
========================================================

foo@bar:~$ ./bin/trustm_monotonic_counter -r 0xe120
========================================================
Monotonic Counter x : [0xE120]
Threshold           : 0x0000000A [10]
Counter Value       : 0x00000002 [2]
========================================================
```

### <a name="trustm_read_data"></a>trustm_read_data

Read all data object listed below

*oid : 0xE0E0-0xE0E3, 0xE0E8-0xE0E9, 0xE0EF,* 

​         *0xE120-0xE123,* 

​         *0xE140, 0xF1D0-0xF1DB, 0xF1E0-0xF1E1*

### <a name="trustm_readmetadata_data"></a>trustm_readmetadata_data

Read all data object metadata listed below 

*oid : 0xE0E0-0xE0E3, 0xE0E8-0xE0E9, 0xE0EF,* 

​         *0xE120-0xE123,* *0xE200*,

​         *0xE140, 0xF1D0-0xF1DB, 0xF1E0-0xF1E1*

### <a name="trustm_readmetadata_private"></a>trustm_readmetadata_private

Read all data object metadata listed below 

*oid : 0xE0F0-0xE0F3,* 

​         *0xF1FC-0xE0FD*

### <a name="trustm_readmetadata_status"></a>trustm_readmetadata_status

Read all data object metadata listed below 

*oid : 0xE0C0-0xE0C6,* 

​         *0xF1C0-0xF1C2*

### <a name="trustm_read_status"></a>trustm_read_status

Read all data object listed below 

*oid : 0xE0C0-0xE0C6,* 

​        *0xF1C0-0xF1C2*

### <a name="trustm_rsa_dec"></a>trustm_rsa_dec

Simple demo to show the process to decrypt using OPTIGA™ Trust M RSA key.

*Note : This example assume RSA key with usage Encryption has already been generated and data is encrypted by the pubkey*

```console
foo@bar:~$ ./bin/trustm_rsa_dec
Help menu: trustm_rsa_dec <option> ...<option>
option:- 
-k <OID Key>  : Select key to decrypt OID 0xNNNN 
-o <filename> : Output to file 
-i <filename> : Input Data file
-X            : Bypass Shielded Communication 
-h            : Print this help 
```

 Example : Decrypt using OID Key 0xE0FC, an encrypted file test_e0fc.enc and output to test_e0fc.dec

```console
foo@bar:~$ ./bin/trustm_rsa_dec -k 0xe0fc -o test_e0fc.dec -i test_e0fc.enc 
========================================================
OID Key          : 0xE0FC 
Output File Name : test_e0fc.dec 
Input File Name  : test_e0fc.enc 
Input data : 
	35 38 AC E8 54 CA 02 92 A7 B4 72 0A 62 F9 7B DD 
	CC C7 E1 9C A4 52 D6 AF CC 04 E4 B4 54 19 85 DD 
	10 80 FA 8B 04 8E B0 5E 29 C5 F5 2F A7 99 BB EC 
	2E 69 D4 AB 35 80 BF F5 87 6D 80 65 60 3E A6 31 
	6E 05 80 F2 CB 9E 32 DA F2 82 DB 15 D6 9C 1E DF 
	FE 1C 5E 1F 7F E6 6D 2A EA B3 54 AD 41 AF C2 08 
	FE BF C7 B5 87 22 79 A2 AA F3 0D 71 BA DB 5D F7 
	CE 50 EA 89 D4 42 BD 0B 11 6A C8 11 2F 09 99 28 
	
Success
========================================================

foo@bar:~$ cat test_e0fc.dec 
helloworld!!!
```

### <a name="trustm_rsa_enc"></a>trustm_rsa_enc

Simple demo to show the process to encrypt using OPTIGA™ Trust M RSA key.

```console
foo@bar:~$ ./bin/trustm_rsa_enc 
Help menu: trustm_rsa_enc <option> ...<option>
option:- 
-k <OID Key>  : Select key for encrypt OID 0xNNNN 
-p <pubkey>   : Use Pubkey file
-o <filename> : Output to file 
-i <filename> : Input Data file
-X            : Bypass Shielded Communication 
-h            : Print this help
```

Example : Encrypt using external pubkey

```console
foo@bar:~$ ./bin/trustm_rsa_enc -p test_e0fc_pub.pem -o test_e0fc.enc -i helloworld.txt 
========================================================
Pubkey file      : test_e0fc_pub.pem 
Output File Name : test_e0fc.enc 
Input File Name  : helloworld.txt 
Input data : 
	68 65 6C 6C 6F 77 6F 72 6C 64 21 21 21 0A 
Success
========================================================
```

Example : Encrypt using Certificate store in OID 0xE0E2

*Note :  This example assume you have a valid x.509 certificate with key usage for Key Encipherment store in OID 0xE0E2.*  

```console
foo@bar:~$ ./bin/trustm_rsa_enc -k 0xe0e2 -o test_e0fc1.enc -i helloworld.txt 
========================================================
OID Key          : 0xE0E2 
Output File Name : test_e0fc1.enc 
Input File Name  : helloworld.txt 
Input data : 
	68 65 6C 6C 6F 77 6F 72 6C 64 21 21 21 0A 
Success
========================================================
```

### <a name="trustm_rsa_keygen"></a>trustm_rsa_keygen

Generate OPTIGA™ Trust M RSA key pair. Key type can be or together to form multiple type.

```console
foo@bar:~$ ./bin/trustm_rsa_keygen 
Help menu: trustm_rsa_keygen <option> ...<option>
option:- 
-g <Key OID>    : Generate RSA Key in OID [0xE0FC-0xE0FD] 
-t <key type>   : Key type Auth:0x01 Enc :0x02 HFWU:0x04
                  DevM:0X08 Sign:0x10 Agmt:0x20
                  [default Auth]
-k <key size>   : Key size RSA1024:0x41 RSA2048:0x42 [default RSA1024]
-o <filename>   : Output Pubkey to file in PEM format
-s              : Save Pubkey with header in <Key OID + 0x10E4>
-X              : Bypass Shielded Communication 
-h              : Print this help 
```

Example : generate an RSA1024 key with type Auth/Enc/Sign in OID 0xe0fc and save pubkey in OID 0xF1E0.

```console
foo@bar:~$ ./bin/trustm_rsa_keygen -g 0xe0fc -t 0x13 -k 0x41 -o test_e0fc_pub.pem -s
========================================================
Generating Key to 0xE0FC
Output File Name : test_e0fc_pub.pem 
Pubkey :
	30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 
	05 00 03 81 8d 00 30 81 89 02 81 81 00 9c 2d 6b 
	19 9c 8e d9 6c 59 0b bc 53 4a 1f 51 0c 87 14 71 
	09 21 55 d6 0c 1c 36 71 42 d9 dd db a2 f5 d8 de 
	df 80 d2 0f aa ae 31 6e 08 04 60 2d 32 ac 3c b7 
	e1 d0 d9 47 16 77 d7 ed d9 d3 e8 41 ed 6a e7 88 
	10 a6 2e 51 d2 cb d2 7d 9a 3b c8 09 c9 05 27 0d 
	85 39 c2 b6 4f 76 08 59 6e e7 51 07 9e 76 60 96 
	8d 63 ce 19 fc d0 a2 7c 28 c2 35 30 72 96 7d 3f 
	3c 48 95 bc 0a a5 5a 37 c6 64 e3 8e 31 02 03 01 
	00 01 
Write Success to OID: 0xF1E0.
========================================================

foo@bar:~$ cat test_e0fc_pub.pem 
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCcLWsZnI7ZbFkLvFNKH1EMhxRx
CSFV1gwcNnFC2d3bovXY3t+A0g+qrjFuCARgLTKsPLfh0NlHFnfX7dnT6EHtaueI
EKYuUdLL0n2aO8gJyQUnDYU5wrZPdghZbudRB552YJaNY84Z/NCifCjCNTByln0/
PEiVvAqlWjfGZOOOMQIDAQAB
-----END PUBLIC KEY-----

foo@bar:~$ ./bin/trustm_data -r 0xf1e0
========================================================
App DataStrucObj type 2     [0xF1E0] [Size 1500] : 
	03 81 8d 00 30 81 89 02 81 81 00 9c 2d 6b 19 9c 
	8e d9 6c 59 0b bc 53 4a 1f 51 0c 87 14 71 09 21 
	55 d6 0c 1c 36 71 42 d9 dd db a2 f5 d8 de df 80 
	d2 0f aa ae 31 6e 08 04 60 2d 32 ac 3c b7 e1 d0 
	d9 47 16 77 d7 ed d9 d3 e8 41 ed 6a e7 88 10 a6 
	2e 51 d2 cb d2 7d 9a 3b c8 09 c9 05 27 0d 85 39 
	c2 b6 4f 76 08 59 6e e7 51 07 9e 76 60 96 8d 63 
	ce 19 fc d0 a2 7c 28 c2 35 30 72 96 7d 3f 3c 48 
	95 bc 0a a5 5a 37 c6 64 e3 8e 31 02 03 01 00 01 
	47 1b 75 53 fd 53 88 72 5e 0b 83 04 29 4e 44 03 
	51 7a 50 ea f6 a7 a9 82 04 6e cb 1a fa 57 7e 17 
	b6 39 d8 76 e7 fe 76 84 59 bc e6 91 a3 f7 fc 75 
	e2 e3 f7 ec 2a d6 3e 36 c6 f0 7f fb a8 50 d5 a7 
	fc 7e c2 28 2e bf ea e2 8d c9 c9 6e 76 69 a3 a2 
	ec 2f 01 40 8f 65 ba 16 19 81 00 8f 74 17 31 da 
	0e 2f f4 19 a9 f3 00 15 8a 28 5e af 99 4e ab 96 
	7f c8 7f fd f6 ea 17 30 7f 71 8e 1f 27 a1 02 03 
	01 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 
	...
	(trucated for better view)
========================================================

```

### <a name="trustm_rsa_sign"></a>trustm_rsa_sign

Simple demo to show the process to sign using OPTIGA™ Trust M RSA key.

```console
foo@bar:~$ ./bin/trustm_rsa_sign 
Help menu: trustm_rsa_sign <option> ...<option>
option:- 
-k <OID Key>  : Select RSA key for signing OID (0xE0FC-0xE0FD) 
-o <filename> : Output to file 
-i <filename> : Input Data file
-H            : Hash before sign
-X            : Bypass Shielded Communication 
-h            : Print this help
```

Example : Hash and sign the file helloworld.txt with key OID 0xE0FC and output to testsignature.bin

```console
foo@bar:~$ ./bin/trustm_rsa_sign -k 0xe0fc -o testsignature.bin -i helloworld.txt -H
========================================================
OID Key          : 0xE0FC
Output File Name : testsignature.bin 
Input File Name  : helloworld.txt 
Hash Success : SHA256
	E0 EE B7 C6 63 CC 5F 6F 45 26 13 E2 D7 AE FF 45 
	2A 26 95 A0 2F B4 AF 30 33 CC 5B C0 62 01 DE 70 
	
filesize: 14
Success
========================================================

foo@bar:~$ hd testsignature.bin
00000000  0f 20 5a d3 0f 8c ec 41  24 74 d9 e3 20 bf ba 75  |. Z....A$t.. ..u|
00000010  56 df a4 5b be 25 0e 0e  e5 32 1a f5 bf 24 45 e0  |V..[.%...2...$E.|
00000020  1d 4c f5 b7 99 0c 17 c2  49 88 52 e1 b8 b4 9e 7d  |.L......I.R....}|
00000030  da 48 6d 98 53 45 e0 12  e8 48 59 dc 80 35 cd 2f  |.Hm.SE...HY..5./|
00000040  e0 01 c1 e2 1e 1d 00 05  9a 32 3b 56 d7 90 72 a9  |.........2;V..r.|
00000050  30 06 72 c9 f4 19 62 eb  20 76 9f c8 12 cb 23 ff  |0.r...b. v....#.|
00000060  bf b1 56 80 89 ea fe 7b  52 5d f0 26 98 10 3e 82  |..V....{R].&..>.|
00000070  bf 8d a7 9b 5e 2b e9 ec  89 6f 46 f2 ee fa 03 83  |....^+...oF.....|
00000080
```

### <a name="trustm_rsa_verify"></a>trustm_rsa_verify

Simple demo to show the process to verify using OPTIGA™ Trust M library.

```console
foo@bar:~$ ./bin/trustm_rsa_verify 
Help menu: trustm_rsa_verify <option> ...<option>
option:- 
-k <OID Key>   : Use Certificate from Data OID 
-p <pubkey>    : Use Pubkey file
-i <filename>  : Input Data file
-s <signature> : Signature file
-H             : Hash input before verify
-X             : Bypass Shielded Communication 
-h             : Print this help
```

Example : verifying a signature using external public key.

```console
foo@bar:~$ ./bin/trustm_rsa_verify -i helloworld.txt -s testsignature.bin -p test_e0fc_pub.pem -H
========================================================
Pubkey file         : test_e0fc_pub.pem
Input File Name     : helloworld.txt 
Signature File Name : testsignature.bin 
Hash Digest : 
	E0 EE B7 C6 63 CC 5F 6F 45 26 13 E2 D7 AE FF 45 
	2A 26 95 A0 2F B4 AF 30 33 CC 5B C0 62 01 DE 70 
	
Signature : 
	0F 20 5A D3 0F 8C EC 41 24 74 D9 E3 20 BF BA 75 
	56 DF A4 5B BE 25 0E 0E E5 32 1A F5 BF 24 45 E0 
	1D 4C F5 B7 99 0C 17 C2 49 88 52 E1 B8 B4 9E 7D 
	DA 48 6D 98 53 45 E0 12 E8 48 59 DC 80 35 CD 2F 
	E0 01 C1 E2 1E 1D 00 05 9A 32 3B 56 D7 90 72 A9 
	30 06 72 C9 F4 19 62 EB 20 76 9F C8 12 CB 23 FF 
	BF B1 56 80 89 EA FE 7B 52 5D F0 26 98 10 3E 82 
	BF 8D A7 9B 5E 2B E9 EC 89 6F 46 F2 EE FA 03 83 
	
Pub key : [1024]
	03 81 8D 00 30 81 89 02 81 81 00 9C 2D 6B 19 9C 
	8E D9 6C 59 0B BC 53 4A 1F 51 0C 87 14 71 09 21 
	55 D6 0C 1C 36 71 42 D9 DD DB A2 F5 D8 DE DF 80 
	D2 0F AA AE 31 6E 08 04 60 2D 32 AC 3C B7 E1 D0 
	D9 47 16 77 D7 ED D9 D3 E8 41 ED 6A E7 88 10 A6 
	2E 51 D2 CB D2 7D 9A 3B C8 09 C9 05 27 0D 85 39 
	C2 B6 4F 76 08 59 6E E7 51 07 9E 76 60 96 8D 63 
	CE 19 FC D0 A2 7C 28 C2 35 30 72 96 7D 3F 3C 48 
	95 BC 0A A5 5A 37 C6 64 E3 8E 31 02 03 01 00 01 
	
Verify Success.
========================================================
```

Example : verifying using certificate store in OID 0xE0E2.

*Note :  This example assume you have a valid x.509 certificate with key usage for signature store in OID 0xE0E2 and data is signed by the private key of the x.509 certificate.*  

```console
foo@bar:~$ ./bin/trustm_rsa_verify -i helloworld.txt -s testsignature.bin -k 0xe0e2 -H
========================================================
OID Cert            : 0xE0E2
Input File Name     : helloworld.txt 
Signature File Name : testsignature.bin 
Hash Digest : 
	E0 EE B7 C6 63 CC 5F 6F 45 26 13 E2 D7 AE FF 45 
	2A 26 95 A0 2F B4 AF 30 33 CC 5B C0 62 01 DE 70 
	
Signature : 
	0F 20 5A D3 0F 8C EC 41 24 74 D9 E3 20 BF BA 75 
	56 DF A4 5B BE 25 0E 0E E5 32 1A F5 BF 24 45 E0 
	1D 4C F5 B7 99 0C 17 C2 49 88 52 E1 B8 B4 9E 7D 
	DA 48 6D 98 53 45 E0 12 E8 48 59 DC 80 35 CD 2F 
	E0 01 C1 E2 1E 1D 00 05 9A 32 3B 56 D7 90 72 A9 
	30 06 72 C9 F4 19 62 EB 20 76 9F C8 12 CB 23 FF 
	BF B1 56 80 89 EA FE 7B 52 5D F0 26 98 10 3E 82 
	BF 8D A7 9B 5E 2B E9 EC 89 6F 46 F2 EE FA 03 83 
	
Verify Success.

========================================================
```

###  <a name="trustm_symmetric_keygen"></a>trustm_symmetric_keygen

Simple demo to show the process to generate symmetric key using OPTIGA™ Trust M library.

Note: The Access Condition CHA for OID 0xe200 must be set to "ALW"(Only executable when LcsO<op). Fore details, please refer to the test script AES_CBC.sh inside  "**linux-optiga-trust-m/scripts/misc/**"

```console
foo@bar:~$ ./bin/trustm_symmetric_keygen 
Help menu: trustm_symmetric_keygen <option> ...<option>
option:- 
-t <key type>   : Key type Auth:0x01 Enc :0x02 HFWU:0x04
                           DevM:0X08 Sign:0x10 Agmt:0x20
                           [default Enc]
-k <key size>   : Key size AES128:0x81 AES192:0x82 AES256:0x83
                           [default AES128]
-X              : Bypass Shielded Communication 
-h              : Print this help 
```

Example : generate an AES256 key with type Enc in OID 0xe200.

```console
foo@bar:~$ ./bin/trustm_symmetric_keygen -t 0x02 -k 0x83 
========================================================
Successfully Generated Symmetric Key in 0xE200 
========================================================
```

###  <a name="trustm_symmetric_enc"></a>trustm_symmetric_enc

Simple demo to show the process to encrypt using OPTIGA™ Trust M library.

```console
foo@bar:~$ ./bin/trustm_symmetric_enc 
Help menu: trustm_symmetric_enc <option> ...<option>
option:- 
-m <mode>     : Mode CBC:0x09 CBC_MAC:0X0A CMAC:0X0B 
                     [default CBC]
-o <filename> : Output to file 
-i <filename> : Input Data file
-v <filename> : Input IV Value
                Only needed for CBC mode
-X            : Bypass Shielded Communication 
-h            : Print this help 

```

Example : Encrypt mydata.txt using AES256 CBC mode.

Note: Initialized value is only applicable for AES CBC mode.

```console
foo@bar:~$ ./bin/trustm_symmetric_enc -m 0x09 -v iv_aes256.bin -i mydata.txt -o aes256.enc 
========================================================
mode             : 0x0009 
Output File Name : aes256.enc 
Input File Name  : mydata.txt 
Input data :    
	6D 79 64 61 74 61 31 32 33 34 35 36 37 38 39 0A 
	
IV File Name  : iv_aes256.bin 
Initialized value : 
	69 6E 69 74 69 61 6C 69 7A 65 64 76 32 35 36 0A 
	
Success
========================================================
```

###  <a name="trustm_symmetric_dec"></a>trustm_symmetric_dec

Simple demo to show the process to decrypt using OPTIGA™ Trust M library.

```console
foo@bar:~$ ./bin/trustm_symmetric_dec
Help menu: trustm_symmetric_dec <option> ...<option>
option:- 
-m <mode>     : Mode CBC:0x09 CBC_MAC:0X0A CMAC:0X0B 
                     [default CBC]
-o <filename> : Output to file 
-i <filename> : Input Data file
-v <filename> : Input IV Value
-X            : Bypass Shielded Communication 
-h            : Print this help 
```

Example : decrypt aes256.enc using AES256 CBC mode.

Note: Initialized value is only applicable for AES CBC mode.

```console
foo@bar:~$ ./bin/trustm_symmetric_dec -m 0x09 -v iv_aes256.bin -i aes256.enc -o mydata.txt.dec
========================================================
mode             : 0x0009 
Output File Name : mydata.txt.dec 
Input File Name  : aes256.enc 
Input data : 
	E5 4E C6 9E 33 51 0F 3D 81 8C 0D 58 34 04 49 D6 
	
IV File Name  : iv_aes256.bin 
Initialized value : 
	69 6E 69 74 69 61 6C 69 7A 65 64 76 32 35 36 0A 
	
Success
========================================================
```

###  <a name="trustm_hkdf"></a>trustm_hkdf

Simple demo to show the process to derive key using OPTIGA™ Trust M library.

Note: For detailed use case, please refer to the test script hkdf.sh inside  "**linux-optiga-trust-m/scripts/misc/**"

```console
foo@bar:~$ ./bin/trustm_hkdf
Help menu: trustm_hkdf <option> ...<option>
option:- 
-i <OID>      : Input secret OID 0xNNNN 
                [default 0xF1D0]
-H <SHA>      : SHA256:0x08 SHA384 :0x09 SHA512:0x0A
                [default SHA256]
-f <filename> : Import Info 
-s <filename> : Import Salt 
-o <filename> : Export Derived Key 
-X            : Bypass Shielded Communication 
-h            : Print this help 
```

Example : derive key using HKDF SHA256 with shared secret in 0xF1D0.

Precondition: Write shared secret into the data object and change the metadata of this data object to PRESSEC.

```console
foo@bar:~$ ./bin/trustm_hkdf -i 0xF1D0 -H 0X08 -f info.bin -s salt.bin -o hkdf_f1d0_256.txt
========================================================
Run HKDF SHA256 command to derive the key

Input Secret OID: 0xF1D0
HKDF Type 0x0008
Output Derived key. 
========================================================
HKDF Type        : 0x0008 
Info File Name   : info.bin 
Salt File Name   : salt.bin 
Output File Name : hkdf_f1d0_256.txt 
salt data : 
	73 61 6C 74 31 32 33 34 35 36 37 38 39 61 62 31 
	32 33 34 35 36 37 38 39 0A 
Info data : 
	69 6E 66 6F 76 61 6C 75 65 31 32 33 0A 
Success
Decryption Key :
	D6 8B 57 18 C3 E8 F7 82 5F 1C A5 19 A7 59 26 8B 
	
========================================================
```

###  <a name="trustm_hmac"></a>trustm_hmac

Simple demo to show the process to generate the MAC for the given input data using the secret installed in OPTIGA™ Trust M.

Note: For detailed use case, please refer to the test script hmac.sh inside  "**linux-optiga-trust-m/scripts/misc/**"

```console
foo@bar:~$ ./bin/trustm_hmac
Help menu: trustm_hmac <option> ...<option>
option:- 
-I <OID>      : Input secret OID 0xNNNN 
                [default 0xF1D0]
-H <SHA>      : hmac_SHA256:0x20 hmac_SHA384 :0x21 hmac_SHA512:0x22
                [default hmac_SHA256]
-o <filename> : Output MAC Data 
-i <filename> : Input Data file
-X            : Bypass Shielded Communication 
-h            : Print this help  
```

Example : generate MAC value using HMAC SHA256 with shared secret in 0xF1D0.

Precondition: Write shared secret into the data object and change the metadata of this data object to PRESSEC.

```console
foo@bar:~$ ./bin/trustm_hmac -I 0xF1D0 -H 0X20 -i hmac.txt -o hmac_data.txt
========================================================
Input Secret OID: 0xF1D0
SHA Type 0x0020
output the MAC data. 
========================================================
HMAC Type         : 0x0020 
Output File Name : hmac_data.txt 
Input File Name  : hmac.txt 
Input data : 
	68 6D 61 63 74 65 73 74 31 32 33 34 35 36 37 38 
	0A 
MAC data :
	1A 36 BA 85 4F B1 CC A5 4C 83 98 CD 5B CB EB 67 
	7D D5 07 B6 BD 9A E0 73 15 0D F6 63 6B 57 E1 6F 
	
========================================================

```

## <a name="engine_usage"></a>OPTIGA™ Trust M3 OpenSSL Engine usage

The Engine is tested base on OpenSSL version 1.1.1d

*Note : The OPTIGA™ Trust M Engine shielded communication depends on the default reset protection level for OPTIGA CRYPT and UTIL APIs. If the setting is set to OPTIGA_COMMS_NO_PROTECTION than the engine will not have shielded communication protection.*

### <a name="rand"></a>rand

Usuage : Random number generation
Example

```console 
foo@bar:~$ openssl rand -engine trustm_engine -base64 1024
```
*Note :* 
*If OPTIGA™ Trust M random number generation fails, there will still be random number output.* 
*This is control by OpenSSL engine do not have control over it.*

### <a name="req"></a>req
Usuage : Certificate request / self signed cert / key generation

OPTIGA™ Trust M engine uses the -key parameter to pass input to the key generation/usage function.

Following is the input format:

-key <OID> : <public key input> : <NEW> :<key size> : <key usage>

where :

- OID for OPTIGA™ Trust M key
  - if OID 0xE0F0 is used no other input is needed
- public key input
  - public key file name in PEM format
  - \* = no public input
  - ^ = public key store in Application OID Key
    - 0xE0F1 store in 0xF1D1,
    - 0xE0F2 store in 0xF1D2,
    - 0xE0F3 store in 0xF1D3,
    - 0xE0FC store in 0xF1E0,
    - 0xE0FD store in 0xF1E1
- NEW
  - Generate new key pair in OPTIGA™ Trust M
- Key size
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
- Key usage 
  - Auth : 0x01 
  - Enc : 0x02 
  - HFWU : 0x04 
  - DevM : 0X08 
  - Sign : 0x10 
  - Agmt : 0x20

*Note: If wrong public is submitted the certificate generation will still go through but verification will fail.*

Example : Generating a certificate request using OID 0xE0F3 with new key generated, ECC 384 key length and Auth/Enc/Sign usage. Verify that public key match the private key in the OID.

```console 
foo@bar:~$ openssl req -keyform engine -engine trustm_engine -key 0xe0f3:*:NEW:0x04:0x13 -new -out test_e0f3.csr -verify
```
*Note:*
*If wrong public is used or no pubkey is submitted the certificate generation will still* 
*go through but verification will fail. Pubic key input only in PEM*

### <a name="pkey"></a>pkey
Usuage : Key tools / Key generation

OPTIGA™ Trust M engine uses the -in parameter to pass input to the key generation/usage function.

Following is the input format:

-in <OID> : <public key input> : <NEW> :<key size> : <key usuage>

(see [req](#req) for input details)

Example

```console 
foo@bar:~$ openssl pkey -engine trustm_engine -pubout -inform engine -in 0xe0f1:*:NEW -out testpube0f1.pem
```

### <a name="dgst"></a>dgst
Usuage : Sign and verify
Example

```console 
foo@bar:~$ openssl dgst -sign 0xe0f1 -engine trustm_engine -keyform engine -out helloworld.sig helloworld.txt
```
```console 
foo@bar:~$ openssl dgst -sha256 -verify testpube0f1.pem -signature helloworld.sig helloworld.txt
```

### <a name="test_tls_ecc"></a>Testing TLS connection with ECC key

#### Scenario where Trust M is on the client :

*Note : To generate a test server certificate refer to [Generating a Test Server Certificate](#testServercert)* 

Creates new ECC 256 key length and Auth/Enc/Sign usage and generate a certificate  request for OPTIGA™ Trust M key 0xE0F1

```console
foo@bar:~$ openssl req -keyform engine -engine trustm_engine \
-key 0xe0f1:^:NEW:0x03:0x13 \
-new \
-out test_e0f1.csr
```

Issue the certificate with keyUsage=digitalSignature,keyEncipherment on the client side with OPTIGA_Trust_M_Infineon_Test_CA.

*Note : Refer to [Generating a Test Server Certificate](#testServercert)  for openssl.cnf*

```console
foo@bar:~$ openssl x509 -req -in test_e0f1.csr \
-CA trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out test_e0f1.crt \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext1
```

Running the test server : 

```console
foo@bar:~$ openssl s_server \
-cert test_opensslserver.crt \
-key privkey.pem -accept 5000 \
-verify_return_error \
-Verify 1 \
-CAfile trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem 
```

Running the test client : *(open a new console)* 

```console
foo@bar:~$ openssl s_client \
-connect 127.0.0.1:5000 \
-client_sigalgs ECDSA+SHA256 \
-keyform engine \
-engine trustm_engine \
-cert test_e0f1.crt -key 0xe0f1:^ \
-tls1_2 \
-CAfile trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-verify 1
```

#### Scenario where Trust M is on the server :

Creates new ECC 256 key length and Auth/Enc/Sign usage and generate a certificate  request for OPTIGA™ Trust M key 0xE0F2

```console
foo@bar:~$ openssl req -keyform engine -engine trustm_engine \
-key 0xe0f2:^:NEW:0x03:0x13 \
-new \
-out test_e0f2.csr
```

Issue the certificate with keyUsage=keyCertSign, cRLSign, digitalSignature on the server side with OPTIGA_Trust_M_Infineon_Test_CA.

```console
foo@bar:~$ openssl x509 -req -in test_e0f2.csr \
-CA trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out test_e0f2.crt \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext2
```

Running the test server : 

```console
foo@bar:~$ openssl s_server -keyform engine -engine trustm_engine \
-cert test_e0f2.crt \
-key 0xe0f2:^ \
-accept 5000 \
-verify_return_error \
-CAfile trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-sigalgs ECDSA+SHA256
```

Running the test client : *(open a new console)* 

```console
foo@bar:~$ openssl s_client \
-CAfile trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-connect 127.0.0.1:5000 -tls1_2
```

### <a name="test_tls_rsa"></a>Testing TLS connection with RSA key

#### Scenario where Trust M is on the client :

*Note : To generate a test server certificate refer to [Generating a Test Server Certificate](#testServercert)* 

Creates new RSA 2048 key length and Auth/Enc/Sign usage and generate a certificate  request for OPTIGA™ Trust M key 0xE0FC

```console
foo@bar:~$ openssl req -keyform engine -engine trustm_engine \
-key 0xe0fc:^:NEW:0x42:0x13 \
-new \
-out test_e0fc.csr
```

Issue the certificate with keyUsage=digitalSignature,keyEncipherment on the client side with OPTIGA_Trust_M_Infineon_Test_CA.

*Note : Refer to [Generating a Test Server Certificate](#testServercert)  for openssl.cnf*

```console
foo@bar:~$ openssl x509 -req -in test_e0fc.csr \
-CA trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out test_e0fc.crt \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext1
```

Running the test server : 

```console
foo@bar:~$ openssl s_server \
-cert test_opensslserver.crt \
-key privkey.pem -accept 5000 \
-verify_return_error \
-Verify 1 \
-CAfile trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem 
```

Running the test client : *(open a new console)* 

```console
foo@bar:~$ openssl s_client -connect 127.0.0.1:5000 \
-client_sigalgs RSA+SHA256 \
-keyform engine \
-engine trustm_engine \
-cert test_e0fc.crt \
-key 0xe0fc:^ \
-tls1_2 \
-CAfile trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-verify 1
```

#### Scenario where Trust M is on the server :

Creates new RSA 2048 key length and Auth/Enc/Sign usage and generate a certificate  request for OPTIGA™ Trust M key 0xE0FD

```console
foo@bar:~$ openssl req -keyform engine -engine trustm_engine \
-key 0xe0fd:^:NEW:0x42:0x13 \
-new \
-out test_e0fd.csr
```

Issue the certificate with keyUsage=keyCertSign, cRLSign, digitalSignature on the server side with OPTIGA_Trust_M_Infineon_Test_CA.

```console
foo@bar:~$ openssl x509 -req -in test_e0fd.csr \
-CA trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out test_e0fd.crt \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext2
```

Running the test server : 

```console
foo@bar:~$ openssl s_server -keyform engine -engine trustm_engine \
-cert test_e0fd.crt \
-key 0xe0fd:^ \
-accept 5000 \
-verify_return_error \
-CAfile trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-sigalgs RSA+SHA256
```

Running the test client : *(open a new console)* 

```console
foo@bar:~$ openssl s_client \
-CAfile trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-connect 127.0.0.1:5000 -tls1_2
```

### <a name="testServercert"></a>Generating a Test Server Certificate

 Generate a new key pair and certificate request. Private key is output to private.pem

```console
foo@bar:~$ openssl req -new -out test_opensslserver.csr
```

Creates the openssl.cnf with the below contain:

```console
foo@bar:~$ cat openssl.cnf 
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
foo@bar:~$ openssl x509 -req -in test_opensslserver.csr \
-CA trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem \
-CAkey trustm_lib/certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem \
-CAcreateserial \
-out test_opensslserver.crt \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext2
```

### <a name="issue_cert"></a>Using OPTIGA™ Trust M OpenSSL engine to sign and issue certificate

In this section, we will demonstrate how you can use OPTIGA™ Trust M OpenSSL engine to enable OPTIGA™ Trust M as a simple Certificate Authorities (CA) without revocation and tracking of certificate it issue.

#### Generating CA key pair and Creating OPTIGA™ Trust M CA self sign certificate

Create OPTIGA™ Trust M CA key pair with the following parameters:

- OID 0xE0F2
- public key store in 0xE1D2
- Self signed CA cert with subject :
  - Organization : Infineon OPTIGA(TM) Trust M
  - Common Name : UID of Trust M
  - expiry days : ~10 years

```console
foo@bar:~$ openssl req -keyform engine -engine trustm_engine \
-key 0xe0f2:^:NEW:0x03:0x13 \
-new \
-x509 \
-days 3650 \
-subj /O="Infineon OPTIGA(TM) Trust M"\
/CN="CD16336B01001C000100000A085255000A005C0046801010711118" \
-out test_e0f2.crt
```

#### Generating a Certificate Request (CSR)

You may use the example given in [req](#req) to generate a CSR or used any valid CSR

#### Signing and issuing the Certificate with Trust M

Following demonstrate how you can issue and sign certificate with OPTIGA™ Trust M with the following inputs:

- input csr file : test_e0f3.csr
- CA Cert : test_e0f2.crt
- CA key : 0xE0F2 with public key store in 0xE1D2
- Create new serial number for certificate (serial number is store in test_e0f3.srl)
- using extension cert_ext in extension file
- expiry days : 1 year

*Note : Refer to [Generating a Test Server Certificate](#testServercert)  for openssl.cnf*

```
foo@bar:~$ openssl x509 -CAkeyform engine -engine trustm_engine \
-req \
-in test_e0f3.csr \
-CA test_e0f2.crt \
-CAkey 0xe0f2:^ \
-CAcreateserial \
-out test_e0f3.crt \
-days 365 \
-sha256 \
-extfile openssl.cnf \
-extensions cert_ext
```

### <a name="opensslC"></a>Simple Example on OpenSSL using C language

In this section, we will describe and demo how the OPTIGA™ Trust M OpenSSL engine could be coded in 'C' to perform TLD/DTLS communication.

*Note : The code only shows example on using OPTIGA™ Trust M for authentication and the secure communication is done via OpenSSL.*

#### Setting up the environment for the demonstration

For easy setup, the demo uses the following input for :

- Server (system with OPTIGA™ Trust M and listening to connection) 
  - server certificate : cert store in oid 0xE0E0
  - OPTIGA™ Trust M key : 0xE0F0
  - CA certificate :  Infineon OPTIGA(TM) Trust M CA 300 Root CA 2.pem
    - include with Infineon OPTIGA(TM) ECC Root CA 2 certificate
    - include with Infineon OPTIGA(TM) Trust M CA 300.pem
  - Port : 5000
  - SSL Protocol : TLS1.3
- Client (system that send HELLO request) 
  - - CA certificate :  Infineon OPTIGA(TM) Trust M CA 300 Root CA 2.pem
      - include with Infineon OPTIGA(TM) ECC Root CA 2 certificate
      - include with Infineon OPTIGA(TM) Trust M CA 300.pem
  - IP : 127.0.0.1
  - Port : 5000
  - SSL Protocol : DTLS1.3

#### Server Setup

##### Getting the 0xE0E0 Certificate in OPTIGA™ Trust M and save it as test_e0e0.crt

You may use the below example to get the cert.

```console
foo@bar:~$ ./bin/trustm_cert -r 0xe0e0 -o test_e0e0.crt
========================================================
OID              : 0xE0E0 
Output File Name : test_e0e0.crt 
Success!!!
========================================================
```

##### CA Certificate

Ensure *Infineon OPTIGA(TM) Trust M CA 300 Root CA 2.pem* is in the same directory as test_e0e0.crt.

The *Infineon OPTIGA(TM) Trust M CA 300 Root CA 2.pem* contain 2 certificate namely:

- Infineon OPTIGA(TM) Trust M CA 300 
- Infineon OPTIGA(TM) ECC Root CA 2

Below is a quick tips for verifying the Server cert matches the CA cert with OpenSSL

```console
foo@bar:~$ openssl verify -CAfile 'Infineon OPTIGA(TM) Trust M CA 300 Root CA 2.pem' -show_chain test_e0e0.crt 
test_e0e0.crt: OK
Chain:
depth=0: CN = InfineonIoTNode (untrusted)
depth=1: C = DE, O = Infineon Technologies AG, OU = OPTIGA(TM), CN = Infineon OPTIGA(TM) Trust M CA 300
depth=2: C = DE, O = Infineon Technologies AG, OU = OPTIGA(TM) Devices, CN = Infineon OPTIGA(TM) ECC Root CA 2
```

#### Client Setup

Ensure *Infineon OPTIGA(TM) Trust M CA 300 Root CA 2.pem* is in the current directory.

#### Running the demonstration

As the default IP is set to a loopback IP 127.0.0.1 both the server and client need to be run on the same system. To run the client and server on a different system please refer to [More about simpleTest_Server](#more-about-simpletest_server) and [More about simpleTest_Client](#more-about-simpletest_client)

To build the demo refer to [Build the command line tools](#build-the-command-line-tools)

#### Running the Server

Open a new terminal in the system and ensure *test_e0e0.crt* and *Infineon OPTIGA(TM) Trust M CA 300 Root CA 2.pem* is in the current folder. 

In this example, *test_e0e0.crt*  is needed to copy into folder scripts/SimpleServeClientTest/with_e0f0_key where *Infineon OPTIGA(TM) Trust M CA 300 Root CA 2.pem* is located.  Run *update latest exe.sh* to copy simpleTest_Server and simpleTest_Client into this folder before running simpleTest_Server

Example of simpleTest_Server running without client connection

```console
foo@bar:~$ ./scripts/SimpleServeClientTest/with_e0f0_key/simpleTest_Server 
89 main: *****************************************
141 serverListen: Listening to incoming connection
```

#### Running the Client

Open another new terminal in the system and ensure *Infineon OPTIGA(TM) Trust M CA 300 Root CA 2.pem* is in the current folder. Run simpleTest_Client

Example of simpleTest_Client running with connection to server

```
foo@bar:~$ ./scripts/SimpleServeClientTest/with_e0f0_key/simpleTest_Client 
88 main: *****************************************
113 doClientConnect: s_ipaddr : 127.0.0.1
150 doClientConnect: Connecting to server ....
168 doClientConnect: Connected to 127.0.0.1, port :0x8813
190 doClientConnect: Performing Handshaking .....
199 doClientConnect: Connection using : TLS_AES_256_GCM_SHA384
200 doClientConnect:                  : TLSv1.3
From Server [11072] : 001
From Server [11072] : 002
From Server [11072] : 003
From Server [11072] : 004
From Server [11072] : 005
```

Server terminal output

```console
foo@bar:~$ ./scripts/SimpleServeClientTest/with_e0f0_key/simpleTest_Server 
92 main: *****************************************
144 serverListen: Listening to incoming connection
157 serverListen: Connection from 127.0.0.1, port :0xe48f
144 serverListen: Listening to incoming connection
236 doServerConnected: Engine ID : trustm_engine
242 doServerConnected: Init TrustM Engine. Ok
248 doServerConnected: Set Default Engine Ok.
261 doServerConnected: Load Certificate ok
269 doServerConnected: Private Key Match the Server Certificate.
278 doServerConnected: Load CA cert ok
301 doServerConnected: Performing Handshking ......... 
306 doServerConnected: Connection using : TLS_AES_256_GCM_SHA384
307 doServerConnected:                  : TLSv1.3
308 doServerConnected: ++++++++++++++++++++++++++++++++++++++++++++++
328 doServerConnected: [12081] Received : 1
328 doServerConnected: [12081] Received : 2
328 doServerConnected: [12081] Received : 3
328 doServerConnected: [12081] Received : 4
328 doServerConnected: [12081] Received : 5
```

The above console screen show a successful server/client connection via TLS1.3. After the TLS handshake is completed the client will send count from 1 to 100 to the server. When server received the data from client it will is display the info received and send back the Process ID (PID) and data received to the client. The client when received the data from the service, it will display them on the screen.

To run multiple client connection, open another new terminal in the system and ensure *Infineon OPTIGA(TM) Trust M CA 300.pem* is in the current folder. Run simpleTest_Client.

#### More about simpleTest_Server

```c
// Macro for Keys/Certificates
#define SERVER_CERT     "test_e0e0.crt"
#define SERVER_KEY      "0xe0f0"
#define CA_CERT         "Infineon OPTIGA(TM) Trust M CA 300 Root CA 2.pem"

// Macro for Engine
#define ENGINE_NAME     "trustm_engine"

// Default IP/PORT
#define DEFAULT_IP      "127.0.0.1"
#define DEFAULT_PORT    5000
#define SECURE_COMM   TLS_server_method()
//#define SECURE_COMM     DTLS_server_method()
```

In the *simpleTest_Server.c* code ~ line number 54-66. List the macro for changing following input:

- SERVER_CERT      *\<filename for server certificate in PEM format>*
- SERVER_KEY        *\<OID of OPTIGA™ Trust M key used. Refer to [req](#req) for the key input format>*
- CA_CERT              *\<CA Certificate filename. if CA cert is chain ensure all cert is in the chain>*
- ENGINE_NAME    *\<OPTIGA™ Trust M engine name>*
- DEFAULT_IP         *\<IP address, not important for server>*
- DEFAULT_PORT   *\<Port to use for connection>*
- SECURE_COMM   *\<SSL Protocol to be used TLS/DTLS>*

#### More about simpleTest_Client

```
// Macro for Keys/Certificates
#define CA_CERT      "Infineon OPTIGA(TM) Trust M CA 300 Root CA 2.pem"

// Macro for Engine
#define ENGINE_NAME  "trustm_engine"

// Default IP/PORT
#define DEFAULT_IP    "127.0.0.1"
#define	DEFAULT_PORT  5000
#define SECURE_COMM TLS_client_method()
//#define SECURE_COMM   DTLS_client_method()
```

In the *simpleTest_Client.c* code ~ line number 53-63. List the macro for changing following input:

- CA_CERT                *\<CA Certificate filename. if CA cert is chain ensure all cert is in the chain>*
- ENGINE_NAME     *\<OPTIGA™ Trust M engine name>*
- DEFAULT_IP         *\<IP address, not important for server>*
- DEFAULT_PORT   *\<Port to use for connection>*
- SECURE_COMM   *\<SSL Protocol to be used TLS/DTLS>*

## <a name="known_observations"></a>Known observations

### Secure communication bypass

The I2C secure communication bypass option for CLI only works if the default reset protection level for OPTIGA CRYPT and UTIL APIs is set to OPTIGA_COMMS_NO_PROTECTION.

### OPTIGA™ Trust M Sporadic hang

Check the hardware reset pin if it is connected with an active reset GPIO as assigned n the OPTIGA™ Trust M library. Alternatively, you could configure the library to use software reset.

