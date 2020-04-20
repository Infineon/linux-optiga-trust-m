# Command Line Interface (CLI) & OpenSSL Engine for OPTIGA™ Trust M1 security solution

1. [About](#about)
    * [Prerequisites](#prerequisites)
    * [Contents of the package](#contents_of_package)
2. [Getting Started](#getting_started)
    * [First time building the library](#build_lib)
    * [Building the engine](#build_engine) 
3. [CLI Tools Usage](#cli_usage)
	* [trustm_cert](#trustm_cert)
    * [trustm_chipinfo](#trustm_chipinfo)
    * [trustm_data](#trustm_data)
    * [trustm_ecc_keygen](#trustm_ecc_keygen)
    * [trustm_ecc_sign](#trustm_ecc_sign)
    * [trustm_ecc_verify](#trustm_ecc_verify)
    * [trustm_errorcode](#trustm_errorcode)
    * [trustm_metadata](#metadata)
    * [trustm_readmetadata_data](#trustm_readmetadata_data)
    * [trustm_readmetadata_private](#trustm_readmetadata_private)
    * [trustm_readmetadata_status](#trustm_readmetadata_status)
    * [trustm_read_status](#trustm_read_status)
    * [trustm_rsa_dec](trustm_rsa_dec)
    * [trustm_rsa_enc](trustm_rsa_enc)
    * [trustm_rsa_keygen](trustm_rsa_keygen)
    * [trustm_rsa_sign](trustm_rsa_sign)
    * [trustm_rsa_verify](trustm_rsa_verify)
4. [Trust M1 OpenSSL Engine usage](#engine_usage)
    * [rand](#rand)
    * [req](#req)
    * [pkey](#pkey)
    * [dgst](#dgst)
5. [Known issues](#known_issues)

## <a name="about"></a>About

This is a command line tools tools and OpenSSL Engine for OPTIGA Trust M1 on Linux platform.


### <a name="prerequisites"></a>Prerequisites

Following is the software component to build the tools :
* GCC
* OpenSSL development library (libssl-dev)
* OpenSSL 1.1.X
* OPTIGA Trust M1 library (source code)
* pthread
* rt

Tested platforms:
* Raspberry PI 3 on Linux kernal 4.19

### <a name="contents_of_package"></a>Contents of Package

This tools consists of the following files & directory:
```formated
        .
	├── bin                         /* all executable amd .so file is store here	 */
	├── LICENSE                    // MIT license file
	├── linux_example                     /* Source code for executable file */
	│   ├── trustm_cert.c                 // read and store x.509 certificate in OPTIGA™ Trust M
	│   └── trustm_chipinfo.c             // list chip info
	│   ├── trustm_data.c                 // read and store raw data in OPTIGA™ Trust M
	│   ├── trustm_ecc_keygen.c           // ECC Key generation
	│   ├── trustm_ecc_sign.c             // example of OPTIGA™ Trust M ECC sign function
	│   ├── trustm_ecc_verify.c           // example of OPTIGA™ Trust M ECC verify function
	│   ├── trustm_errorcode.c            // List all known OPTIGA™ Trust M error code
	│   ├── trustm_metadata.c             // read and modify metadata of selected OID 
	│   ├── trustm_monotonic_counter.c    // example of OPTIGA™ Trust M monotonic  counter function
	│   ├── trustm_read_data.c            // read all app1 data
	│   ├── trustm_readmetadata_data.c    // read all metadata of data objects
	│   ├── trustm_readmetadata_private.c // read all metadata of keys OID
	│   ├── trustm_readmetadata_status.c  // read all metadata of status OID
	│   ├── trustm_read_status.c          // read all status data
	│   ├── trustm_rsa_dec.c              // example of OPTIGA™ Trust M RSA Decode function
	│   ├── trustm_rsa_enc.c              // example of OPTIGA™ Trust M RSA Encode function
	│   ├── trustm_rsa_keygen.c           // RSA Key generation
	│   ├── trustm_rsa_sign.c             //  example of OPTIGA™ Trust M RSA sign function
	│   └── trustm_rsa_verify.c           // example of OPTIGA™ Trust M RSA verify function
	├── Makefile                    // this project Makefile 
	├── README.md                   // this read me file in Markdown format 
	├── trustm_engine                     /* all trust M1 OpenSSL Engine source code       */
	│   ├── trustm_engine.c               // entry point for Trust M1 OpenSSL Engine 
	│   ├── trustm_engine_common.h        // header file for Trust M1 OpenSSL Engine
	│   ├── trustm_engine_rand.c          // Random number generator source  
	│   └── trustm_engine_rsa.c           // RSA source 
	├── trustm_helper                     /* Helper rountine for Trust M library           */
	│   ├── include	                          /* Helper include directory
	│   │   └── trustm_helper.h	              // Helper header file
	│   └── trustm_helper.c	              // Helper source 
	└── trustm_lib                        /* Directory for trust M library */
```

## <a name="getting_started"></a>Getting Started
### <a name="build_lib"></a>First time building the library

```console 
foo@bar:~$ make
```
 to install

```console 
foo@bar:~$ sudo make install
```

to uninstall

```console 
foo@bar:~$ sudo make uninstall
```

## <a name="cli_usage"></a>CLI Tools Usage

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
-h              : Print this help 
```

Example : read OID 0xe0e0 and output the certification to teste0e0.crt

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

Example : write certificate teste0e0.crt into OID 0xe0e1

```console
foo@bar:~$ ./bin/trustm_cert -w 0xe0e1 -i teste0e0.crt 
========================================================
Success!!!
========================================================
```

Example : clear certificate store in OID 0xe0e1

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
-o <filename> : Output file 
-p <offset>   : Offset position 
-e            : Erase and wirte 
-h            : Print this help 
```

Example : writing text file 1234.txt into OID 0xe0e1 and reading after writing

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

Example : erase with offset OID 0xe0e1

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

Generate OPTIGA™ Trust M key pair. Key type can be or together to form multiple type.

```console
foo@bar:~$ ./bin/trustm_ecc_keygen 
Help menu: trustm_ecc_keygen <option> ...<option>
option:- 
-g <Key OID>    : Generate ECC Key in OID 0xNNNN 
-t <key type>  	: Key type Auth:0x01 Enc :0x02 HFWU:0x04
                           DevM:0X08 Sign:0x10 Agmt:0x20
                           [default Auth]
-k <key size>   : Key size ECC256:0x03 ECC384:0x04 [default ECC256]
-o <filename>  	: Output Pubkey to file in PEM format
-s              : Save Pubkey without header in <Key OID + 0x10E0>
-h              : Print this help 
```

Example : generate an ECC256 key with type Auth/Enc/Sign in OID 0xe0f3 and save pubkey in OID 0xf1d3.

```console
foo@bar:~$ ./bin/trustm_ecc_keygen -g 0xe0f3 -t 0x13 -k 0x03 -o test_e0f3_pub.pem -s
========================================================
Generating Key to 0xE0F3
Output File Name : test_e0f3_pub.pem 
Pubkey :
	30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 
	86 48 ce 3d 03 01 07 03 42 00 04 07 52 4e 41 67 
	09 ac 78 a0 c4 a8 74 d5 ba 99 59 b6 a2 30 c7 8d 
	33 f6 98 3c cc 51 a5 04 8e 38 34 d1 38 c2 7f 23 
	fa f9 98 5e 8b c6 ed 0b b1 f4 4f 74 cb 69 79 0f 
	ce 05 11 a1 d3 86 59 3b 0d 80 b6 
Write Success to OID: 0xF1D3.
========================================================

foo@bar:~$ cat test_e0f3_pub.pem 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB1JOQWcJrHigxKh01bqZWbaiMMeN
M/aYPMxRpQSOODTROMJ/I/r5mF6Lxu0LsfRPdMtpeQ/OBRGh04ZZOw2Atg==
-----END PUBLIC KEY-----

foo@bar:~$ ./bin/trustm_data -r 0xf1d3
========================================================
App DataStrucObj type 1     [0xF1D3] [Size 0100] : 
	03 42 00 04 07 52 4e 41 67 09 ac 78 a0 c4 a8 74 
	d5 ba 99 59 b6 a2 30 c7 8d 33 f6 98 3c cc 51 a5 
	04 8e 38 34 d1 38 c2 7f 23 fa f9 98 5e 8b c6 ed 
	0b b1 f4 4f 74 cb 69 79 0f ce 05 11 a1 d3 86 59 
	3b 0d 80 b6 00 00 00 00 00 00 00 00 00 00 00 00 
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
	00 00 00 00 
========================================================
```

### <a name="trustm_ecc_sign"></a>trustm_ecc_sign

Simple demo to show the process to sign using OPTIGA™ Trust M key.

```console
foo@bar:~$ ./bin/trustm_ecc_sign 
Help menu: trustm_ecc_sign <option> ...<option>
option:- 
-k <OID Key>  : Select ECC key for signing OID (0xE0F0-0xE0F3) 
-o <filename> : Output to file 
-i <filename> : Input Data file
-H            : Hash before sign
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
	E0 EE B7 C6 63 CC 5F 6F 45 26 13 E2 D7 AE FF 45 
	2A 26 95 A0 2F B4 AF 30 33 CC 5B C0 62 01 DE 70 
	
filesize: 14
Success
========================================================

foo@bar:~$ hd testsignature.bin 
00000000  02 20 08 fe f2 2a 8c 3c  b2 c2 f3 3e fa 69 e9 a7  |. ...*.<...>.i..|
00000010  9a 16 58 2f 9f 53 52 0e  40 18 95 f7 39 b5 ac 10  |..X/.SR.@...9...|
00000020  e0 8b 02 20 13 e1 e1 ea  57 7e e2 cc f7 c7 09 98  |... ....W~......|
00000030  e4 41 d7 64 c5 99 a1 1b  f0 65 45 32 3a ec e1 61  |.A.d.....eE2:..a|
00000040  21 32 97 78                                       |!2.x|
00000044
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
	E0 EE B7 C6 63 CC 5F 6F 45 26 13 E2 D7 AE FF 45 
	2A 26 95 A0 2F B4 AF 30 33 CC 5B C0 62 01 DE 70 
	
Signature : 
	02 20 08 FE F2 2A 8C 3C B2 C2 F3 3E FA 69 E9 A7 
	9A 16 58 2F 9F 53 52 0E 40 18 95 F7 39 B5 AC 10 
	E0 8B 02 20 13 E1 E1 EA 57 7E E2 CC F7 C7 09 98 
	E4 41 D7 64 C5 99 A1 1B F0 65 45 32 3A EC E1 61 
	21 32 97 78 
Pub key : [256]
	03 42 00 04 07 52 4E 41 67 09 AC 78 A0 C4 A8 74 
	D5 BA 99 59 B6 A2 30 C7 8D 33 F6 98 3C CC 51 A5 
	04 8E 38 34 D1 38 C2 7F 23 FA F9 98 5E 8B C6 ED 
	0B B1 F4 4F 74 CB 69 79 0F CE 05 11 A1 D3 86 59 
	3B 0D 80 B6 
Verify Success.
========================================================
```

Example for verifying using certificate store in OID 0xE0E3.

Note :  This example assume you have a valid x.509 certificate with key usage for signature store in OID 0xe0e3 and data is signed by the private key of the x.509 certificate.  

```console
foo@bar:~$ ./bin/trustm_ecc_verify -i helloworld.txt -s testsignature.bin -k 0xe0e3 -H
========================================================
OID Cert            : 0xE0E3
Input File Name     : helloworld.txt 
Signature File Name : testsignature.bin 
Hash Digest : 
	E0 EE B7 C6 63 CC 5F 6F 45 26 13 E2 D7 AE FF 45 
	2A 26 95 A0 2F B4 AF 30 33 CC 5B C0 62 01 DE 70 
	
Signature : 
	02 20 08 FE F2 2A 8C 3C B2 C2 F3 3E FA 69 E9 A7 
	9A 16 58 2F 9F 53 52 0E 40 18 95 F7 39 B5 AC 10 
	E0 8B 02 20 13 E1 E1 EA 57 7E E2 CC F7 C7 09 98 
	E4 41 D7 64 C5 99 A1 1B F0 65 45 32 3A EC E1 61 
	21 32 97 78 
Verify Success.

========================================================
```

### <a name="trustm_errorcode"></a>trustm_errorcode

List all the known OPTIGA™ Trust M error code with description

### <a name="trustm_metadata"></a>trustm_metadata

Modify OPTIGA™ Trust M OID metadata.

*Warning : -L and -T option is not reversible. Lock set Lcs0 to 0x07 and Terminate set Lcs0 to 0x0F*

```console
foo@bar:~$ ./bin/trustm_metadata 
Help menu: trustm_metadata <option> ...<option>
option:- 
-r <OID>  : Read metadata of OID 0xNNNN 
-w <OID>  : Write metadata of OID
-C <data> : Set Change mode (a:allow change,
                             n:disable change,
                             t:disable change on termination,
                             f:<input file for complex setting>)
-R <data> : Set Read mode (a:allow read,
                           t:disable read on termination
                           f:<input file for complex setting>)
-E <data> : Set Change mode (a:allow execute,
                             n:disable execute,
                             t:disable execute on termination,
                             f:<input file for complex setting>)
-L        : Lock OID metadata 
-T        : TERMINATE OID 
-h        : Print this help 
```

Example : changing OID 0xe0e1 metadata to read only and reading the metadata after changing

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

Example : charging OID 0xe0e1 metadata using complex setting (LcsO>3||LcsG<4) for Change mode

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

oid : 0xE0E0-0xE0E3, 0xE0E8-0xE0E9, 0xE0EF, 
        0xE120-0xE123, 0xE140, 
        0xF1D0-0xF1DB, 0xF1E0-0xF1E1

### <a name="trustm_readmetadata_data"></a>trustm_readmetadata_data

Read all data object metadata listed below
oid : 0xE0E0-0xE0E3, 0xE0E8-0xE0E9, 0xE0EF, 
        0xE120-0xE123, 0xE140, 
        0xF1D0-0xF1DB, 0xF1E0-0xF1E1

### <a name="trustm_readmetadata_private"></a>trustm_readmetadata_private

Read all data object metadata listed below
oid : 0xE0F0-0xE0F3
         0xF1FC-0xE0FD

### <a name="trustm_readmetadata_status"></a>trustm_readmetadata_status

Read all data object metadata listed below
oid : 0xE0C0-0xE0C6
        0xF1C0-0xF1C2

### <a name="trustm_read_status"></a>trustm_read_status

Read all data object listed below
oid : 0xE0C0-0xE0C6
        0xF1C0-0xF1C2

### <a name="trustm_rsa_dec"></a>trustm_rsa_dec

Simple demo to show the process to decrypt using OPTIGA™ Trust M key.

Note : This example assume RSA key with usage Encryption has already been generated and data is encrypted by the pubkey

```console
foo@bar:~$ ./bin/trustm_rsa_dec
Help menu: trustm_rsa_dec <option> ...<option>
option:- 
-k <OID Key>  : Select key to decrypt OID 0xNNNN 
-o <filename> : Output to file 
-i <filename> : Input Data file
-h            : Print this help 
```

 Example : Decrypt using OID Key 0xe0fc, an encrypted file test_e0fc.enc and output to test_e0fc.dec

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

Simple demo to show the process to encrypt using OPTIGA™ Trust M key.

```console
foo@bar:~$ ./bin/trustm_rsa_enc 
Help menu: trustm_rsa_enc <option> ...<option>
option:- 
-k <OID Key>  : Select key for encrypt OID 0xNNNN 
-p <pubkey>   : Use Pubkey file
-o <filename> : Output to file 
-i <filename> : Input Data file
-h            : Print this help 
```

 Example :xxxxxxxxxx Encrypt using OID Key 0xe0fc, an encrypted file test_e0fc.enc and output to test_e0fc.dec

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



### <a name="trustm_rsa_sign"></a>trustm_rsa_sign



### <a name="trustm_rsa_verify"></a>trustm_rsa_verify



## <a name="engine_usage"></a>Trust M1 OpenSSL Engine usage
### <a name="rand"></a>rand
Usuage : Random number generation
Example
```console 
foo@bar:~$ openssl rand -engine trustm_engine -base64 1024
```
Note : 
If trustM random number generation fails, there will still be random number output. 
This is control by openSSL engine do not have control over it.

### <a name="req"></a>req
Usuage : Certificate request / self signed cert / key generation
Example
```console 
foo@bar:~$ openssl req -keyform engine -engine trustm_engine -key <OID>:<Public key file | *>:<NEW> -new -out test.csr -verify
```
Note:
If wrong public is used or no pubkey is submitted the certificate generation will still 
go through but verification will fail. Pubic key input only in PEM

### <a name="pkey"></a>pkey
Usuage : Key tools / Key generation
Example
```console 
foo@bar:~$ openssl pkey -engine trustm_engine -pubout -inform engine -in 0xe0fc:*:NEW -out testpube0fc.pem
```

### <a name="dgst"></a>dgst
Usuage : Sign and verify
Example
```console 
foo@bar:~$ openssl dgst -sign 0xe0fc -engine trustm_engine -keyform engine -out helloworld.sig helloworld.txt
```
```console 
foo@bar:~$ openssl dgst -engine trustm_engine -verify testpube0fc.pem -keyform engine -signature helloworld.sig helloworld.txt
```

## <a name="known_issues"></a>Known issues
