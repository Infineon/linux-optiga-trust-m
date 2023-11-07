# Linux Tools for Integrity and Confidentiality Protected Update 

This Linux tools are used to generate manifest and fragment for Integrity and Confidentiality Protected Update function.

Installation:

Go to the repository directory "**linux-optiga-trust-m/ex_protected_update_data_set/Linux**"

```console 
foo@bar:~$ make clean
foo@bar:~$ make
```

 *Note :  This folder is used to generate the manifest and fragment for Integrity and Confidentiality protected update. It can be built and installed after the trustm_lib.so and trustm_engine.so are built and installed.   make clean to ensure a clean build.*

to install

```console 
foo@bar:~$ sudo make install
```

For Usage:

 please run the command shown as below to check all the options:

```console
foo@bar:~$ ./bin/trustm_protected_update_set 
```

The output is shown as below as your reference:

```console
foo@bar:~$ Tool Version : 3.00.2490
Info : Default values are set
Info : User provided inputs

Info : Setting value for data formatter
	Payload version      : 0        
	Trust anchor oid     : E0E8     
	Target oid           : E0E2     
	Digest algorithm     : 29       
	Signature Algorithm  : FFFFFFF9 
	Type of Payload      : FFFFFFFF 
Error : No data available for payload
Usage : <.exe> input1=<value> input2=<value> ..

	(1) : To create manifest , provide the following details
	payload_version      default  :  0        
	                     note     :  Input is a decimal string.E.g. 10 
	trust_anchor_oid     default  :  E0E8     
	                     note     :  Input is a hexadecimal string.E.g. E0E8 
	target_oid           default  :  E0E2     
	                     note     :  Input is a hexadecimal string.E.g. E0E2 
	couid                default  :  (null)   
	                     note     :  Unicast gets enabled if "couid" is provided otherwise it is broadcast.
				      :  Input is a hexadecimal string.E.g. A1DE34 
	sign_algo            default  :  ES_256   
	                     options  :  ES_256 , RSA-SSA-PKCS1-V1_5-SHA-256 
	priv_key             default  :  (null)   
	                     options  :  private key file (pem format) 
	                     note     :  Refer : samples/integrity/sample_ec_256_priv.pem 
	digest_algo          default  :  SHA256   
	                     options  :  SHA256   
	payload_type         default  :  data     
	                     options  :  data , key , metadata 

	(2) : To enable confidentiality,"secret" must be provided (All other options are ignored if there is no confidentiality)
	secret               default  :  (null)   
	                     options  :  Text file containing shared secret as hexadecimal string 
	                     note     :  Refer : samples/confidentiality/secret.txt 
	secret_oid           default  :  F1D0     
	                     note     :  Input is a hexadecimal string.E.g. F1D0 
	label                default  :  Confidentiality 
	                     note     :  Input is a string.E.g. Confidentiality 
	enc_algo             default  :  AES-CCM-16-64-128 
	                     options  :  AES-CCM-16-64-128 
	kdf                  default  :  IFX_KDF-TLS12_PRF_SHA256 
	                     options  :  IFX_KDF-TLS12_PRF_SHA256 
	seed_length          default  :  64       
	                     note     :  Input is a decimal string.E.g. 64 

	(3.1) : To update data object, "payload_type" should be "data" and provide the following details:
	offset               default  :  0        
	write_type           default  :  2        
	                     options  :  Write (1), EraseAndWrite (2) 
	data                 default  :  (null)   
	                     note     :  Input is a text file with hexadecimal or ascii string content 
	in_data_format       default  :  hex      
	                     options  :  hex , ascii 
	                     note     :  Refer : samples/payload/data/ascii_data.txt for input_data_format=ascii
				      :  Refer : samples/payload/data/hex_data.txt for input_data_format=hex 

	(3.2) : To update key object, "payload_type" should be "key" and provide the following details:
	key_usage            default  :  02       
	                     options  :  AUTH (0x01) , ENC (0x02) , SIGN (0x10) , KEY_AGREE (0x20) 
	                     note     :  Input is a hexadecimal string.E.g. E3
				      :  The values in "options" can be bitwise ORED and provided ( Refer SRM ) 
	key_algo             default  :           
	                     options  :  ECC-NIST-P-256 (3) , ECC-NIST-P-384 (4), ECC-NIST-P-521 (5), ECC-BRAINPOOL-P-256-R1 (19) , ECC-BRAINPOOL-P-384-R1 (21), ECC-BRAINPOOL-P-512-R1 (22), RSA-1024-Exp (65) , RSA-2048-Exp (66), AES-128 (129), AES-192 (129), AES-256 (131) 
	                     note     :  Input is a decimal string.E.g. 129 
	key_data             default  :  (null)   
	                     options  :  ECC / RSA key in .pem format or AES key in txt file as hexadecimal string 
	                     note     :  Refer : samples/payload/key/sample_ec_256_priv.pem for ECC or RSA key
				      :  Refer : samples/payload/key/aes_key.txt for AES key 

	(3.3) : To update metadata object, "payload_type" should be "metadata" and provide the following details:
	content_reset        default  :  0        
	                     options  :  As per metadata identifier flag (0), Zeroes (1), Random (2) 
	metadata             default  :  (null)   
	                     note     :  Input is a txt file as hexadecimal string 

	(4) : To write dataset to file, "dataset_to_file" should be the file path 
	dataset_to_file      default  :  (null)   
	                     options  :  Provide the filename for output dataset to be stored  
```

The sample command is shown as below as your reference:

In this sample command, the payload type is metadata and payload version is set to 3 after protected update. OID 0xE0E8 is used to store the trust anchor for integrity protected update, Signature Algorithm is ES_256 and Private key is stored as: ../samples/integrity/sample_ec_256_priv.pem. OID 0xF1D4 is used to store secret for confidentiality protected update. Target OID is set to 0xF1D6. After successful protected update, the meatadata of Target OID will been brought back to the mode stated inside metadata=../samples/payload/metadata/metadata.txt.

```console
foo@bar:~$ ./bin/trustm_protected_update_set payload_version=3 trust_anchor_oid=E0E8 target_oid=F1D6 sign_algo=ES_256 priv_key=../samples/integrity/sample_ec_256_priv.pem payload_type=metadata metadata=../samples/payload/metadata/metadata.txt content_reset=0 secret=../samples/confidentiality/secret.txt label="test" enc_algo="AES-CCM-16-64-128" secret_oid=F1D4
```

The output for this sample command is shown as below:

```console
foo@barTool Version : 3.00.2490
Info : Default values are set
Info : User provided inputs
	Payload version      : 3        
	Trust anchor oid     : E0E8     
	Target oid           : F1D6     
	Signature Algorithm  : ES_256   
	Private key          : ../samples/integrity/sample_ec_256_priv.pem 
	Type of Payload      : metadata 
	Shared secret        : ../samples/confidentiality/secret.txt 
	Shared secret OID    : F1D4     
	Label                : test     
	Encryption algorithm : AES-CCM-16-64-128 
	Content Reset        : 0        
	Meta Data            : ../samples/payload/metadata/metadata.txt 

Info : Setting value for data formatter
	Payload version      : 3        
	Trust anchor oid     : E0E8     
	Target oid           : F1D6     
	Digest algorithm     : 29       
	Signature Algorithm  : FFFFFFF9 
	Type of Payload      : FFFFFFFE 
	Length of seed       : 40       
	Label                : test     
	Shared secret OID    : F1D4     
0x49, 0xC9, 0xF4, 0x92, 0xA9, 0x92, 0xF6, 0xD4, 0xC5, 0x4F, 0x5B, 0x12, 0xC5, 0x7E, 0xDB, 0x27, 
	0xCE, 0xD2, 0x24, 0x04, 0x8F, 0x25, 0x48, 0x2A, 0xA1, 0x49, 0xC9, 0xF4, 0x92, 0xA9, 0x92, 0xF6, 
	0x49, 0xC9, 0xF4, 0x92, 0xA9, 0x92, 0xF6, 0xD4, 0xC5, 0x4F, 0x5B, 0x12, 0xC5, 0x7E, 0xDB, 0x27, 
	0xCE, 0xD2, 0x24, 0x04, 0x8F, 0x25, 0x48, 0x2A, 0xA1, 0x49, 0xC9, 0xF4, 0x92, 0xA9, 0x92, 0xF6, 
	Encryption algorithm : A        
	Key Derivation Function : FFFEFF48 
	Content Reset        : 0        
Manifest Data , size : [233]
	uint8_t manifest_data[] = 
	{
	0x84, 0x43, 0xA1, 0x01, 0x26, 0xA1, 0x04, 0x42, 0xE0, 0xE8, 0x58, 0x9B, 0x86, 0x01, 0xF6, 0xF6, 
	0x84, 0x21, 0x0D, 0x03, 0x82, 0x00, 0x00, 0x82, 0x82, 0x20, 0x58, 0x25, 0x82, 0x18, 0x29, 0x58, 
	0x20, 0xBB, 0x41, 0x83, 0x77, 0xCF, 0xAE, 0x6A, 0x08, 0xB7, 0x88, 0xDC, 0x67, 0xC5, 0xFC, 0x66, 
	0x2A, 0x02, 0x0D, 0x20, 0x2E, 0x11, 0x2D, 0xB4, 0xCF, 0x54, 0x2D, 0x1A, 0x96, 0x0A, 0x6E, 0xDC, 
	0x1F, 0x82, 0x01, 0x83, 0x43, 0xA1, 0x01, 0x0A, 0x81, 0x82, 0x58, 0x54, 0xA3, 0x04, 0x42, 0xF1, 
	0xD4, 0x01, 0x3A, 0x00, 0x01, 0x00, 0xB7, 0x05, 0x82, 0x44, 0x74, 0x65, 0x73, 0x74, 0x58, 0x40, 
	0x4E, 0xB6, 0xAB, 0xD0, 0xCE, 0xB1, 0xDC, 0xA6, 0xD0, 0xCC, 0x16, 0x29, 0xC2, 0xD9, 0x6C, 0x5F, 
	0x9B, 0x5E, 0xB9, 0xB3, 0xA3, 0x19, 0xDA, 0x9E, 0x50, 0x82, 0x4D, 0x07, 0xC3, 0xA7, 0xA4, 0x70, 
	0xDC, 0x80, 0x44, 0xAD, 0x6F, 0x1B, 0xDC, 0xB4, 0x2B, 0x37, 0x5A, 0xE2, 0x32, 0x7E, 0xEA, 0xB7, 
	0xE3, 0xA4, 0x34, 0x6B, 0x74, 0xB6, 0x3E, 0x02, 0xAA, 0x3C, 0x9A, 0x08, 0xF6, 0xC0, 0x66, 0x88, 
	0xF6, 0xF6, 0x82, 0x40, 0x42, 0xF1, 0xD6, 0x58, 0x40, 0xE9, 0x69, 0xF7, 0x9E, 0x57, 0x57, 0xDB, 
	0xCF, 0xAE, 0x87, 0xD1, 0x58, 0x6E, 0x4A, 0x75, 0x1B, 0x28, 0x87, 0x9E, 0x93, 0xAE, 0x00, 0x9A, 
	0x00, 0xD0, 0xBD, 0xCA, 0x36, 0x41, 0x6C, 0xFC, 0x47, 0x45, 0x41, 0x0B, 0xCA, 0x2C, 0x9B, 0x3C, 
	0x5A, 0x87, 0x23, 0xB9, 0xF0, 0xF0, 0xEC, 0x7D, 0x16, 0xCB, 0x95, 0xE9, 0xDF, 0xA4, 0x2D, 0xF4, 
	0x99, 0x99, 0xD7, 0x36, 0x65, 0x56, 0xB4, 0x68, 0x67, 
	};

Fragment number:[01], size:[021]
	uint8_t fragment_01[] = 
	{
	0x74, 0xD1, 0x99, 0x5C, 0x6F, 0xC9, 0xE7, 0x02, 0xCB, 0xA8, 0x99, 0xC1, 0x55, 0xE6, 0xA6, 0x3A, 
	0x1E, 0x7B, 0x14, 0x22, 0x03, 
    };
```

 Enviorment:

   mbedTLS 2.16.0 is used for crypto operation in this tool.
	1. The following MACRO must be disabled/ enabled when using mbedTLS for this tool.
		i. Enable :
			MBEDTLS_FS_IO
			MBEDTLS_PEM_PARSE_C
			MBEDTLS_BASE64_C
			MBEDTLS_ECDSA_DETERMINISTIC
			MBEDTLS_HMAC_DRBG_C
			MBEDTLS_ECDSA_DETERMINISTIC_DEBUG
			MBEDTLS_RSA_C
			MBEDTLS_PKCS1_V15
			MBEDTLS_PK_RSA_ALT_SUPPORT
			MBEDTLS_TIMING_C
			MBEDTLS_ENTROPY_C
			MBEDTLS_CTR_DRBG_C
			MBEDTLS_ECP_DP_SECP256R1_ENABLED
			MBEDTLS_ECP_DP_SECP384R1_ENABLED
			MBEDTLS_ECP_DP_SECP521R1_ENABLED
			MBEDTLS_ECP_DP_BP256R1_ENABLED
			MBEDTLS_ECP_DP_BP384R1_ENABLED
			MBEDTLS_ECP_DP_BP512R1_ENABLED

Limitations

1. Only SHA-256 digest algorithm is supported for hash calculation
2. Manifest version number is 1	
