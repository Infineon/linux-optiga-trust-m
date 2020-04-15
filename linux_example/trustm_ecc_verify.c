/**
* MIT License
*
* Copyright (c) 2020 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

typedef struct _OPTFLAG {
	uint16_t	verify		: 1;
	uint16_t	input		: 1;
	uint16_t	signature	: 1;
	uint16_t	hash		: 1;
	uint16_t	pubkey		: 1;
	uint16_t	dummy5		: 1;
	uint16_t	dummy6		: 1;
	uint16_t	dummy7		: 1;
	uint16_t	dummy8		: 1;
	uint16_t	dummy9		: 1;
	uint16_t	dummy10		: 1;
	uint16_t	dummy11		: 1;
	uint16_t	dummy12		: 1;
	uint16_t	dummy13		: 1;
	uint16_t	dummy14		: 1;
	uint16_t	dummy15		: 1;
}OPTFLAG;

union _uOptFlag {
	OPTFLAG	flags;
	uint16_t	all;
} uOptFlag;

void _helpmenu(void)
{
	printf("\nHelp menu: trustm_ecc_verify <option> ...<option>\n");
	printf("option:- \n");
	printf("-k <OID Key>   : Use Certificate from OID [0xE0E1-E0E3]\n");
	printf("-p <pubkey>    : Use Pubkey file\n");
	printf("-i <filename>  : Input Data file\n");
	printf("-s <signature> : Signature file\n");
	printf("-H             : Hash input before verify\n");
	printf("-h             : Print this help \n");
}

static uint32_t _ParseHexorDec(const char *aArg)
{
	uint32_t value;

	if ((strncmp(aArg, "0x",2) == 0) ||(strncmp(aArg, "0X",2) == 0))
		sscanf(aArg,"%x",&value);
	else
		sscanf(aArg,"%d",&value);

	return value;
}

void _hexdump(uint8_t *data, uint16_t len)
{
	uint16_t j,k;

	printf("\t");
	k=0;
	for (j=0;j<len;j++)
	{
		printf("%.2X ", data[j]);
		if(k < 15)
		{
			k++;
		}	
		else
		{
			printf("\n\t");
			k=0;
		}
	}
	printf("\n");
}

uint16_t _writeTo(uint8_t *buf, uint32_t len, const char *filename)
{
	FILE *datafile;

	//create 
	datafile = fopen(filename,"wb");
	if (!datafile)
	{
		return 1;
	}

	//Write to file
	fwrite(buf, 1, len, datafile);
	fclose(datafile);

	return 0;

}

static uint16_t _readFrom(uint8_t *data, uint8_t *filename)
{
	
	FILE *datafile;
	uint16_t len;
	uint8_t buf[2048];
	uint16_t ret;

	//open 
	datafile = fopen((const char *)filename,"rb");
	if (!datafile)
	{
		return 0;
	}

	//Read file
	len = fread(buf, 1, sizeof(buf), datafile); 
	if (len > 0)
	{
		ret = len;
		memcpy(data,buf,len);
	}

	fclose(datafile);

	return ret;

}



int main (int argc, char **argv)
{
	optiga_lib_status_t return_status;
	optiga_hash_context_t hash_context;
	hash_data_from_host_t hash_data_host;
	uint8_t hash_context_buffer[2048];
	
	uint16_t optiga_oid;
	uint8_t signature [100];     //To store the signture generated
    uint16_t signatureLen = sizeof(signature);
    uint8_t digest[32];
    uint16_t digestLen = 0;
    uint8_t pubkey[2048];
    uint32_t pubkeyLen;
    uint8_t data[2048];
    uint16_t dataLen = 0;

    char *inFile = NULL;
    char *signatureFile = NULL;
    char *pubkeyFile = NULL;
    char name[100];
    FILE *fp = NULL;
	uint16_t filesize;
	
	int option = 0;                    // Command line option.


/***************************************************************
 * Getting Input from CLI
 **************************************************************/
	uOptFlag.all = 0;
    printf("\n");
    do // Begin of DO WHILE(FALSE) for error handling.
    {
		// ---------- Check for command line parameters ----------
		
        if (argc < 2)
        {
			_helpmenu();
			exit(0);
		}

        // ---------- Command line parsing with getopt ----------
        opterr = 0; // Disable getopt error messages in case of unknown parameters

        // Loop through parameters with getopt.
        while (-1 != (option = getopt(argc, argv, "k:i:s:p:Hh")))
        {
			switch (option)
            {
				case 'k': // Cert OID 
					uOptFlag.flags.verify = 1;
					optiga_oid = _ParseHexorDec(optarg);			 	
					break;
				case 'i': // Input
					uOptFlag.flags.input = 1;
					inFile = optarg;			 	
					break;
				case 's': // Signature
					uOptFlag.flags.signature = 1;
					signatureFile = optarg;			 	
					break;
				case 'p': // Host Pubkey
					uOptFlag.flags.pubkey = 1;
					pubkeyFile = optarg;			 	
					break;
				case 'H': // Input
					uOptFlag.flags.hash = 1;		 	
					break;
				case 'h': // Print Help Menu
				default:  // Any other command Print Help Menu
					_helpmenu();
					exit(0);
					break;
			}
		}
    } while (0); // End of DO WHILE FALSE loop.
 

/***************************************************************
 * Example 
 **************************************************************/
	return_status = trustm_Open();
	if (return_status != OPTIGA_LIB_SUCCESS)
		exit(1);
		
	printf("========================================================\n");	

	do
	{
		if(uOptFlag.flags.input != 1)
		{
			printf("Input filename missing!!!\n");
			break;
		}

		if(uOptFlag.flags.signature != 1)
		{
			printf("Signature filename missing!!!\n");
			break;
		}

		signatureLen = _readFrom(signature, (uint8_t *) signatureFile);
		if (signatureLen == 0)
		{
			printf("Error signature reading file!!!\n");
			break;				
		}	
		
		if(uOptFlag.flags.hash == 1)
		{
			//open 
			fp = fopen((const char *)inFile,"rb");
			if (!fp)
			{
				printf("error opening file : %s\n",inFile);
				exit(1);
			}
			
			hash_context.context_buffer = hash_context_buffer;
			hash_context.context_buffer_length = sizeof(hash_context_buffer);
			hash_context.hash_algo = (uint8_t)OPTIGA_HASH_TYPE_SHA_256;  			
			filesize = 0;
			
			optiga_lib_status = OPTIGA_LIB_BUSY;
			return_status = optiga_crypt_hash_start(me_crypt, &hash_context);
			if (OPTIGA_LIB_SUCCESS != return_status)
			{
				break;
			}

			while (OPTIGA_LIB_BUSY == optiga_lib_status)
			{
				//Wait until the optiga_crypt_hash_start operation is completed
			}

			if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
			{
				return_status = optiga_lib_status;
				printf("hash start : optiga_lib_status Error!!! [0x%.8X]\n",return_status);
				break;
			}
				
			while((dataLen = fread(data,1,sizeof(data),fp)) > 0)
			{
				hash_data_host.buffer = data;
				hash_data_host.length = dataLen;

				optiga_lib_status = OPTIGA_LIB_BUSY;
				return_status = optiga_crypt_hash_update(me_crypt,
														 &hash_context,
														 OPTIGA_CRYPT_HOST_DATA,
														 &hash_data_host);
				if (OPTIGA_LIB_SUCCESS != return_status)
				{
					break;
				}

				while (OPTIGA_LIB_BUSY == optiga_lib_status)
				{
					//Wait until the optiga_crypt_hash_update operation is completed
				}

				if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
				{
					return_status = optiga_lib_status;
					printf("hash update : optiga_lib_status Error!!! [0x%.8X]\n",return_status);
					break;
				}
				filesize += dataLen;
			}
			
			optiga_lib_status = OPTIGA_LIB_BUSY;
			return_status = optiga_crypt_hash_finalize(me_crypt,
													   &hash_context,
													   digest);

			if (OPTIGA_LIB_SUCCESS != return_status)
			{
				break;
			}

			while (OPTIGA_LIB_BUSY == optiga_lib_status)
			{
				//Wait until the optiga_crypt_hash_finalize operation is completed
			}

			if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
			{
				return_status = optiga_lib_status;
				printf("hash finalize : optiga_lib_status Error!!! [0x%.8X]\n",return_status);
				break;
			}

			if (return_status != OPTIGA_LIB_SUCCESS)
			{
				printf("hash finalize : return_status Error!!! [0x%.8X]\n",return_status);
			}
			else
			{
				digestLen = sizeof(digest);
				//printf("Hash Success : SHA256\n");
				//_hexdump(digest,digestLen);
			}

			//printf("filesize: %d\n",filesize);
			
		} else	
		{
			digestLen = _readFrom(digest, (uint8_t *) inFile);
			if (digestLen == 0)
			{
				printf("Error reading input file!!!\n");
				break;				
			}
		}	
				
		if(uOptFlag.flags.verify == 1)
		{
			printf("OID Cert            : 0x%.4X\n",optiga_oid);
			printf("Input File Name     : %s \n", inFile);
			printf("Signature File Name : %s \n", signatureFile);
			
			if(uOptFlag.flags.hash == 1)
				printf("Hash Digest : \n");
			else
				printf("Input data : \n");
			_hexdump(digest,digestLen);
			
			printf("Signature : \n");
			_hexdump(signature,signatureLen);					

			optiga_lib_status = OPTIGA_LIB_BUSY;
			return_status = optiga_crypt_ecdsa_verify (me_crypt,
													   digest,
													   digestLen,
													   signature,
													   signatureLen,
													   OPTIGA_CRYPT_OID_DATA,
													   &optiga_oid);

			if (OPTIGA_LIB_SUCCESS != return_status)
			{
				break;
			}

			while (OPTIGA_LIB_BUSY == optiga_lib_status)
			{
				//Wait until the optiga_crypt_ecdsa_verify operation is completed
			}

			if ((OPTIGA_LIB_SUCCESS != optiga_lib_status))
			{
				//Signature verification failed.
				return_status = optiga_lib_status;
				//printf("optiga_lib_status Error!!! [0x%.8X]\n",return_status);				
				//break;
			}

			if (return_status != OPTIGA_LIB_SUCCESS)
			{
				printf("return_status Error!!! [0x%.8X]\n",return_status);
			}
			else
			{
				printf("Verify Success.\n");
			}
			printf("\n");
		}

		if(uOptFlag.flags.pubkey == 1)
		{
			printf("Pubkey file         : %s\n",pubkeyFile);
			printf("Input File Name     : %s \n", inFile);
			printf("Signature File Name : %s \n", signatureFile);

            trustmReadPEM(pubkey, &pubkeyLen, pubkeyFile, name);
			if (pubkeyLen == 0)
			{
		        printf("Invalid Pubkey file \n");
				break;
			}				
			else if (strcmp(name, "PUBLIC KEY"))
            {
				printf("Invalid Public Key File!!!\n");
				break;
			}
						
			if(uOptFlag.flags.hash == 1)
				printf("Hash Digest : \n");
			else
				printf("Input data : \n");
			_hexdump(digest,digestLen);	

			printf("Signature : \n");
			_hexdump(signature,signatureLen);	

			printf("Pub key : \n");
			_hexdump((pubkey+23),pubkeyLen-23);	

			public_key_from_host_t public_key_details = {
														 pubkey+23,
														 pubkeyLen-23,
														 OPTIGA_ECC_CURVE_NIST_P_256
														};

			optiga_lib_status = OPTIGA_LIB_BUSY;
			return_status = optiga_crypt_ecdsa_verify (me_crypt,
													   digest,
													   digestLen,
													   signature,
													   signatureLen,
													   OPTIGA_CRYPT_HOST_DATA,
													   &public_key_details);

			if (OPTIGA_LIB_SUCCESS != return_status)
			{
				break;
			}

			while (OPTIGA_LIB_BUSY == optiga_lib_status)
			{
				//Wait until the optiga_crypt_ecdsa_verify operation is completed
			}

			if ((OPTIGA_LIB_SUCCESS != optiga_lib_status))
			{
				//Signature verification failed.
				return_status = optiga_lib_status;
				//printf("optiga_lib_status Error!!! [0x%.8X]\n",return_status);				
				//break;
			}

			if (return_status != OPTIGA_LIB_SUCCESS)
			{
				printf("return_status Error!!! [0x%.8X]\n",return_status);
			}
			else
			{
				printf("Verify Success.\n");
			}
		}
	}while(FALSE);
	printf("========================================================\n");	
	
	trustm_Close();

	return 0;
}
