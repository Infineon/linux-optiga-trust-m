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

BIO	*reqbio = NULL;
BIO	*outbio = NULL;

#define MAX_OID_PUB_CERT_SIZE	1728

typedef struct _OPTFLAG {
	uint16_t	sign		: 1;
	uint16_t	input		: 1;
	uint16_t	output		: 1;
	uint16_t	hash		: 1;
	uint16_t	dummy4		: 1;
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
	printf("\nHelp menu: trustm_ecc_sign <option> ...<option>\n");
	printf("option:- \n");
	printf("-k <OID Key>  : Select ECC key for signing OID (0xE0F0-0xE0F3) \n");
	printf("-o <filename> : Output to file \n");
	printf("-i <filename> : Input Data file\n");
	printf("-H            : Hash before sign\n");
	printf("-h            : Print this help \n");
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

	optiga_key_id_t optiga_key_id;
	optiga_hash_context_t hash_context;
	hash_data_from_host_t hash_data_host;
	uint8_t hash_context_buffer[2048];
	
	uint8_t signature [100];     //To store the signture generated
    uint16_t signature_length = sizeof(signature);
    uint8_t digest[32];
    uint16_t digestLen = 0;
    uint8_t data[2048];
    uint16_t dataLen = 0;

    char *outFile = NULL;
    char *inFile = NULL;
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
        while (-1 != (option = getopt(argc, argv, "k:o:i:Hh")))
        {
			switch (option)
            {
				case 'k': // OID Key
					uOptFlag.flags.sign = 1;
					optiga_key_id = _ParseHexorDec(optarg);			 	
					break;
				case 'o': // Output
					uOptFlag.flags.output = 1;
					outFile = optarg;			 	
					break;
				case 'i': // Input
					uOptFlag.flags.input = 1;
					inFile = optarg;			 	
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
		if(uOptFlag.flags.sign == 1)
		{
			if(uOptFlag.flags.output != 1)
			{
				printf("Output filename missing!!!\n");
				break;
			}

			if(uOptFlag.flags.input != 1)
			{
				printf("Input filename missing!!!\n");
				break;
			}

			printf("OID Key 0x%.4X\n",optiga_key_id);
			printf("Output File Name : %s \n", outFile);
			printf("Input File Name : %s \n", inFile);

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
					printf("Hash Success : SHA256\n");
					_hexdump(digest,digestLen);
				}

				printf("filesize: %d\n",filesize);
				
			} else
			{
				digestLen = _readFrom(digest, (uint8_t *) inFile);
				if (digestLen == 0)
				{
					printf("Error reading file!!!\n");
					break;				
				}
				if (digestLen > sizeof(digest))
				{
					printf("Error : File too big try using option -H \n");	
					break;				
				} else
				{
					printf("Input data[%d] : \n", digestLen);
					_hexdump(digest,digestLen);
				}					
			}

			optiga_lib_status = OPTIGA_LIB_BUSY;
			return_status = optiga_crypt_ecdsa_sign(me_crypt,
													digest,
													digestLen,
													optiga_key_id,
													signature,
													&signature_length);

			if (OPTIGA_LIB_SUCCESS != return_status)
			{
				break;
			}

			while (OPTIGA_LIB_BUSY == optiga_lib_status)
			{
				//Wait until the optiga_crypt_ecdsa_sign operation is completed
			}

			if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
			{
				return_status = optiga_lib_status;
				printf("optiga_lib_status Error!!! [0x%.8X]\n",return_status);				
				break;
			}
			
			if (return_status != OPTIGA_LIB_SUCCESS)
			{
				printf("return_status Error!!! [0x%.8X]\n",return_status);
			}
			else
			{
				_writeTo(signature, signature_length, outFile);
				printf("Success\n");
			}
		}

	}while(FALSE);
	printf("========================================================\n");	
	
	trustm_Close();

	return 0;
}
