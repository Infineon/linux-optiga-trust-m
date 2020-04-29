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
#include <openssl/asn1.h>

#define MAX_OID_PUB_CERT_SIZE	1728

typedef struct _OPTFLAG {
	uint16_t	read		: 1;
	uint16_t	type		: 1;
	uint16_t	output		: 1;
	uint16_t	keysize		: 1;
	uint16_t	savepubkey	: 1;
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


void helpmenu(void)
{
	printf("\nHelp menu: trustm_rsa_keygen <option> ...<option>\n");
	printf("option:- \n");
	printf("-g <Key OID>    : Generate RSA Key in OID [0xE0FC-0xE0FD] \n");
	printf("-t <key type>  	: Key type Auth:0x01 Enc :0x02 HFWU:0x04\n");
	printf("                           DevM:0X08 Sign:0x10 Agmt:0x20\n");
	printf("                           [default Auth]\n");  
	printf("-k <key size>   : Key size RSA1024:0x41 RSA2048:0x42 [default RSA1024]\n");
	printf("-o <filename>  	: Output Pubkey to file in PEM format\n");
	printf("-s              : Save Pubkey with header in <Key OID + 0x10E4>\n");
	printf("-h              : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;
    optiga_key_id_t optiga_key_id;
    
    uint8_t rsaheader2048[] = {0x30,0x82,0x01,0x22,
				0x30,0x0d,
				0x06,0x09,
				0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00};

    uint8_t rsaheader1024[] = {0x30,0x81,0x9F,
				0x30,0x0D,
				0x06,0x09,
				0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00};

    uint8_t pubKey[300];
    uint16_t i;
						
    uint16_t pubKeyLen = sizeof(pubKey)+1000;
    uint8_t keyType=0x01;// default Auth
    uint8_t keySize=0x41;// default 1024
    char *outFile = NULL;

	int option = 0;                    // Command line option.

	uOptFlag.all = 0;

    printf("\n");
    do // Begin of DO WHILE(FALSE) for error handling.
    {
		// ---------- Check for command line parameters ----------
        if (argc < 2)
        {
			helpmenu();
			exit(0);
		}

        // ---------- Command line parsing with getopt ----------
        opterr = 0; // Disable getopt error messages in case of unknown parameters

        // Loop through parameters with getopt.
        while (-1 != (option = getopt(argc, argv, "g:t:k:o:sh")))
        {
			switch (option)
            {
				case 'g': // Generate Key ECC key E0F1-E0F3
					uOptFlag.flags.read = 1;
					optiga_key_id = trustmHexorDec(optarg);
					if((optiga_key_id < 0xE0FC) || (optiga_key_id > 0xE0FD))
					{
						printf("Invalid RSA key OID!!!\n");
						exit(0); 
					}
					break;
				case 't': // Key Type
					uOptFlag.flags.type = 1;	
					keyType = trustmHexorDec(optarg);
					if ((keyType == 0x00) || (keyType & 0xc0))
					{
						printf("Key Type Error!!!\n");
						exit(0);
					}
					break;
				case 'k': // Key Size
					uOptFlag.flags.type = 1;	
					keySize = trustmHexorDec(optarg);
					if ((keySize != 0x41) && (keySize != 0x42))
					{
						printf("Key Size Error!!!\n");
						exit(0);
					}
					break;
				case 'o': // Output
					uOptFlag.flags.output = 1;
					outFile = optarg;			 	
					break;
				case 's': // Save pubkey
					uOptFlag.flags.savepubkey = 1;
					break;				
				case 'h': // Print Help Menu
				default:  // Any other command Print Help Menu
					helpmenu();
					exit(0);
					break;
			}
		}
    } while (0); // End of DO WHILE FALSE loop.
 
	return_status = trustm_Open();
	if (return_status != OPTIGA_LIB_SUCCESS)
		exit(1);
		
    printf("========================================================\n");    	

	do
	{
		if(uOptFlag.flags.read == 1)
		{
			if(uOptFlag.flags.output != 1)
			{
				printf("Output filename missing!!!\n");
				break;
			}
		
			if(keySize == 0x42)
			{
				for (i=0; i < sizeof(rsaheader2048);i++)
				{
					pubKey[i] = rsaheader2048[i];
				}
			}
			else
			{
				for (i=0; i < sizeof(rsaheader1024);i++)
				{
					pubKey[i] = rsaheader1024[i];
				}
			}

			printf("Generating Key to 0x%.4X\n",optiga_key_id);
			printf("Output File Name : %s \n", outFile);
			
			optiga_lib_status = OPTIGA_LIB_BUSY;
			return_status = optiga_crypt_rsa_generate_keypair(me_crypt,
										keySize,
										keyType,
										FALSE,
										&optiga_key_id,
										(pubKey+i),
										&pubKeyLen);	
			if (OPTIGA_LIB_SUCCESS != return_status)
				break;			
			//Wait until the optiga_util_read_metadata operation is completed
			while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
			return_status = optiga_lib_status;
			if (return_status != OPTIGA_LIB_SUCCESS)
				break;
			else
			{
				printf("Pubkey :\n");
				trustmHexDump(pubKey, (uint32_t) pubKeyLen+i);

				return_status = trustmWritePEM(pubKey, pubKeyLen+i, 
								outFile,"PUBLIC KEY");
				if (return_status != OPTIGA_LIB_SUCCESS)
				{
					printf("Error when saving file!!!\n");
				}
			}
		}
		
		if(uOptFlag.flags.savepubkey == 1)
		{
		    optiga_lib_status = OPTIGA_LIB_BUSY;
		    return_status = optiga_util_write_data(me_util,
							    (optiga_key_id+0x10E4),
							    OPTIGA_UTIL_ERASE_AND_WRITE,
							    0,
							    (pubKey+i), 
							    pubKeyLen);
			if (OPTIGA_LIB_SUCCESS != return_status)
				break;			
			//Wait until the optiga_util_read_metadata operation is completed
			while (OPTIGA_LIB_BUSY == optiga_lib_status) {}
			return_status = optiga_lib_status;
			if (return_status != OPTIGA_LIB_SUCCESS)
				break;
			else
				printf("Write Success to OID: 0x%.4X.\n",(optiga_key_id+0x10E4));
		}
		
	}while(FALSE);
    
    // Capture OPTIGA Trust M error
	if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);
        
    printf("========================================================\n"); 
    	
	trustm_Close();
	return 0;
}
