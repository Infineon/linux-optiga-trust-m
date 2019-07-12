/**
* MIT License
*
* Copyright (c) 2019 Infineon Technologies AG
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

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

#define MAX_OID_PUB_CERT_SIZE	1728

typedef struct _OPTFLAG {
	uint16_t	read		: 1;
	uint16_t	write		: 1;
	uint16_t	output		: 1;
	uint16_t	format		: 1;
	uint16_t	clear		: 1;
	uint16_t	input		: 1;
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
	printf("\nHelp menu: trustm_cert <option> ...<option>\n");
	printf("option:- \n");
	printf("-r <Cert OID>  	: Read Certificate from OID 0xNNNN \n");
	printf("-w <Cert OID>  	: Write Certificte to OID\n");
	printf("-o <filename>  	: Output certificate to file \n");
	printf("-i <filename>  	: Input certificate to file \n");
	printf("-c <Cert OID>   : Clear cert OID data to zero \n");
	printf("-h              : Print this help \n");
}

static uint32_t _ParseHexorDec(const char *aArg)
{
	uint32_t value;

	if (strncmp(aArg, "0x",2) == 0)
		sscanf(aArg,"%x",&value);
	else
		sscanf(aArg,"%d",&value);

	return value;
}

int main (int argc, char **argv)
{
	optiga_lib_status_t return_status;
	uint16_t offset, bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[2048];
    uint8_t *pCert;
    uint16_t certLen;
    uint16_t ret;
    char *outFile = NULL;
    char *inFile = NULL;
    
    X509 *x509Cert;

	pCert = NULL;
	certLen = 0;

	int option = 0;                    // Command line option.

	uOptFlag.all = 0;

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
        while (-1 != (option = getopt(argc, argv, "r:w:o:i:f:c:h")))
        {
			switch (option)
            {
				case 'r': // Read Cert
					uOptFlag.flags.read = 1;
					optiga_oid = _ParseHexorDec(optarg);			 	
					break;
				case 'w': // Write Cert
					uOptFlag.flags.write = 1;	
					optiga_oid = _ParseHexorDec(optarg);								 	
					break;
				case 'o': // Output
					uOptFlag.flags.output = 1;
					outFile = optarg;			 	
					break;
				case 'i': // Input
					uOptFlag.flags.input = 1;
					inFile = optarg;			 	
					break;
				case 'f': // File format
					uOptFlag.flags.format = 1;
								 	
					break;
				case 'c': // Clean OID Cert
					uOptFlag.flags.clear = 1;	
					optiga_oid = _ParseHexorDec(optarg);							 	
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
		
	printf("===========================================\n");	

	do
	{
		if(uOptFlag.flags.read == 1)
		{
			if(uOptFlag.flags.output != 1)
			{
				printf("Output filename missing!!!\n");
				break;
			}

			printf("Reading OID 0x%.4X\n",optiga_oid);
			printf("Output File Name : %s \n", outFile);
			offset = 0x00;
			bytes_to_read = sizeof(read_data_buffer);

			optiga_lib_status = OPTIGA_LIB_BUSY;
			return_status = optiga_util_read_data(me_util,
												optiga_oid,
												offset,
												read_data_buffer,
												(uint16_t *)&bytes_to_read);
			if (OPTIGA_LIB_SUCCESS != return_status)
			{
				printf("Error!!! [0x%.8X]\n",return_status);
				break;
			}

			while (OPTIGA_LIB_BUSY == optiga_lib_status) 
			{
				//Wait until the optiga_util_read_metadata operation is completed
			}
/*			
			return_status = optiga_util_read_data(optiga_oid,
												offset,
												read_data_buffer,
												&bytes_to_read);
*/
			if (return_status != OPTIGA_LIB_SUCCESS)
			{
				printf("Error!!! [0x%.8X]\n",return_status);
				break;
			}

			else
			{
				switch (read_data_buffer[0])
				{
				case 0x30: // DER format Cert
					pCert = read_data_buffer;
					certLen = bytes_to_read;
					break;
				case 0xC0: // TLS Indentity
					pCert = read_data_buffer + 9;
					certLen = bytes_to_read - 9;
					break;
				case 0xC2: // USB Type-C identity
				default:
					pCert = NULL;
					certLen = 0;
					break;
				}
				
				if (pCert != NULL)
				{
					x509Cert = d2i_X509(NULL, (const uint8_t **)&pCert, certLen);
					if(!x509Cert)
					{
						printf("Unable to parse cert in OID Ox%.4X\n",optiga_oid);
						
					}
					else
					{
						ret = trustmWriteX509PEM(x509Cert, outFile);
						if (ret != 0)
							printf("Write file error!!!!\n");
						else	
							printf("Success!!!\n");
					}
				}
				else
				{
					printf("Error :No X.509 cert found!!!!\n");
				}
			}	
		}

		if(uOptFlag.flags.write == 1)
		{
			if(uOptFlag.flags.input != 1)
			{
				printf("input filename missing !!!!\n");
				break;
			}
			
			ret = trustmReadX509PEM(&x509Cert, inFile);
			if (ret == 0)
			{
				certLen = i2d_X509(x509Cert, &pCert);
				if(certLen != 0)
				{
					optiga_lib_status = OPTIGA_LIB_BUSY;
					return_status = optiga_util_write_data(me_util,
															optiga_oid,
															OPTIGA_UTIL_ERASE_AND_WRITE,
															offset,
															pCert, 
															certLen);
					if (OPTIGA_LIB_SUCCESS != return_status)
					{
						printf("Error!!! [0x%.8X]\n",return_status);
						break;
					}

					while (OPTIGA_LIB_BUSY == optiga_lib_status) 
					{
						//Wait until the optiga_util_read_metadata operation is completed
					}					

/*
					return_status = optiga_util_write_data(optiga_oid,
										   OPTIGA_UTIL_ERASE_AND_WRITE,
										   offset,
										   pCert, 
										   certLen);
*/
					if (return_status != OPTIGA_LIB_SUCCESS)
					{
						printf("Error!!! [0x%.8X]\n",return_status);
					}
					else
						printf("Success!!!\n");
				}
				else
				{
					printf("invalid cert %s error!!!\n",inFile);
				}	
			}
			else
			{
				printf("Read Cert %s Error!!!\n",inFile);
			}
		}

		if(uOptFlag.flags.clear == 1)
		{
			bytes_to_read = 0x01; 
			read_data_buffer[0] = 0;
			offset = 0;

			optiga_lib_status = OPTIGA_LIB_BUSY;
			return_status = optiga_util_write_data(me_util,
													optiga_oid,
													OPTIGA_UTIL_ERASE_AND_WRITE,
													offset,
													read_data_buffer, 
													bytes_to_read);
			if (OPTIGA_LIB_SUCCESS != return_status)
			{
				printf("Error!!! [0x%.8X]\n",return_status);
				break;
			}

			while (OPTIGA_LIB_BUSY == optiga_lib_status) 
			{
				//Wait until the optiga_util_read_metadata operation is completed
			}
/*			
			return_status = optiga_util_write_data(optiga_oid,
												   OPTIGA_UTIL_ERASE_AND_WRITE,
												   offset,
												   read_data_buffer, 
												   bytes_to_read);
*/
			if (return_status != OPTIGA_LIB_SUCCESS)
			{
				printf("Error!!! [0x%.8X]\n",return_status);
			}
			else
			{
				printf("Cleared.\n");
			}
		}
	}while(0);
	
	trustm_Close();
	return 0;
}
