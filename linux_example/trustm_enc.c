/**
* MIT License
*
* Copyright (c) 2018 Infineon Technologies AG
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
#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/optiga_util.h"

#include "trustm_helper.h"

BIO	*reqbio = NULL;
BIO	*outbio = NULL;

#define MAX_OID_PUB_CERT_SIZE	1728

typedef struct _OPTFLAG {
	uint16_t	enc			: 1;
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
	printf("\nHelp menu: trustm_enc <option> ...<option>\n");
	printf("option:- \n");
	printf("-k <OID Key>  : Select key for encrypt OID 0xNNNN \n");
	printf("-o <filename> : Output to file \n");
	printf("-i <filename> : Input Data file\n");
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
		return 1;
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
	uint8_t message[256];     //To store the signture generated
    uint16_t messagelen = sizeof(message);
    uint8_t encyptdata[256];
    uint16_t encyptdatalen;

    char *outFile = NULL;
    char *inFile = NULL;
    
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
        while (-1 != (option = getopt(argc, argv, "k:o:i:h")))
        {
			switch (option)
            {
				case 'k': // OID Key
					uOptFlag.flags.enc = 1;
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
		if(uOptFlag.flags.enc == 1)
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

			messagelen = _readFrom(message, (uint8_t *) inFile);
			if (messagelen == 0)
			{
				printf("Error reading file!!!\n");
				break;				
			}
			
			printf("Input data : \n");
			_hexdump(message,messagelen);	

				optiga_lib_status = OPTIGA_LIB_BUSY;
				
/*
				return_status = optiga_util_read_data(me_util,
													optiga_oid,
													offset,
													read_data_buffer,
													(uint16_t *)&bytes_to_read);

 
				if (OPTIGA_LIB_SUCCESS != return_status)
				{
					printf("Error!!! [0x%.8X]\n",return_status);
				}

				while (OPTIGA_LIB_BUSY == optiga_lib_status) 
				{
					//Wait until the optiga_util_read_metadata operation is completed
				}

				if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
				{
					//Reading metadata data object failed.
					//printf("\nError!!! [0x%.8X]\n",optiga_lib_status);
					//break;					
					return_status = optiga_lib_status;
				}				
*/
		} // End of for loop
	}while(FALSE);

	printf("===========================================\n");	
	trustm_Close();

	return 0;
}
