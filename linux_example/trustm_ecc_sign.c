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

#define MAX_OID_PUB_CERT_SIZE   1728

typedef struct _OPTFLAG {
    uint16_t    sign        : 1;
    uint16_t    input       : 1;
    uint16_t    output      : 1;
    uint16_t    outputssl   : 1;
    uint16_t    hash        : 1;
    uint16_t    bypass      : 1;
    uint16_t    dummy6      : 1;
    uint16_t    dummy7      : 1;
    uint16_t    dummy8      : 1;
    uint16_t    dummy9      : 1;
    uint16_t    dummy10     : 1;
    uint16_t    dummy11     : 1;
    uint16_t    dummy12     : 1;
    uint16_t    dummy13     : 1;
    uint16_t    dummy14     : 1;
    uint16_t    dummy15     : 1;
}OPTFLAG;

union _uOptFlag {
    OPTFLAG flags;
    uint16_t    all;
} uOptFlag;

void _helpmenu(void)
{
    printf("\nHelp menu: trustm_ecc_sign <option> ...<option>\n");
    printf("option:- \n");
    printf("-k <OID Key>  : Select ECC key for signing OID (0xE0F0-0xE0F3) \n");
    printf("-o <filename> : Output to file with header\n");
    printf("-O <filename> : Output to file without header\n");    
    printf("-i <filename> : Input Data file\n");
    printf("-H            : Hash before sign\n");
    printf("-X            : Bypass Shielded Communication \n");
    printf("-h            : Print this help \n");
}

int main (int argc, char **argv)
{
    optiga_lib_status_t return_status;

    optiga_key_id_t optiga_key_id;
    //optiga_hash_context_t hash_context;
    //hash_data_from_host_t hash_data_host;
    //uint8_t hash_context_buffer[2048];

    uint8_t signature [300];     //To store the signture generated
    uint16_t signature_length = sizeof(signature);
    uint8_t digest[32];
    uint16_t digestLen = 0;
   // uint8_t data[2048];
    //uint16_t dataLen = 0;

    char *outFile = NULL;
    char *inFile = NULL;
    FILE *fp = NULL;
    
    int i;

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
        while (-1 != (option = getopt(argc, argv, "k:o:O:i:HXh")))
        {
            switch (option)
            {
                case 'k': // OID Key
                    uOptFlag.flags.sign = 1;
                    optiga_key_id = trustmHexorDec(optarg);
                    break;
                case 'o': // Output with header
                    uOptFlag.flags.outputssl = 1;
                    outFile = optarg;
                    break;
                case 'O': // Output without header
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
                case 'X': // Bypass Shielded Communication
                    uOptFlag.flags.bypass = 1;
                    printf("Bypass Shielded Communication. \n");
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
    if(uOptFlag.flags.bypass != 1)
    #ifdef HIBERNATE_ENABLE
        trustm_hibernate_flag = 1; // Enable hibernate Context Save
    #else
        trustm_hibernate_flag = 0; // disable hibernate Context Save
    #endif 
    else
        trustm_hibernate_flag = 0; // disable hibernate Context Save

    return_status = trustm_Open();
    if (return_status != OPTIGA_LIB_SUCCESS)
        exit(1);

    printf("========================================================\n");

    do
    {
        if(uOptFlag.flags.sign == 1)
        {
            if((uOptFlag.flags.output != 1) && (uOptFlag.flags.outputssl != 1))
            {
                printf("Output filename missing!!!\n");
                break;
            }

            if(uOptFlag.flags.input != 1)
            {
                printf("Input filename missing!!!\n");
                break;
            }

            printf("OID Key          : 0x%.4X\n",optiga_key_id);
            printf("Output File Name : %s \n", outFile);
            printf("Input File Name  : %s \n", inFile);

            if(uOptFlag.flags.hash == 1)
            {
                //open
                fp = fopen((const char *)inFile,"rb");
                if (!fp)
                {
                    printf("error opening file : %s\n",inFile);
                    exit(1);
                }
		

                  SHA256_CTX sha256;
                  SHA256_Init(&sha256);
                  const int bufSize = 32768;
                  char* buffer = malloc(bufSize);
                  int bytesRead = 0;
                  if(!buffer) return -1;
                  while((bytesRead = fread(buffer, 1, bufSize, fp)))
                  {
                      SHA256_Update(&sha256, buffer, bytesRead);
                  }
                  SHA256_Final(digest, &sha256);
                  digestLen = sizeof(digest);
                  printf("Hash Success : SHA256\n");
                  trustmHexDump(digest,digestLen);
                //}

                

            } else
            {
                digestLen = trustmreadFrom(digest, (uint8_t *) inFile);
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
                    trustmHexDump(digest,digestLen);
                }
            }

            if(uOptFlag.flags.bypass != 1)
            {
                // OPTIGA Comms Shielded connection settings to enable the protection
                OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
                OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt, OPTIGA_COMMS_FULL_PROTECTION);
            }
                
            optiga_lib_status = OPTIGA_LIB_BUSY;
            return_status = optiga_crypt_ecdsa_sign(me_crypt,
                                                    digest,
                                                    digestLen,
                                                    optiga_key_id,
                                                    signature,
                                                    &signature_length);
            if (OPTIGA_LIB_SUCCESS != return_status)
                break;
            //Wait until the optiga_util_read_metadata operation is completed
            trustm_WaitForCompletion(BUSY_WAIT_TIME_OUT);
            return_status = optiga_lib_status;
            if (return_status != OPTIGA_LIB_SUCCESS)
                break;
            else
            {
                if(uOptFlag.flags.outputssl == 1)
                {
                    for(i=signature_length-1; i >= 0; i--)
                    {
                        signature[i+2] = signature[i]; 
                    }
                    signature[0] = 0x30; // Insert SEQUENCE
                    signature[1] = signature_length; // insert length
                    signature_length += 2;
                }
                trustmwriteTo(signature, signature_length, outFile);
                printf("Success\n");
            }
        }

    }while(FALSE);

    // Capture OPTIGA Trust M error
    if (return_status != OPTIGA_LIB_SUCCESS)
        trustmPrintErrorCode(return_status);

    printf("========================================================\n");

    trustm_Close();
    trustm_hibernate_flag = 0; // Disable hibernate Context Save
    return 0;
}
